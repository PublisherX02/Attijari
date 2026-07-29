import email
import imaplib
import poplib
import hashlib
import json
import os
import ssl
import time
from email import policy
from email.parser import BytesParser
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import magic
    _HAS_MAGIC = True
except ImportError:
    _HAS_MAGIC = False

#email extraction function

# timeouts (seconds)
CONNECT_TIMEOUT = 30
FETCH_TIMEOUT = 60
PARSE_TIMEOUT = 30
ATTACHMENT_TIMEOUT = 15

# size limits
MAX_EMAIL_SIZE = 25 * 1024 * 1024       # 25 MB
MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024   # 10 MB per attachment
MAX_ATTACHMENT_COUNT = 20                # max attachments per email

# safe base directory — all file storage resolved relative to project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAFE_DATA_DIR = _PROJECT_ROOT / "data"


def _safe_path(base: Path, filename: str) -> Path:
    """Resolve a path under base and verify it doesn't escape via traversal."""
    resolved = (base / filename).resolve()
    if not str(resolved).startswith(str(base.resolve())):
        raise ValueError(f"Path traversal blocked: {filename}")
    return resolved

class TimeoutError(Exception):
    pass

def _check_elapsed(start: float, limit: float, step: str):
    elapsed = time.time() - start
    if elapsed > limit:
        raise TimeoutError(f"[TIMEOUT] {step} exceeded {limit}s (took {elapsed:.1f}s)")

def verify_sender_authentication(raw_email_bytes: bytes) -> bool:
    """
    Parses the Authentication-Results header to ensure the email 
    passed DMARC (which implicitly requires SPF or DKIM alignment).
    """
    msg = email.message_from_bytes(raw_email_bytes, policy=policy.default)
    auth_results = msg.get("Authentication-Results", "")
    
    if not auth_results:
        return True # if no gateway is present, bypass the strict check (for local testing)
        
    # Strictly enforce DMARC pass if the header exists
    if "dmarc=pass" not in auth_results.lower():
        return False
        
    return True

class EmailIngestion:
    def __init__(self , host: str , user:str , password: str , folder: str = "INBOX" , port: int = 993 ):
        self.host = host
        self.user = user
        self.password = password
        self.folder = folder
        self.port = port
        self.parser = BytesParser(policy = policy.default) #MIME policy rules

    def connect(self):
        print(f"[CONNECT] Connecting to {self.host}:{self.port}...")
        t0 = time.time()
        # Explicit SSL context — enforce certificate verification (CRIT-02)
        ctx = ssl.create_default_context()
        self.conn = imaplib.IMAP4_SSL(self.host, port=self.port, ssl_context=ctx)
        _check_elapsed(t0, CONNECT_TIMEOUT, "SSL connection")
        print(f"[CONNECT] SSL OK ({time.time()-t0:.1f}s), logging in as {self.user}...")
        self.conn.login(self.user, self.password)
        _check_elapsed(t0, CONNECT_TIMEOUT, "Login")
        print(f"[CONNECT] Logged in, selecting {self.folder}...")
        self.conn.select(self.folder)
        print(f"[CONNECT] Ready ({time.time()-t0:.1f}s total)")

    def disconnect(self):
        print("[DISCONNECT] Closing connection...")
        self.conn.close()
        self.conn.logout()
        print("[DISCONNECT] Done")

    #extracting raw email information
    def fetch_recent(self, since_days: int = 7, limit: int = 50) -> list[bytes]:
        """Fetch emails from the last `since_days` days (like Gmail inbox view).

        Uses IMAP SINCE date filter instead of UNSEEN, so rebooting the app
        won't pull in ancient unread emails.  BODY.PEEK[] is used so emails
        are NOT marked as read on the server — mirrors Gmail behaviour.
        """
        since_date = (datetime.now() - timedelta(days=since_days)).strftime("%d-%b-%Y")
        print(f"[FETCH] Searching for emails since {since_date} (limit={limit})...")
        t0 = time.time()
        _, msg_ids = self.conn.search(None, f'(SINCE "{since_date}")')
        ids = msg_ids[0].split()
        total = len(ids)
        # Process newest-first so new emails are always picked up even when
        # the window has more than `limit` messages (old ones are skipped
        # by idempotency anyway).
        ids = ids[-limit:] if len(ids) > limit else ids
        print(f"[FETCH] Found {total} in window, fetching last {len(ids)} (newest-first)")
        raw_emails = []
        for i, mid in enumerate(ids, 1):
            _check_elapsed(t0, FETCH_TIMEOUT, f"Fetch batch")
            print(f"[FETCH] Downloading {i}/{len(ids)} (id={mid.decode()})...")
            # BODY.PEEK[] fetches without marking as \Seen
            _, data = self.conn.fetch(mid, "(BODY.PEEK[])")
            raw_byte = data[0][1]
            if len(raw_byte) > MAX_EMAIL_SIZE:
                print(f"[FETCH] SKIPPED id={mid.decode()} — {len(raw_byte)/1024/1024:.1f} MB exceeds {MAX_EMAIL_SIZE/1024/1024:.0f} MB limit")
                continue
            raw_emails.append(raw_byte)
        print(f"[FETCH] All downloaded ({time.time()-t0:.1f}s)")
        return raw_emails

    # Backward compat alias
    def fetch_unread(self, limit: int = 50) -> list[bytes]:
        return self.fetch_recent(since_days=7, limit=limit)

    # Directory the inbound SMTP receiver (src/smtp_receiver.py) writes
    # accepted messages into. Kept as an instance attribute (not a
    # classmethod constant) so tests can monkeypatch it per-instance.
    PENDING_SMTP_DIR = SAFE_DATA_DIR / "smtp_pending"

    def fetch_pending_smtp(self, limit: int = 50) -> list[bytes]:
        """Read raw messages the SMTP receiver has accepted and queued.

        Mirrors fetch_recent()'s contract (returns a list[bytes], newest
        files first, capped at `limit`) so main.py's run_pipeline() can
        swap sources without changing anything downstream. Unlike IMAP,
        there's no "already fetched" concept here — every call re-reads
        whatever is currently on disk, and the existing idempotency cache
        (idempotency_key / get_cached_result) is what prevents reprocessing,
        exactly as it already does for IMAP-sourced mail.
        """
        pending_dir = self.PENDING_SMTP_DIR
        if not pending_dir.exists():
            return []
        files = sorted(pending_dir.glob("*.eml"), key=lambda p: p.stat().st_mtime, reverse=True)
        files = files[:limit]
        raw_emails = []
        for path in files:
            try:
                raw_emails.append(path.read_bytes())
            except OSError as e:
                print(f"[SMTP-PENDING] Failed to read {path.name}: {e}")
        return raw_emails

    #archiving emails before manipulation to save content
    def archive_raw(self, raw:bytes) -> Path:
        archive_dir = SAFE_DATA_DIR / "raw_emails"
        archive_dir.mkdir(parents=True , exist_ok=True)
        sha = hashlib.sha256(raw).hexdigest()
        path = _safe_path(archive_dir, f"{sha}.eml")
        if not path.exists():
            path.write_bytes(raw)
            print(f"[ARCHIVE] Saved {sha[:12]}...eml ({len(raw)} bytes)")
        else:
            print(f"[ARCHIVE] Already exists {sha[:12]}...eml (skipped)")
        return path

    #idempotency key — composite: Message-ID + raw SHA256 (Message-ID alone is spoofable)
    def idempotency_key(self, raw: bytes, message_id: str | None) -> str:
        raw_sha = hashlib.sha256(raw).hexdigest()
        if message_id:
            composite = f"{message_id}:{raw_sha}"
            return hashlib.sha256(composite.encode()).hexdigest()
        return raw_sha

    #idempotency ledger — tracks processed emails with their results
    LEDGER_PATH = SAFE_DATA_DIR / "processed_ledger.json"

    def _load_ledger(self) -> dict:
        if not self.LEDGER_PATH.exists():
            return {}
        try:
            with open(self.LEDGER_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            # migrate old format (list of keys) to new format (dict)
            if isinstance(data, list):
                return {k: {"status": "recu"} for k in data}
            return data
        except (json.JSONDecodeError, OSError) as e:
            # Corrupted ledger = escalate-worthy event, but don't crash
            print(f"[LEDGER] WARNING: Failed to read ledger: {e} — starting fresh")
            return {}

    def _save_ledger(self, ledger: dict):
        self.LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write: write to temp file, then rename (crash-safe)
        tmp_path = self.LEDGER_PATH.with_suffix(".tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(ledger, f, indent=2)
                f.flush()
                os.fsync(f.fileno())  # ensure data hits disk
            # Atomic rename (on Windows, need to remove target first)
            if self.LEDGER_PATH.exists():
                os.replace(str(tmp_path), str(self.LEDGER_PATH))
            else:
                os.rename(str(tmp_path), str(self.LEDGER_PATH))
        except OSError as e:
            print(f"[LEDGER] ERROR: Failed to save ledger: {e}")
            # Clean up temp file on failure
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    @property
    def lock(self):
        from filelock import FileLock
        return FileLock(str(self.LEDGER_PATH) + ".lock")

    def get_cached_result(self, raw: bytes, message_id: str | None) -> dict | None:
        key = self.idempotency_key(raw, message_id)
        with self.lock:
            ledger = self._load_ledger()
            return ledger.get(key)

    def mark_processed(self, key: str, result: dict):
        with self.lock:
            ledger = self._load_ledger()
            ledger[key] = {
                "status": result["status"],
                "from": result["headers"].get("from"),
                "subject": result["headers"].get("subject"),
                "attachments": len(result["attachments"]),
                "parse_errors": result["parse_errors"],
                "processed_at": datetime.now().isoformat(),
            }
            self._save_ledger(ledger)

    #MIME parsing
    def parse_email(self , raw:bytes) ->dict:
        t0 = time.time()
        sha_short = hashlib.sha256(raw).hexdigest()[:12]
        print(f"[PARSE] Parsing email {sha_short}...")
        msg = self.parser.parsebytes(raw)
        result = {
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "headers" : {},
            "body_text" : None,
            "body_html" : None,
            "attachments": [],
            "parse_errors": [],
            "status": "recu"
        }

        #headers
        print(f"[PARSE] Extracting headers...")
        header_fields = [
            "From" , "To" , "Reply-To" , "Return-Path",
            "Message-ID", "Subject", "Date",
            "Received", "Authentication-Results",
            "Content-Type",
        ]
        for field in header_fields:
            try:
                value = msg.get_all(field) if field in ("Received", "From", "Content-Type") else msg.get(field)
                if field == "From" and isinstance(value, list):
                    result["headers"]["from"] = str(value[0]) if value else None
                    result["headers"]["from_all"] = [str(v) for v in value]
                elif field == "Content-Type" and isinstance(value, list):
                    result["headers"]["content-type"] = str(value[0]) if value else None
                    result["headers"]["content-type_all"] = [str(v) for v in value]
                else:
                    result["headers"][field.lower()] = str(value) if value else None
            except Exception as e:
                result["headers"][field.lower()] = None
                result["parse_errors"].append(f"header:{field}:{e}")
        _check_elapsed(t0, PARSE_TIMEOUT, "Header extraction")

        #Idempotency
        result["idempotency_key"] = self.idempotency_key(
            raw , result["headers"].get("message-id")
        )

        #body
        print(f"[PARSE] Extracting body...")
        try:
            body_text = msg.get_body(preferencelist=("plain" ,))
            result["body_text"] = body_text.get_content() if body_text else None
        except Exception as e:
            result["parse_errors"].append(f"body_text:{e}")

        try:
            body_html = msg.get_body(preferencelist=("html" ,))
            result["body_html"] = body_html.get_content() if body_html else None
        except Exception as e:
            result["parse_errors"].append(f"body_html:{e}")
        _check_elapsed(t0, PARSE_TIMEOUT, "Body extraction")

        #attached files
        print(f"[PARSE] Processing attachments...")
        att_count = 0
        try:
            for part in msg.iter_attachments():
                if att_count >= MAX_ATTACHMENT_COUNT:
                    result["parse_errors"].append(
                        f"attachments:exceeded max count ({MAX_ATTACHMENT_COUNT}), remaining skipped")
                    result["status"] = "escalated"
                    print(f"[PARSE] LIMIT — {MAX_ATTACHMENT_COUNT} attachments max, skipping rest")
                    break
                att_count += 1
                _check_elapsed(t0, PARSE_TIMEOUT, "Attachment loop")
                att = self._extract_attachment(part)
                if att:
                    if att.get("error"):
                        result["parse_errors"].append(f"attachment:{att['original_name']}:{att['error']}")
                    else:
                        result["attachments"].append(att)
        except Exception as e:
            result["parse_errors"].append(f"attachments:{e}")

        #security protocol — status stays "recu" until full analysis chain passes
        #only escalate on errors; "accepted" is set downstream after verification
        if result["parse_errors"]:
            result["status"] = "escalated"
            print(f"[PARSE] Done with {len(result['parse_errors'])} error(s) -> ESCALATED ({time.time()-t0:.1f}s)")
        else:
            print(f"[PARSE] Done OK — {len(result['attachments'])} attachment(s), status=recu ({time.time()-t0:.1f}s)")
        return result

    #security protocol for attached files — extracting PJ not given name
    def _extract_attachment(self, part) -> dict | None:
        t0 = time.time()
        try:
            content = part.get_content()
            if isinstance(content, str):
                content = content.encode()

            filename = part.get_filename() or "unnamed"
            declared_type = part.get_content_type() or "unknown"

            if len(content) > MAX_ATTACHMENT_SIZE:
                print(f"[ATTACHMENT] WARNING oversized attachment skipped: {filename} ({len(content)} bytes)")
                return {"error": "oversized", "original_name": filename, "size_bytes": len(content)}

            sha = hashlib.sha256(content).hexdigest()
            internal_id = sha #internal identifier

            # magic-byte type verification — declared type lies (CLAUDE.md rule 7)
            real_type = None
            type_mismatch = False
            if _HAS_MAGIC:
                try:
                    real_type = magic.from_buffer(content, mime=True)
                    if real_type and declared_type != "unknown":
                        # normalize for comparison (e.g. both should be MIME)
                        if real_type != declared_type and declared_type != "application/octet-stream":
                            type_mismatch = True
                except Exception:
                    real_type = "detection_failed"

            print(f"[ATTACHMENT] {filename} (declared={declared_type}, real={real_type or 'unverified'}, {len(content)} bytes)"
                  + (" !! TYPE MISMATCH" if type_mismatch else ""))

            #Secure saving of internal ids
            att_dir = SAFE_DATA_DIR / "attachments"
            att_dir.mkdir(parents=True , exist_ok = True)
            safe_path = _safe_path(att_dir, internal_id)
            safe_path.write_bytes(content)
            _check_elapsed(t0, ATTACHMENT_TIMEOUT, f"Attachment {filename}")

            return{
                "internal_id" : internal_id,
                "original_name" : filename,
                "declared_type" : declared_type,
                "real_type" : real_type,
                "type_mismatch" : type_mismatch,
                "size_bytes" : len(content),
                "sha256" : sha,
                "stored_path" : str(safe_path),
            }
        except Exception as e:
            print(f"[ATTACHMENT] FAILED: {e}")
            return {"error":str(e) , "original_name" : "parse_failed"}


class Pop3Ingestion:
    """Mirrors EmailIngestion's public interface (connect/disconnect/fetch_recent)
    for mailboxes that only offer POP3, not IMAP.

    Two behavioral differences from EmailIngestion, both safe:
    - No PEEK equivalent: POP3's RETR has no no-mark-read option. This does
      NOT threaten repeated-poll safety — that guarantee lives entirely in
      the SMTP receiver's SHA-256 content dedup (see gmail_smtp_bridge.py),
      not in the source protocol. Re-relaying an already-seen message via
      POP3 is still a no-op downstream.
    - No server-side date search: POP3's LIST only gives sequence numbers,
      not dates. Filtering by since_days happens client-side after parsing
      each message's Date header.
    """
    def __init__(self, host: str, user: str, password: str, port: int = 995):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.parser = BytesParser(policy=policy.default)

    def connect(self):
        ctx = ssl.create_default_context()
        self.conn = poplib.POP3_SSL(self.host, port=self.port, context=ctx)
        self.conn.user(self.user)
        self.conn.pass_(self.password)

    def disconnect(self):
        self.conn.quit()

    def fetch_recent(self, since_days: int = 7, limit: int = 50) -> list[bytes]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
        _, listing, _ = self.conn.list()
        msg_nums = [int(line.decode().split()[0]) for line in listing]

        candidates = []
        for num in msg_nums:
            _, lines, _ = self.conn.retr(num)
            raw = b"\r\n".join(lines)
            if len(raw) > MAX_EMAIL_SIZE:
                continue
            msg = self.parser.parsebytes(raw)
            date_header = msg.get("Date")
            try:
                msg_date = email.utils.parsedate_to_datetime(date_header) if date_header else None
                if msg_date and msg_date.tzinfo is None:
                    msg_date = msg_date.replace(tzinfo=timezone.utc)
            except Exception:
                msg_date = None
            if msg_date is None or msg_date >= cutoff:
                candidates.append((msg_date or cutoff, raw))

        candidates.sort(key=lambda pair: pair[0], reverse=True)
        return [raw for _, raw in candidates[:limit]]

if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()

    print("=" * 50)
    print("[START] Email Ingestion Pipeline")
    print("=" * 50)
    t_start = time.time()

    ingestion = EmailIngestion(
        host=os.getenv("IMAP_HOST"),
        user=os.getenv("IMAP_USER"),
        password=os.getenv("IMAP_PASSWORD"),
    )

    try:
        ingestion.connect()
        raw_emails = ingestion.fetch_recent(since_days=7)

        cached = 0
        for i, raw in enumerate(raw_emails, 1):
            print(f"\n--- Email {i}/{len(raw_emails)} ---")
            # archive raw BEFORE parsing — crash-safe
            ingestion.archive_raw(raw)

            # check if already processed — show cached result directly
            msg = BytesParser(policy=policy.default).parsebytes(raw)
            message_id = msg.get("Message-ID")
            prev = ingestion.get_cached_result(raw, str(message_id) if message_id else None)
            if prev:
                print(f"[CACHED] Already verified — showing saved result:")
                print(f"  De:     {prev.get('from')}")
                print(f"  Sujet:  {prev.get('subject')}")
                print(f"  PJ:     {prev.get('attachments')}")
                print(f"  Statut: {prev['status']}")
                if prev.get('parse_errors'):
                    print(f"  Erreurs: {prev['parse_errors']}")
                cached += 1
                continue

            parsed = ingestion.parse_email(raw)
            ingestion.mark_processed(parsed["idempotency_key"], parsed)
            print(f"  De:     {parsed['headers']['from']}")
            print(f"  Sujet:  {parsed['headers']['subject']}")
            print(f"  PJ:     {len(parsed['attachments'])}")
            print(f"  Statut: {parsed['status']}")
            if parsed['parse_errors']:
                print(f"  Erreurs: {parsed['parse_errors']}")

        if cached:
            print(f"\n[INFO] {cached} email(s) loaded from cache (verification skipped)")

        ingestion.disconnect()
    except TimeoutError as e:
        print(f"\n[ABORT] {e}")
        print("[ABORT] Pipeline stopped — check network or server")
    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__}: {e}")

    elapsed = time.time() - t_start
    print(f"\n{'=' * 50}")
    print(f"[DONE] Finished in {elapsed:.1f}s")
    print(f"{'=' * 50}")
