import email
import imaplib
import hashlib
import json
import os
import time
import socket
from email import policy
from email.parser import BytesParser
from datetime import datetime
from pathlib import Path

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

class TimeoutError(Exception):
    pass

def _check_elapsed(start: float, limit: float, step: str):
    elapsed = time.time() - start
    if elapsed > limit:
        raise TimeoutError(f"[TIMEOUT] {step} exceeded {limit}s (took {elapsed:.1f}s)")

class EmailIngestion:
    def __init__(self , host: str , user:str , password: str , folder: str = "INBOX" ):
        self.host = host
        self.user = user
        self.password = password
        self.folder = folder
        self.parser = BytesParser(policy = policy.default) #MIME policy rules

    def connect(self):
        print(f"[CONNECT] Connecting to {self.host}...")
        t0 = time.time()
        self.conn = imaplib.IMAP4_SSL(self.host)
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
    def fetch_unread(self, limit: int = 5) -> list[bytes]:
        print(f"[FETCH] Searching for unread emails (limit={limit})...")
        t0 = time.time()
        try:
            # enforce socket-level timeout for blocking IMAP ops
            if hasattr(self.conn, "sock") and self.conn.sock:
                try:
                    self.conn.sock.settimeout(FETCH_TIMEOUT)
                except Exception:
                    pass

            _, msg_ids = self.conn.search(None, "UNSEEN")
            ids = msg_ids[0].split() if msg_ids and msg_ids[0] else []
            total = len(ids)
            ids = ids[-limit:]  # keep only the most recent
            print(f"[FETCH] Found {total} unread, fetching last {len(ids)}")
            raw_emails = []
            for i, mid in enumerate(ids, 1):
                _check_elapsed(t0, FETCH_TIMEOUT, f"Fetch batch")
                print(f"[FETCH] Downloading {i}/{len(ids)} (id={mid.decode()})...")
                _, data = self.conn.fetch(mid, "(RFC822)")
                raw_byte = data[0][1]
                if len(raw_byte) > MAX_EMAIL_SIZE:
                    print(f"[FETCH] SKIPPED id={mid.decode()} — {len(raw_byte)/1024/1024:.1f} MB exceeds {MAX_EMAIL_SIZE/1024/1024:.0f} MB limit")
                    continue
                raw_emails.append(raw_byte)
            print(f"[FETCH] All downloaded ({time.time()-t0:.1f}s)")
            return raw_emails

        except (socket.timeout, TimeoutError) as e:
            print(f"[FETCH] Timeout or network error: {e}")
            return []
        except KeyboardInterrupt:
            print("[FETCH] Interrupted by user")
            return []
        except Exception as e:
            print(f"[FETCH] Error during fetch: {type(e).__name__}: {e}")
            return []
        finally:
            try:
                if hasattr(self.conn, "sock") and self.conn.sock:
                    self.conn.sock.settimeout(None)
            except Exception:
                pass

    #archiving emails before manipulation to save content
    def archive_raw(self, raw:bytes) -> Path:
        archive_dir = Path("data/raw_emails")
        archive_dir.mkdir(parents=True , exist_ok=True)
        sha = hashlib.sha256(raw).hexdigest()
        path = archive_dir / f"{sha}.eml"
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
    LEDGER_PATH = Path("data/processed_ledger.json")

    def _load_ledger(self) -> dict:
        if self.LEDGER_PATH.exists():
            data = json.loads(self.LEDGER_PATH.read_text())
            # migrate old format (list of keys) to new format (dict)
            if isinstance(data, list):
                return {k: {"status": "recu"} for k in data}
            return data
        return {}

    def _save_ledger(self, ledger: dict):
        self.LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.LEDGER_PATH.write_text(json.dumps(ledger, indent=2))

    def get_cached_result(self, raw: bytes, message_id: str | None) -> dict | None:
        key = self.idempotency_key(raw, message_id)
        ledger = self._load_ledger()
        return ledger.get(key)

    def mark_processed(self, key: str, result: dict):
        ledger = self._load_ledger()
        ledger[key] = {
            "status": result["status"],
            "from": result["headers"].get("from"),
            "subject": result["headers"].get("subject"),
            "attachments": len(result.get("attachments", [])),
            "parse_errors": result.get("parse_errors"),
            "llm_analysis": None if not result.get("llm_analysis") else {
                "verdict": result["llm_analysis"].get("verdict"),
                "reasons": result["llm_analysis"].get("reasons"),
            },
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
            "Received", "Authentication-Results"
        ]
        for field in header_fields:
            try:
                value = msg.get_all(field) if field in ("Received" ,) else msg.get(field)
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
        try:
            for part in msg.iter_attachments():
                _check_elapsed(t0, PARSE_TIMEOUT, "Attachment loop")
                att = self._extract_attachment(part)
                if att:
                    result["attachments"].append(att)
        except Exception as e:
            result["parse_errors"].append(f"attachments:{e}")

        #security protocol
        if result["parse_errors"]:
            result["status"] = "escalated"
            print(f"[PARSE] Done with {len(result['parse_errors'])} error(s) -> ESCALATED ({time.time()-t0:.1f}s)")
        else:
            print(f"[PARSE] Done OK — {len(result['attachments'])} attachment(s) ({time.time()-t0:.1f}s)")
        return result

    #security protocol for attached files — extracting PJ not given name
    def _extract_attachment(self, part) -> dict | None:
        t0 = time.time()
        try:
            content = part.get_content()
            if isinstance(content, str):
                content = content.encode()
            
            sha = hashlib.sha256(content).hexdigest()
            internal_id = sha[:16] #internal identifier
            
            #saving original names
            original_name = part.get_filename() or "unnamed"
            declared_type = part.get_content_type() or "unknown"
            print(f"[ATTACHMENT] {original_name} ({declared_type}, {len(content)} bytes)")

            #Secure saving of internal ids
            att_dir = Path("data/attachments")
            att_dir.mkdir(parents=True , exist_ok = True)
            safe_path = att_dir / internal_id
            safe_path.write_bytes(content)
            _check_elapsed(t0, ATTACHMENT_TIMEOUT, f"Attachment {original_name}")

            return{
                "internal_id" : internal_id,
                "original_name" : original_name,
                "declared_type" : declared_type,
                "size_bytes" : len(content),
                "sha256" : sha,
                "stored_path" : str(safe_path),
            }
        except Exception as e:
            print(f"[ATTACHMENT] FAILED: {e}")
            return {"error":str(e) , "original_name" : "parse_failed"}

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
        raw_emails = ingestion.fetch_unread()

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

