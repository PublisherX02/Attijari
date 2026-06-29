from email.utils import parseaddr
import os
import re
import time
from urllib.parse import urlparse

from threat_feeds import get_feeds, WHITELISTED_DOMAINS
from url_utils import normalize_url


from pathlib import Path

BLOCKED_EXTENSIONS = {".exe", ".js", ".vbs", ".scr", ".bat", ".ps1", ".jar", ".msi", ".cmd", ".com"}

# CLAUDE.md rule 8: Encrypted attachment + password in body = automatic escalate/reject
# These patterns detect passwords mentioned in the email body
_PASSWORD_PATTERNS = re.compile(
    r'(?i)'
    r'(?:mot de passe|password|passcode|pin code|code d[\'\u2019]acc[eè]s'
    r'|unlock code|extraction code|archive password'
    r'|le mot de passe est|the password is|pwd)\s*[:\-=]?\s*'
    r'[\w!@#$%^&*()]{2,}',
)
# Attachment extensions that commonly support encryption/password protection
_ENCRYPTED_ATTACHMENT_EXTENSIONS = {".zip", ".rar", ".7z", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".pdf"}

# ---------------------------------------------------------------------------
# Database-backed blocklist with in-memory cache (60s TTL)
# ---------------------------------------------------------------------------
_blocklist_cache: set[str] = set()
_blocklist_cache_time: float = 0.0
_BLOCKLIST_CACHE_TTL = 60.0  # seconds


def _refresh_blocklist_cache():
    """Reload the blocklist from PostgreSQL into an in-memory set."""
    global _blocklist_cache, _blocklist_cache_time, BLOCKED_HASH
    now = time.time()
    if now - _blocklist_cache_time < _BLOCKLIST_CACHE_TTL and _blocklist_cache:
        return  # cache is fresh

    try:
        from database import SessionLocal, get_blocked_set
        db = SessionLocal()
        emails = get_blocked_set(db, "email")
        domains = get_blocked_set(db, "domain")
        _blocklist_cache = emails | domains
        # Also load blocked hashes from DB
        try:
            hashes = get_blocked_set(db, "hash")
            BLOCKED_HASH = hashes
        except Exception:
            pass  # hash type may not exist yet in DB
        _blocklist_cache_time = now
        db.close()
    except Exception as e:
        # Fall back to file-based blocklist if DB is unavailable
        print(f"[RULES] DB blocklist unavailable ({e}), using file fallback")
        _load_file_blocklist()
        _blocklist_cache_time = now


def _load_file_blocklist():
    """Fallback: load blocklist from text file if DB is down."""
    global _blocklist_cache
    _DATA_DIR = Path(__file__).resolve().parent.parent / "data"
    _BLOCKLIST_FILE = _DATA_DIR / "blocked_senders.txt"

    _blocklist_cache = set()
    if _BLOCKLIST_FILE.exists():
        try:
            lines = _BLOCKLIST_FILE.read_text(encoding="utf-8").splitlines()
            for line in lines:
                if line.strip():
                    _blocklist_cache.add(line.strip().lower())
        except Exception:
            pass


def get_blocked_senders() -> set[str]:
    """Get the current set of blocked senders/domains."""
    _refresh_blocklist_cache()
    return _blocklist_cache


BLOCKED_HASH = set()


# ---------------------------------------------------------------------------
# Shared infrastructure IPs — CLAUDE.md: "never auto-block shared
# infrastructure IPs (Gmail, Outlook relays). A whitelist override always wins."
# These are well-known mail relay CIDR prefixes that should never be blocklisted.
# ---------------------------------------------------------------------------
SHARED_INFRA_PREFIXES = (
    # Google / Gmail
    "74.125.", "209.85.", "172.217.", "142.250.", "108.177.",
    # Microsoft / Outlook / O365
    "40.92.", "40.93.", "40.94.", "40.107.", "52.100.", "52.101.",
    "104.47.",
    # Amazon SES
    "54.240.",
    # Cloudflare
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
    "104.21.", "104.22.", "104.23.", "104.24.", "104.25.",
    "172.64.", "172.65.", "172.66.", "172.67.",
    # SendGrid
    "167.89.", "198.21.",
)


def is_shared_infrastructure_ip(ip: str) -> bool:
    """Check if an IP belongs to known shared mail infrastructure."""
    ip = (ip or "").strip()
    return any(ip.startswith(prefix) for prefix in SHARED_INFRA_PREFIXES)


def add_to_blocklist(sender: str):
    """Add a sender to the persistent blocklist (DB + cache)."""
    if not sender:
        return
    sender = sender.strip().lower()

    try:
        from database import SessionLocal, add_blocklist_entry
        db = SessionLocal()
        # Determine type
        indicator_type = "email" if "@" in sender else "domain"
        added = add_blocklist_entry(db, indicator_type, sender, source="auto")
        db.close()

        if added:
            _blocklist_cache.add(sender)
            print(f"[BLOCKLIST] Added to DB: {indicator_type}:{sender}")
    except Exception as e:
        # Fallback: write to file
        print(f"[BLOCKLIST] DB write failed ({e}), falling back to file")
        _DATA_DIR = Path(__file__).resolve().parent.parent / "data"
        _BLOCKLIST_FILE = _DATA_DIR / "blocked_senders.txt"
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        if sender not in _blocklist_cache:
            _blocklist_cache.add(sender)
            try:
                with open(_BLOCKLIST_FILE, "a", encoding="utf-8") as f:
                    f.write(f"{sender}\n")
            except Exception:
                pass


def cascade_blocklist(sender_email: str, sender_domain: str | None,
                      ips: list[str] | None, hashes: list[str] | None):
    """CLAUDE.md cascading blocklist: on confirmed malicious, block all associated indicators.

    Blocks:
      - sender email address
      - sender domain (and all subdomains via the domain entry)
      - associated IPs (skipping shared infrastructure)
      - file hashes as known-bad

    Whitelist always wins — add_blocklist_entry checks whitelist before inserting.
    """
    added_count = 0

    try:
        from database import SessionLocal, add_blocklist_entry
        db = SessionLocal()

        # 1. Block sender email
        if sender_email:
            if add_blocklist_entry(db, "email", sender_email, source="cascade"):
                _blocklist_cache.add(sender_email.strip().lower())
                added_count += 1
                print(f"[CASCADE] Blocked email: {sender_email}")

        # 2. Block sender domain
        if sender_domain:
            if add_blocklist_entry(db, "domain", sender_domain, source="cascade"):
                _blocklist_cache.add(sender_domain.strip().lower())
                added_count += 1
                print(f"[CASCADE] Blocked domain: {sender_domain}")

        # 3. Block associated IPs (skip shared infrastructure)
        for ip in (ips or []):
            ip = ip.strip()
            if not ip:
                continue
            if is_shared_infrastructure_ip(ip):
                print(f"[CASCADE] Skipped IP {ip} — shared infrastructure (Gmail/Outlook/CDN)")
                continue
            if add_blocklist_entry(db, "ip", ip, source="cascade"):
                added_count += 1
                print(f"[CASCADE] Blocked IP: {ip}")

        # 4. Block file hashes as known-bad
        for h in (hashes or []):
            h = (h or "").strip().lower()
            if not h or len(h) != 64:
                continue
            if add_blocklist_entry(db, "hash", h, source="cascade"):
                BLOCKED_HASH.add(h)
                added_count += 1
                print(f"[CASCADE] Blocked hash: {h[:12]}...")

        db.close()

    except Exception as e:
        print(f"[CASCADE] DB error ({e}), falling back to email-only blocklist")
        add_to_blocklist(sender_email)
        return

    if added_count > 0:
        print(f"[CASCADE] Total: {added_count} indicator(s) added to blocklist")
    else:
        print(f"[CASCADE] No new indicators added (already blocked or whitelisted)")


def extract_signals(parsed: dict) -> dict:
    headers = parsed.get("headers") or {}
    from_field = headers.get("from") or headers.get("From") or ""
    _, addr = parseaddr(from_field)
    parts = addr.split("@") if "@" in addr else []
    domain = parts[-1].strip().lower() if len(parts) >= 2 and parts[-1].strip() else None

    extensions = []
    hashes = []
    attachments = parsed.get("attachments") or []
    for att in attachments:
        name = att.get("original_name") or ""
        _, ext = os.path.splitext(name)
        extensions.append(ext.lower())
        hashes.append(att.get("sha256"))

    # Extract URLs and IPs from body for threat feed checks
    body = parsed.get("body_text") or ""
    body_html = parsed.get("body_html") or ""
    combined_text = body + " " + body_html

    # Simple URL extraction from text, followed by normalization
    raw_urls = re.findall(r'https?://[^\s<>"\']+', combined_text)
    urls = [normalize_url(u) for u in raw_urls]

    # Extract IPs from Received headers and body
    received = headers.get("received") or ""
    if isinstance(received, list):
        received = " ".join(str(r) for r in received)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, str(received) + " " + combined_text)

    # Extract domains from URLs — skip whitelisted shared infrastructure
    # (Google, Microsoft, Dropbox, etc. appear in legitimate emails constantly)
    url_domains = set()
    for url in urls:
        try:
            h = urlparse(url).hostname
            if h:
                h = h.lower()
                # Check if domain or its base is whitelisted
                base = ".".join(h.split(".")[-2:]) if len(h.split(".")) > 2 else h
                if h not in WHITELISTED_DOMAINS and base not in WHITELISTED_DOMAINS:
                    url_domains.add(h)
        except Exception:
            pass

    return {
        "sender_domain": domain,
        "sender_address": addr,
        "extensions": extensions,
        "hashes": hashes,
        "attachments": attachments,
        "body_urls": urls,
        "body_ips": ips,
        "body_domains": list(url_domains),
    }


class RuleEngine:
    def __init__(self):
        # Load threat feeds once (singleton — cached after first call)
        self.feeds = get_feeds()

    def analyze(self, parsed: dict) -> dict:
        signals = extract_signals(parsed)
        details = []
        flags = 0

        # Refresh blocklist cache from DB
        blocked = get_blocked_senders()

        # Rule 1 — blocklist domain (from DB)
        sender_blocked = False
        if signals["sender_domain"] and signals["sender_domain"] in blocked:
            sender_blocked = True
        if signals["sender_address"] and signals["sender_address"].lower() in blocked:
            sender_blocked = True

        if sender_blocked:
            details.append({"rule": "blocklist_domain", "flagged": True,
                            "reason": f"blocked: {signals['sender_domain'] or signals['sender_address']}"})
            flags += 1
        else:
            details.append({"rule": "blocklist_domain", "flagged": False, "reason": "sender not blocked"})

        # Check whitelist — whitelist always wins (CLAUDE.md)
        if sender_blocked and signals["sender_domain"]:
            try:
                from database import SessionLocal, is_whitelisted
                db = SessionLocal()
                if is_whitelisted(db, "domain", signals["sender_domain"]):
                    # Remove the blocklist flag — whitelist wins
                    details[-1] = {"rule": "blocklist_domain", "flagged": False,
                                   "reason": f"whitelisted override: {signals['sender_domain']}"}
                    flags -= 1
                db.close()
            except Exception:
                pass  # DB unavailable — blocklist stands

        # Rule 2 — blocked extensions
        bad_exts = [ext for ext in signals["extensions"] if ext in BLOCKED_EXTENSIONS]
        if bad_exts:
            details.append({"rule": "blocked_extension", "flagged": True,
                            "reason": f"blocked extension(s): {', '.join(bad_exts)}"})
            flags += 1
        else:
            details.append({"rule": "blocked_extension", "flagged": False, "reason": "no blocked extensions"})

        # Rule 3 — known bad hashes
        bad_hashes = [h for h in signals["hashes"] if h and h in BLOCKED_HASH]
        if bad_hashes:
            details.append({"rule": "blocked_hash", "flagged": True,
                            "reason": f"known bad hash: {bad_hashes[0][:12]}..."})
            flags += 1
        else:
            details.append({"rule": "blocked_hash", "flagged": False, "reason": "no known bad hashes"})

        # Rule 4 — phishing body heuristic
        # Requires BOTH coercive urgency AND financial/credential targeting.
        # "please review the attached invoice" is normal business — only flag when
        # urgency is paired with requests for credentials, wire transfers, or account changes.
        body = (parsed.get("body_text") or "").lower()

        # Tier 1: coercive urgency with threat of consequence
        urgency_phrases = [
            "your account will be", "account has been suspended",
            "account will be suspended", "account will be closed",
            "legal action", "unauthorized transaction", "unusual charge",
            "unexpected charge", "we'll assume", "verify your identity",
            "confirm your identity", "failure to respond",
            "within 24 hours", "within 48 hours", "immediate action required",
            "action required immediately",
        ]

        # Tier 2: financial or credential targeting
        targeting_phrases = [
            "update your payment", "verify your account", "confirm your password",
            "enter your credentials", "click here to verify", "click here to confirm",
            "wire transfer", "bank details", "routing number", "iban", "bic",
            "login immediately", "sign in to verify", "reset your password",
            "social security", "credit card number", "cvv",
            "modify bank", "change bank details", "new bank account",
        ]

        urgency_matches = [p for p in urgency_phrases if p in body]
        targeting_matches = [p for p in targeting_phrases if p in body]

        if urgency_matches and targeting_matches:
            reasons = [f"coercive_urgency: {', '.join(urgency_matches[:3])}",
                       f"financial_targeting: {', '.join(targeting_matches[:3])}"]
            details.append({"rule": "phishy_body", "flagged": True, "reason": ", ".join(reasons)})
            flags += 1
        else:
            details.append({"rule": "phishy_body", "flagged": False, "reason": "no phishing pattern (urgency+targeting) detected"})

        # Rule 5 — Threat feed: sender domain in URLhaus/OpenPhish
        if signals["sender_domain"] and self.feeds.check_domain(signals["sender_domain"]):
            details.append({"rule": "feed_sender_domain", "flagged": True,
                            "reason": f"sender domain in threat feeds: {signals['sender_domain']}"})
            flags += 1
        else:
            details.append({"rule": "feed_sender_domain", "flagged": False,
                            "reason": "sender domain not in threat feeds"})

        # Rule 6 — Threat feed: URLs in body
        bad_urls = [u for u in signals["body_urls"] if self.feeds.check_url(u)]
        if bad_urls:
            details.append({"rule": "feed_malicious_url", "flagged": True,
                            "reason": f"malicious URL(s) in body: {', '.join(bad_urls[:3])}"})
            flags += 1
        else:
            details.append({"rule": "feed_malicious_url", "flagged": False,
                            "reason": "no malicious URLs in body"})

        # Rule 7 — Threat feed: domains in body URLs
        bad_domains = [d for d in signals["body_domains"] if self.feeds.check_domain(d)]
        if bad_domains:
            details.append({"rule": "feed_malicious_domain", "flagged": True,
                            "reason": f"malicious domain(s) in body: {', '.join(bad_domains[:3])}"})
            flags += 1
        else:
            details.append({"rule": "feed_malicious_domain", "flagged": False,
                            "reason": "no malicious domains in body"})

        # Rule 8 — Threat feed: IPs in headers/body
        bad_ips = [ip for ip in signals["body_ips"] if self.feeds.check_ip(ip)]
        if bad_ips:
            details.append({"rule": "feed_malicious_ip", "flagged": True,
                            "reason": f"malicious IP(s): {', '.join(bad_ips[:3])}"})
            flags += 1
        else:
            details.append({"rule": "feed_malicious_ip", "flagged": False,
                            "reason": "no malicious IPs found"})

        # Rule 9 — CLAUDE.md rule 8: Encrypted attachment + password in body
        # "Encrypted attachment + password in email body = automatic escalate/reject"
        has_encryptable_attachment = False
        for att in signals.get("attachments", []):
            name = (att.get("original_name") or "").lower()
            _, ext = os.path.splitext(name)
            if ext in _ENCRYPTED_ATTACHMENT_EXTENSIONS:
                has_encryptable_attachment = True
                break
            # Also check if extraction reported the file as encrypted/password-protected
            if att.get("encrypted") or att.get("password_protected"):
                has_encryptable_attachment = True
                break

        body_has_password = bool(_PASSWORD_PATTERNS.search(body))
        if has_encryptable_attachment and body_has_password:
            details.append({"rule": "encrypted_attachment_password", "flagged": True,
                            "reason": "attachment + password in body — classic malware delivery pattern"})
            flags += 1
        else:
            details.append({"rule": "encrypted_attachment_password", "flagged": False,
                            "reason": "no encrypted attachment + password pattern"})

        # Determine verdict severity:
        # - "proposed_reject": deterministic hard-evidence rules fired
        #   (blocklist, bad extension, bad hash, threat feed match)
        #   → goes to human review as a proposed rejection
        # - "escalated": only heuristic/soft rules fired (phishy_body)
        #   → goes to human review as ambiguous
        # - "accepted": nothing fired
        HARD_EVIDENCE_RULES = {
            "blocklist_domain", "blocked_extension", "blocked_hash",
            "feed_sender_domain", "feed_malicious_url",
            "feed_malicious_domain", "feed_malicious_ip",
            "encrypted_attachment_password",
        }
        hard_flags = [d for d in details if d["flagged"] and d["rule"] in HARD_EVIDENCE_RULES]

        if hard_flags:
            verdict = "proposed_reject"
        elif flags > 0:
            verdict = "escalated"
        else:
            verdict = "accepted"

        return {
            "verdict": verdict,
            "rules_run": len(details),
            "flags": flags,
            "hard_flags": len(hard_flags),
            "details": details,
        }
