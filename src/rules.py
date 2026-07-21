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
    """Reload the blocklist from PostgreSQL into an in-memory set.

    Only includes entries where expires_at IS NULL or expires_at > now().
    The 60-second cache TTL means expired entries are evicted within one minute
    without needing a background cleanup job.
    """
    global _blocklist_cache, _blocklist_cache_time, BLOCKED_HASH
    now = time.time()
    if now - _blocklist_cache_time < _BLOCKLIST_CACHE_TTL and _blocklist_cache:
        return  # cache is fresh

    try:
        from datetime import datetime, timezone
        from database import SessionLocal, Blocklist
        db = SessionLocal()
        current_utc = datetime.now(timezone.utc)

        def _get_active_set(indicator_type: str) -> set:
            rows = db.query(Blocklist.value).filter(
                Blocklist.indicator_type == indicator_type,
                Blocklist.active == True,
                (Blocklist.expires_at == None) | (Blocklist.expires_at > current_utc),
            ).all()
            return {r[0] for r in rows}

        emails = _get_active_set("email")
        domains = _get_active_set("domain")
        _blocklist_cache = emails | domains
        # Also load blocked hashes from DB, respecting TTL
        try:
            BLOCKED_HASH = _get_active_set("hash")
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


# ---------------------------------------------------------------------------
# Shared email domains — CLAUDE.md: "never auto-block shared infrastructure."
# These are multi-tenant providers where blocking the domain would block ALL
# users, not just the malicious sender. Block the sender address only.
# ---------------------------------------------------------------------------
SHARED_EMAIL_DOMAINS = {
    # Consumer webmail
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.fr", "yahoo.co.uk",
    "outlook.com", "hotmail.com", "hotmail.fr", "live.com", "msn.com",
    "aol.com", "icloud.com", "me.com", "mac.com", "mail.com",
    "protonmail.com", "proton.me", "tutanota.com", "zoho.com",
    "gmx.com", "gmx.fr", "gmx.de", "yandex.com", "yandex.ru",
    # Tunisian ISPs / webmail
    "topnet.tn", "planet.tn", "orange.tn", "tunisietelecom.tn",
    "gnet.tn", "hexabyte.tn",
    # French ISPs
    "orange.fr", "free.fr", "sfr.fr", "laposte.net", "wanadoo.fr",
    # Education (generic patterns handled by suffix check below)
    # Business platforms
    "linkedin.com", "facebook.com", "twitter.com",
}

# Academic domain suffixes — any .edu, .ac.*, .edu.* domain is shared
SHARED_DOMAIN_SUFFIXES = (".edu", ".ac.", ".edu.", ".gov", ".gouv.")


def is_shared_email_domain(domain: str) -> bool:
    """Check if a domain is a shared multi-tenant provider.

    Blocking these domains would affect all users, not just the attacker.
    For shared domains, only the specific sender address should be blocked.
    """
    domain = (domain or "").strip().lower()
    if domain in SHARED_EMAIL_DOMAINS:
        return True
    return any(domain.endswith(suffix) for suffix in SHARED_DOMAIN_SUFFIXES)


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

        # 2. Block sender domain (skip shared/multi-tenant providers)
        if sender_domain:
            if is_shared_email_domain(sender_domain):
                print(f"[CASCADE] Skipped domain {sender_domain} — shared provider (blocked sender only)")
            elif add_blocklist_entry(db, "domain", sender_domain, source="cascade"):
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

        # Rule 1 — blocklist check (from DB)
        # Track WHY the sender is blocked: domain-level vs sender-level.
        # A domain whitelist should NOT override a specific sender block.
        _domain_blocked = bool(signals["sender_domain"] and signals["sender_domain"] in blocked)
        _sender_blocked = bool(signals["sender_address"] and signals["sender_address"].lower() in blocked)
        sender_blocked = _domain_blocked or _sender_blocked

        if sender_blocked:
            _block_reason = signals["sender_address"] if _sender_blocked else signals["sender_domain"]
            details.append({"rule": "blocklist_domain", "flagged": True,
                            "reason": f"blocked: {_block_reason}"})
            flags += 1
        else:
            details.append({"rule": "blocklist_domain", "flagged": False, "reason": "sender not blocked"})

        # Check whitelist — whitelist wins for DOMAIN-level blocks only.
        # If the specific sender address is blocked (e.g. scammer@gmail.com),
        # whitelisting gmail.com must NOT override it — that sender was
        # individually confirmed malicious by an analyst.
        if _domain_blocked and not _sender_blocked and signals["sender_domain"]:
            try:
                from database import SessionLocal, is_whitelisted
                db = SessionLocal()
                if is_whitelisted(db, "domain", signals["sender_domain"]):
                    # Remove the blocklist flag — whitelist wins for domain-only blocks
                    details[-1] = {"rule": "blocklist_domain", "flagged": False,
                                   "reason": f"whitelisted override: {signals['sender_domain']}"}
                    flags -= 1
                    sender_blocked = False
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

        # Tier 1: coercive urgency with threat of consequence (English + French)
        urgency_phrases = [
            "your account will be", "account has been suspended",
            "account will be suspended", "account will be closed",
            "legal action", "unauthorized transaction", "unusual charge",
            "unexpected charge", "we'll assume", "verify your identity",
            "confirm your identity", "failure to respond",
            "within 24 hours", "within 48 hours", "immediate action required",
            "action required immediately",
            # French equivalents
            "votre compte sera", "compte a ete suspendu",
            "compte sera suspendu", "compte sera ferme",
            "action en justice", "transaction non autorisee",
            "obligatoire", "action immediate requise",
            "dans les 24 heures", "delai de 24h", "delai de 48h",
            "suspension de votre", "avant le ",
            "reconfiguration obligatoire",
        ]

        # Tier 2: financial or credential targeting (English + French)
        targeting_phrases = [
            "update your payment", "verify your account", "confirm your password",
            "enter your credentials", "click here to verify", "click here to confirm",
            "wire transfer", "bank details", "routing number", "iban", "bic",
            "login immediately", "sign in to verify", "reset your password",
            "social security", "credit card number", "cvv",
            "modify bank", "change bank details", "new bank account",
            # French equivalents
            "mettre a jour votre paiement", "verifier votre compte",
            "confirmer votre mot de passe", "confirmer votre identite",
            "cliquez ici pour verifier", "cliquez ici pour confirmer",
            "virement bancaire", "coordonnees bancaires",
            "reinitialiser votre mot de passe", "reinitialiser votre",
            "numero de carte", "modifier vos coordonnees",
            # Auth/2FA targeting (quishing vector)
            "scanner le qr code", "reconfigurer votre",
            "authentification 2fa", "microsoft authenticator",
            "reinitialiser avant",
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

        # Rule 10 — Thread hijack / BEC supplier fraud detection
        # External senders referencing bank detail changes with lookalike internal links
        bec_flagged = False
        bec_reasons = []

        # Check subject for financial keywords (French + English)
        subject = (parsed.get("headers", {}).get("subject") or "").lower()
        _BEC_SUBJECT_KW = (
            "coordonnees bancaires", "bank details", "changement", "virement",
            "wire transfer", "rib ", "iban", "payment update", "mise a jour",
            "modification bancaire", "nouveau rib", "new bank",
        )
        subject_has_financial = any(kw in subject for kw in _BEC_SUBJECT_KW)

        # Check if sender is external (not @imaniabank.com.tn)
        sender_is_external = (
            signals["sender_domain"] and
            signals["sender_domain"] != "imaniabank.com.tn" and
            not signals["sender_domain"].endswith(".imaniabank.com.tn")
        )

        # Check body URLs for SharePoint/OneDrive lookalikes with evil subdomains
        _COLLAB_SERVICES = ("sharepoint", "onedrive", "1drv", "googleapis", "teams")
        _LEGIT_COLLAB_HOSTS = (
            ".sharepoint.com", ".onedrive.com", ".1drv.com",
            "googleapis.com", "teams.microsoft.com",
        )
        body_urls = signals.get("body_urls", [])
        spoofed_links = []
        for url in body_urls:
            try:
                host = urlparse(url).hostname or ""
                host = host.lower()
                # URL mentions a collab service but NOT on the real domain
                if any(svc in host for svc in _COLLAB_SERVICES):
                    if not any(host.endswith(legit) for legit in _LEGIT_COLLAB_HOSTS):
                        spoofed_links.append(host)
            except Exception:
                pass

        # Also check body for bank-detail-change keywords (French + English)
        _BEC_BODY_KW = (
            "coordonnees bancaires", "bank details", "rib", "iban",
            "changement de compte", "new account details", "wire transfer",
            "virement", "modification bancaire",
        )
        body_has_financial = any(kw in body for kw in _BEC_BODY_KW)

        if sender_is_external and spoofed_links:
            bec_flagged = True
            bec_reasons.append(f"spoofed collaboration link(s): {', '.join(spoofed_links[:3])}")
        if sender_is_external and subject_has_financial and body_has_financial:
            bec_flagged = True
            bec_reasons.append("external sender with financial subject + body (supplier fraud pattern)")

        if bec_flagged:
            details.append({"rule": "thread_hijack_bec", "flagged": True,
                            "reason": f"BEC/thread hijack: {'; '.join(bec_reasons)}"})
            flags += 1
        else:
            details.append({"rule": "thread_hijack_bec", "flagged": False,
                            "reason": "no thread hijack / BEC pattern detected"})

        # Rule 11 — ICS calendar attachment from external sender
        # Calendar invites (.ics) auto-add to Outlook/Gmail and are a known
        # phishing vector. External senders sending calendar files = suspicious.
        ics_flagged = False
        if sender_is_external:
            for att in signals.get("attachments", []):
                att_name = (att.get("original_name") or "").lower()
                att_type = (att.get("declared_type") or "").lower()
                if att_name.endswith(".ics") or "text/calendar" in att_type:
                    ics_flagged = True
                    break

        if ics_flagged:
            details.append({"rule": "ics_calendar_external", "flagged": True,
                            "reason": "calendar invite (.ics) from external sender — known phishing vector"})
            flags += 1
        else:
            details.append({"rule": "ics_calendar_external", "flagged": False,
                            "reason": "no external calendar invite"})

        # Rule 12 — Vishing / callback phishing pattern
        # Fake charge notification + phone number + cancel/refund trigger.
        # Classic BazarCall / callback phishing — victim calls attacker's number.
        _PHONE_PATTERN = re.compile(
            r'(?:\+\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}'
        )
        _AMOUNT_PATTERN = re.compile(
            r'(?:\$|€|£)?\s?\d{1,6}[.,]\d{2}\s*(?:USD|EUR|TND|GBP|usd|eur|tnd|gbp)?'
            r'|(?:\d{1,6}[.,]\d{2}\s*(?:USD|EUR|TND|GBP|usd|eur|tnd|gbp))'
        )
        _VISHING_TRIGGERS = (
            "renouvellement", "renewal", "renewed", "renouvele",
            "debite", "charged", "deducted", "preleve",
            "annuler", "cancel", "refund", "remboursement",
            "ne reconnaissez pas", "do not recognize",
            "contacter", "contact", "call", "appelez",
        )

        has_phone = bool(_PHONE_PATTERN.search(body))
        has_amount = bool(_AMOUNT_PATTERN.search(body))
        has_vishing_trigger = any(t in body for t in _VISHING_TRIGGERS)

        if has_phone and has_amount and has_vishing_trigger:
            details.append({"rule": "vishing_callback", "flagged": True,
                            "reason": "callback phishing: phone number + charge amount + cancel/refund trigger"})
            flags += 1
        else:
            details.append({"rule": "vishing_callback", "flagged": False,
                            "reason": "no vishing/callback pattern"})

        # Rule 13 — Internal domain spoofing detection
        # If sender claims @imaniabank.com.tn but authentication fails,
        # this is a spoofed internal email. Catches ICS/phishing from
        # attackers impersonating internal staff.
        spoof_flagged = False
        if not sender_is_external:
            # Sender claims to be internal — verify authentication
            auth_results = (parsed.get("headers", {}).get("authentication-results")
                           or parsed.get("headers", {}).get("Authentication-Results") or "")
            if isinstance(auth_results, list):
                auth_results = " ".join(str(r) for r in auth_results)
            auth_lower = auth_results.lower()
            # If auth header exists and shows failures, it's spoofed
            has_auth_header = bool(auth_results.strip())
            spf_fail = "spf=fail" in auth_lower or "spf=softfail" in auth_lower or "spf=none" in auth_lower
            dkim_fail = "dkim=fail" in auth_lower or "dkim=none" in auth_lower
            dmarc_fail = "dmarc=fail" in auth_lower or "dmarc=none" in auth_lower
            if has_auth_header and (spf_fail or dkim_fail or dmarc_fail):
                spoof_flagged = True

        if spoof_flagged:
            details.append({"rule": "internal_domain_spoof", "flagged": True,
                            "reason": "sender claims internal domain but authentication fails — likely spoofed"})
            flags += 1
        else:
            details.append({"rule": "internal_domain_spoof", "flagged": False,
                            "reason": "no internal domain spoofing detected"})

        # Rule 14 — HTML script/smuggling detection
        # Scan body_html for <script> tags, javascript: URIs, and blob creation
        # patterns used in HTML smuggling attacks.
        html_smuggle_flagged = False
        body_html = (parsed.get("body_html") or "").lower()
        if body_html:
            _HTML_DANGER_PATTERNS = (
                "<script", "javascript:", "vbscript:",
                "createobjecturl", "new blob(", "new blob (",
                "uint8array", "atob(", "btoa(",
                "mhtml:", "data:application",
            )
            html_matches = [p for p in _HTML_DANGER_PATTERNS if p in body_html]
            if html_matches:
                html_smuggle_flagged = True

        if html_smuggle_flagged:
            details.append({"rule": "html_smuggling", "flagged": True,
                            "reason": f"HTML part contains dangerous patterns: {', '.join(html_matches[:3])}"})
            flags += 1
        else:
            details.append({"rule": "html_smuggling", "flagged": False,
                            "reason": "no HTML smuggling patterns detected"})

        # Rule 15 — Return-Path / From domain mismatch (envelope spoofing)
        # The Return-Path (envelope sender) should match the From header domain.
        # A mismatch indicates the email was sent from a different server than
        # claimed — a classic SPF evasion / spoofing technique.
        headers = parsed.get("headers") or {}
        return_path = headers.get("return-path") or ""
        from_header = headers.get("from") or ""
        rp_mismatch_flagged = False
        if return_path and from_header and "@" in return_path:
            rp_clean = return_path.strip().strip("<>").lower()
            rp_domain = rp_clean.split("@")[-1] if "@" in rp_clean else ""
            from_addr_match = re.search(r'[\w.+-]+@[\w.-]+', from_header.lower())
            from_domain = from_addr_match.group().split("@")[-1] if from_addr_match else ""
            if rp_domain and from_domain and rp_domain != from_domain:
                # Skip known forwarding/mailing-list patterns
                _FORWARDING_DOMAINS = {
                    "googlegroups.com", "lists.sourceforge.net", "freelists.org",
                    "yahoogroups.com", "bounces.google.com",
                }
                if rp_domain not in _FORWARDING_DOMAINS:
                    rp_mismatch_flagged = True

        if rp_mismatch_flagged:
            details.append({"rule": "return_path_mismatch", "flagged": True,
                            "reason": f"Return-Path domain ({rp_domain}) differs from From domain ({from_domain}) — envelope spoofing"})
            flags += 1
        else:
            details.append({"rule": "return_path_mismatch", "flagged": False,
                            "reason": "Return-Path matches From domain or not applicable"})

        # Rule 16 — Multiple From headers (RFC 5322 violation)
        # A legitimate email has exactly one From header. Multiple From headers
        # are used to confuse email clients into displaying a trusted sender
        # while the actual envelope routes through a malicious one.
        from_all = headers.get("from_all") or []
        multi_from_flagged = len(from_all) > 1

        if multi_from_flagged:
            details.append({"rule": "multi_from_header", "flagged": True,
                            "reason": f"Email contains {len(from_all)} From headers (RFC violation) — display spoofing attack"})
            flags += 1
        else:
            details.append({"rule": "multi_from_header", "flagged": False,
                            "reason": "single From header (normal)"})

        # Rule 17 — Empty envelope sender (null Return-Path)
        # A Return-Path of "<>" is legitimate for bounce messages (DSN).
        # But attackers use it to bypass SPF checks since SPF validates the
        # envelope sender — an empty one means no domain to check.
        empty_rp_flagged = False
        if return_path.strip() == "<>" or return_path.strip() == "":
            # Only flag if the subject/body doesn't look like a real bounce
            subject_lower = (headers.get("subject") or "").lower()
            _BOUNCE_KEYWORDS = ("undeliverable", "delivery status", "returned mail",
                                "mail delivery failed", "postmaster", "mailer-daemon")
            is_likely_bounce = any(kw in subject_lower for kw in _BOUNCE_KEYWORDS)
            if not is_likely_bounce and return_path.strip() == "<>":
                empty_rp_flagged = True

        if empty_rp_flagged:
            details.append({"rule": "empty_envelope_sender", "flagged": True,
                            "reason": "Empty Return-Path (<>) on non-bounce email — SPF bypass attempt"})
            flags += 1
        else:
            details.append({"rule": "empty_envelope_sender", "flagged": False,
                            "reason": "Return-Path present or legitimate bounce"})

        # Rule 18 — XSS payload in headers OR HTML body (email client exploitation)
        # Detects JavaScript injection in To/Subject/From fields and also inline
        # HTML event handlers (onmouseover, onerror, etc.) in the email body.
        xss_flagged = False
        _XSS_PATTERNS = (
            "onerror=", "onload=", "onmouseover=", "onfocus=", "onbegin=",
            "onmouseout=", "onmousemove=", "onclick=", "onblur=", "onchange=",
            "ondblclick=", "onkeydown=", "onkeypress=", "onkeyup=",
            "onsubmit=", "onreset=", "onselect=", "onabort=",
            "expression(", "alert(", "<svg", "animatetransform",
            "javascript:", "vbscript:",
        )
        # Check headers: To, Subject, From
        to_header = (headers.get("to") or "").lower()
        subject_header = (headers.get("subject") or "").lower()
        from_header_lower = (headers.get("from") or "").lower()
        xss_in = []
        for pattern in _XSS_PATTERNS:
            if pattern in to_header:
                xss_in.append(f"To:{pattern}")
            if pattern in subject_header:
                xss_in.append(f"Subject:{pattern}")
            if pattern in from_header_lower:
                xss_in.append(f"From:{pattern}")

        # Check HTML body for inline XSS (event handlers without <script> tags)
        if not xss_in:
            body_html_lower = (parsed.get("body_html") or "").lower()
            if body_html_lower:
                for pattern in _XSS_PATTERNS:
                    if pattern in body_html_lower:
                        xss_in.append(f"body:{pattern}")
                        if len(xss_in) >= 3:
                            break

        if xss_in:
            xss_flagged = True

        if xss_flagged:
            details.append({"rule": "xss_header_injection", "flagged": True,
                            "reason": f"XSS payload detected: {', '.join(xss_in[:3])}"})
            flags += 1
        else:
            details.append({"rule": "xss_header_injection", "flagged": False,
                            "reason": "no XSS payloads in headers or body"})

        # Rule 19 — MIME confusion attack (duplicate Content-Type headers)
        # Multiple Content-Type headers in the same MIME part cause different
        # email clients to interpret the content differently — one sees text/plain
        # (safe), another sees text/html (executes scripts).
        mime_attack_flagged = False
        ct_all = headers.get("content-type_all") or []
        if len(ct_all) > 1:
            # Multiple Content-Type headers in the top-level message = MIME confusion
            mime_attack_flagged = True

        if mime_attack_flagged:
            details.append({"rule": "mime_confusion_attack", "flagged": True,
                            "reason": "MIME structure confusion attack detected"})
            flags += 1
        else:
            details.append({"rule": "mime_confusion_attack", "flagged": False,
                            "reason": "no MIME confusion attack detected"})

        # Rule 20 — Multiple addresses in single From header
        # RFC 5322 allows a single From with one address. Multiple comma-separated
        # addresses in one From header (e.g. "legit@good.com, attacker@evil.com")
        # is used to confuse clients into showing the first (trusted) address
        # while the email actually originates from the second.
        multi_addr_flagged = False
        from_raw = (headers.get("from") or "")
        if from_raw:
            # Count @ signs — more than 1 in a single From header = suspicious
            at_count = from_raw.count("@")
            if at_count > 1:
                # Exclude mailing list formats like "Name via List <list@domain>"
                if "," in from_raw or " " in from_raw.split("@")[0].split("<")[-1]:
                    multi_addr_flagged = True

        if multi_addr_flagged:
            details.append({"rule": "multi_addr_from", "flagged": True,
                            "reason": f"From header contains {at_count} addresses — sender confusion attack"})
            flags += 1
        else:
            details.append({"rule": "multi_addr_from", "flagged": False,
                            "reason": "single address in From header"})

        # Rule 21 — Unicode spoofing in From header (RTL override, homoglyphs)
        # Attackers use Unicode control characters (U+202A LRE, U+202E RLO,
        # U+200F RLM) to reverse the visual display of the sender address,
        # making "attacker@evil.com" display as "moc.live@rekcatta".
        unicode_spoof_flagged = False
        _UNICODE_TRICKS = (
            "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # bidi overrides
            "\u200e", "\u200f",  # LRM, RLM
            "\u200b", "\u200c", "\u200d",  # zero-width chars
            "\ufeff",  # BOM
        )
        from_raw_full = from_raw
        for trick in _UNICODE_TRICKS:
            if trick in from_raw_full:
                unicode_spoof_flagged = True
                break
        # Also detect encoded unicode in raw From (=?utf-8?b? with \u202 patterns)
        if not unicode_spoof_flagged and "=?utf-8?" in from_raw_full.lower():
            # Base64-encoded From headers containing bidi chars are suspicious
            # when the decoded result doesn't match a normal email format
            import base64 as _b64
            _enc_match = re.search(r'=\?utf-8\?b\?(.*?)\?=', from_raw_full, re.IGNORECASE)
            if _enc_match:
                try:
                    decoded = _b64.b64decode(_enc_match.group(1)).decode("utf-8", errors="replace")
                    for trick in _UNICODE_TRICKS:
                        if trick in decoded:
                            unicode_spoof_flagged = True
                            break
                    # Also check if decoded string has reversed domain pattern
                    if not unicode_spoof_flagged and "@" in decoded:
                        # Check for backwards TLD (e.g. "moc.liamg" instead of "gmail.com")
                        domain_part = decoded.split("@")[-1].strip()
                        if domain_part and "." in domain_part:
                            tld = domain_part.split(".")[-1]
                            if tld in ("moc", "ten", "gro", "ude", "vog"):
                                unicode_spoof_flagged = True
                except Exception:
                    pass

        if unicode_spoof_flagged:
            details.append({"rule": "unicode_from_spoofing", "flagged": True,
                            "reason": "From header contains Unicode control characters or bidi overrides — visual spoofing"})
            flags += 1
        else:
            details.append({"rule": "unicode_from_spoofing", "flagged": False,
                            "reason": "no Unicode spoofing in From header"})

        # Rule 22 — Source-route injection in From/envelope
        # RFC 5321 source routes (e.g. "From <@relay1,@relay2:attacker@evil.com>")
        # are deprecated but still parsed by some clients. Attackers inject them
        # to route emails through intermediaries while hiding the true origin.
        source_route_flagged = False
        if from_raw and re.search(r'<@[^>]*,.*?:', from_raw):
            source_route_flagged = True
        # Also check for domain appended after space (e.g. "user@legit.com attacker.com")
        from_addr_match = re.search(r'[\w.+-]+@[\w.-]+\s+[\w.-]+\.[\w]{2,}', from_raw)
        if from_addr_match:
            source_route_flagged = True

        if source_route_flagged:
            details.append({"rule": "source_route_injection", "flagged": True,
                            "reason": "From header contains source-route or appended domain — origin spoofing"})
            flags += 1
        else:
            details.append({"rule": "source_route_injection", "flagged": False,
                            "reason": "no source-route injection detected"})

        # Rule 23 — Empty/malformed email (no headers, no From, no Subject)
        # A legitimate email always has From and Subject headers. An email
        # with missing core headers is either malformed or deliberately
        # crafted to exploit parser differences between security tools and
        # email clients (parser differential attack).
        malformed_flagged = False
        has_from = bool((headers.get("from") or "").strip())
        has_subject = bool((headers.get("subject") or "").strip())
        has_body = bool((parsed.get("body_text") or "").strip()) or bool((parsed.get("body_html") or "").strip())
        if not has_from and not has_subject:
            malformed_flagged = True
        elif not has_from and not has_body:
            malformed_flagged = True

        if malformed_flagged:
            details.append({"rule": "malformed_email", "flagged": True,
                            "reason": "Email missing core headers (From/Subject) — parser differential attack or malformed payload"})
            flags += 1
        else:
            details.append({"rule": "malformed_email", "flagged": False,
                            "reason": "core email headers present"})

        # Rule 24 — MIME body part confusion (duplicate Content-Type in MIME parts)
        # Our Rule 19 checks top-level duplicate Content-Type headers. This rule
        # catches MIME attacks where duplicate Content-Types appear inside the
        # raw email body parts (after the top-level headers). Email clients may
        # pick different parts to render, causing one to see safe text while
        # another renders malicious HTML.
        mime_body_confusion = False
        raw_body_text = (parsed.get("body_text") or "") + (parsed.get("body_html") or "")
        # Check if body contains embedded MIME headers (Content-Type appearing in body)
        if not mime_attack_flagged:
            body_ct_count = raw_body_text.lower().count("content-type:")
            if body_ct_count >= 2:
                mime_body_confusion = True

        if mime_body_confusion:
            details.append({"rule": "mime_body_part_confusion", "flagged": True,
                            "reason": f"Multiple Content-Type declarations in MIME body ({body_ct_count}) — rendering confusion attack"})
            flags += 1
        else:
            details.append({"rule": "mime_body_part_confusion", "flagged": False,
                            "reason": "no MIME body part confusion detected"})

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
            "ics_calendar_external",
            "internal_domain_spoof",
            "html_smuggling",
            "return_path_mismatch",
            "multi_from_header",
            "empty_envelope_sender",
            "xss_header_injection",
            "mime_confusion_attack",
            "multi_addr_from",
            "unicode_from_spoofing",
            "source_route_injection",
            "malformed_email",
            "mime_body_part_confusion",
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
