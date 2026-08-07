from email.utils import parseaddr
import os
import re
import time
import unicodedata
from urllib.parse import urlparse

from threat_feeds import get_feeds, WHITELISTED_DOMAINS
from url_utils import normalize_url


def _normalize_for_phrase_match(text: str) -> str:
    """Strip diacritics and normalize typographic quotes so the ASCII-only
    French phrase lists below (e.g. "compte a ete suspendu") match real
    accented French text ("compte a été suspendu") -- without this, every
    French phrase rule in this file only ever matched pre-stripped/
    transliterated text, never properly-encoded real French. Found while
    investigating why a real "vous avez gagné une réduction" reward-lure
    test email matched none of the existing phrase-based rules: "gagné"
    (U+00E9) never equals "gagne", and typed curly apostrophes (U+2019,
    "d’achat") never equal straight ones ('), no matter how complete the
    phrase list is. Safe to apply to raw body_html too -- HTML tag/
    attribute syntax is plain ASCII, so normalization only affects the
    natural-language content being phrase-matched, not markup structure."""
    text = text.replace("’", "'").replace("‘", "'")
    text = text.replace("“", '"').replace("”", '"')
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


from pathlib import Path

# Interpreter/script extensions that execute arbitrary code on open, not just
# Windows-native ones -- .py/.pyw/.sh/.rb/.pl/.php were missing here despite
# being the same risk class as .js/.vbs/.ps1, and .vbe/.jse/.wsf/.hta were
# already escalated by extraction.py's _SCRIPT_EXTS but never blocked at the
# earlier rules-engine stage, so the two layers disagreed on the same files.
BLOCKED_EXTENSIONS = {
    ".exe", ".js", ".vbs", ".scr", ".bat", ".ps1", ".jar", ".msi", ".cmd", ".com",
    ".vbe", ".jse", ".wsf", ".hta",
    ".py", ".pyw", ".sh", ".rb", ".pl", ".php",
}

# Default-deny for attachment types: every extension the extraction stage
# actually has a real, verified handling story for (documents via oletools,
# PDFs via pdfid/pymupdf, images via tesseract OCR, archives/disk images via
# the archive tool, OneNote/nested-email via their always-escalate paths).
# Anything OUTSIDE this set AND outside BLOCKED_EXTENSIONS is a format this
# pipeline has never been taught anything about -- rather than silently
# falling through to MarkItDown's generic text extraction (which produces
# confident-looking "clean" output for a format it was never actually
# vetted against), unrecognized types are treated as suspicious by design,
# matching CLAUDE.md rule 1 ("fail-safe, never fail-open"). This is a
# deliberate posture shift from "blocklist known-bad" to "allowlist
# known-handled, deny everything else" -- an unusual-but-legitimate
# business file type (e.g. .msg, .pub, .accdb) will get proposed_reject
# under this rule, which is the intended tradeoff: proposed_reject still
# requires human confirmation before anything is actually blocked, so a
# false positive here costs an analyst a look, not a lost email.
RECOGNIZED_ATTACHMENT_EXTENSIONS = {
    # Office documents (oletools) + RTF + PDF
    ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
    ".ppt", ".pptx", ".pptm", ".ppsx", ".ppsm", ".rtf", ".pdf",
    # OneNote (always-escalate, no parser -- still a "known" format)
    ".one",
    # Images (tesseract OCR)
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp",
    # Archives / disk images (archive tool; .rar/.vhd/.vhdx/.cab hit their
    # own "no parser available" escalation inside it, but the FORMAT itself
    # is recognized and deliberately handled, not unknown)
    ".zip", ".7z", ".gz", ".iso", ".img", ".rar", ".vhd", ".vhdx", ".cab", ".lnk",
    # Nested email (always-escalate, no deep scan -- still a known format)
    ".eml",
    # Plain text/data -- low-risk, generic MarkItDown text extraction is a
    # legitimate handling story for these specifically (unlike arbitrary
    # unknown binary formats)
    ".txt", ".csv",
}

# Rule 8: Encrypted attachment + password in body = automatic escalate/reject
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
# Shared infrastructure IPs — "never auto-block shared
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
# Shared email domains — "never auto-block shared infrastructure."
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
    """Cascading blocklist: on confirmed malicious, block all associated indicators.

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


# ---------------------------------------------------------------------------
# Masked hyperlink detection ("hidden URL" phishing) — a link whose visible
# text names one domain but whose actual href points somewhere else
# entirely, e.g. <a href="http://evil.tld/x">https://paypal.com/login</a>.
# Nothing in this pipeline compared displayed link text to its real
# destination before this: URL extraction elsewhere in this file treats
# HTML source as flat text via regex, so it happens to catch both the
# displayed and the real URL as separate entries in body_urls, but never
# links "claims to be X" to "actually goes to Y" — the single most classic
# phishing link-masking technique.
# ---------------------------------------------------------------------------
from html.parser import HTMLParser as _HTMLParser

# Domain-like token embedded in arbitrary text — requires a label plus a
# 2+ letter TLD so ordinary abbreviations ("e.g.", "U.S.") never match
# (their final component is a single letter).
_TEXT_DOMAIN_RE = re.compile(
    r'(?:https?://)?(?:www\.)?'
    r'([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z]{2,63}(?:\.[a-z]{2,63})?)',
    re.IGNORECASE,
)

# <meta http-equiv="refresh" content="0;url=...">: a fully JS-free HTML
# redirect. http-equiv/content can appear in either attribute order, so the
# tag itself is matched first (order-independent), then the target url= is
# searched for separately within that matched tag substring — interleaving
# both into one regex made the url= capture order-dependent (it would only
# succeed when http-equiv happened to come first), which two independent
# regexes avoid.
_META_REFRESH_RE = re.compile(
    r'<meta\b[^>]*http-equiv\s*=\s*["\']?refresh["\']?[^>]*>',
    re.IGNORECASE,
)
_META_REFRESH_URL_RE = re.compile(r'url\s*=\s*["\']?([^"\'>\s;]+)', re.IGNORECASE)

# Known email-security URL-rewriting proxies legitimately show the
# original destination as link text while routing the actual href through
# their own scanning domain — that mismatch is the proxy working as
# designed, not deception, so these are excluded from flagging.
_SAFE_LINK_PROXY_DOMAINS = {
    "safelinks.protection.outlook.com", "urldefense.proofpoint.com",
    "protect-eu.mimecast.com", "protect-us.mimecast.com", "protect2.fireeye.com",
    "clicktime.symantec.com",
}

# Brand impersonation in the From display name -- one of the single most
# common real-world phishing tactics ("PayPal Support <random@gmail.com>",
# "Microsoft Security <attacker@evil.tld>") and distinct from
# internal_domain_spoof (Rule 13), which only checks claims of THIS bank's
# own internal domain. Deliberately excludes brands whose legitimate
# ecosystem is too broad/ambiguous to pin to a fixed domain set without
# real false-positive risk (e.g. generic terms). Each brand keyword is
# matched on WORD BOUNDARIES against the display name only (never the
# address), so it can't be tripped by a brand name coincidentally
# substring-matching inside an unrelated word.
_BRAND_DOMAINS = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com", "office365.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.fr", "amazon.co.uk", "amazon.de"},
    "netflix": {"netflix.com"},
    "dhl": {"dhl.com", "dhl.fr"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "meta": {"meta.com", "facebookmail.com", "facebook.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com", "facebookmail.com", "meta.com"},
    "linkedin": {"linkedin.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com"},
    "dropbox": {"dropbox.com"},
    "zoom": {"zoom.us"},
    "whatsapp": {"whatsapp.com"},
    "western union": {"westernunion.com"},
    "attijari": {"attijaribank.com.tn", "attijariwafabank.com", "attijari.com.tn"},
}
_BRAND_KEYWORD_RE = {
    brand: re.compile(r'\b' + re.escape(brand) + r'\b', re.IGNORECASE)
    for brand in _BRAND_DOMAINS
}


class _AnchorExtractor(_HTMLParser):
    """Extracts (href, visible_text) pairs from <a> tags in an HTML email body."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.anchors: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._current_href = dict(attrs).get("href")
            self._current_text = []

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:
            self.anchors.append((self._current_href, "".join(self._current_text).strip()))
            self._current_href = None
            self._current_text = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)


class _HiddenTextExtractor(_HTMLParser):
    """Extracts text content from elements CSS-hides from a human reader
    (display:none, font-size:0, visibility:hidden) via an inline style
    attribute -- text invisible on screen but still present in the raw
    HTML an LLM analysis stage reads verbatim. Uses a stack of booleans
    (not per-tag-name matching) to track "is this element or an ancestor
    hidden" -- imprecise if a document is malformed, but that's an
    acceptable tradeoff for a heuristic phishing signal, not a structural
    security boundary."""

    _HIDING_STYLE_RE = re.compile(
        r'display\s*:\s*none|font-size\s*:\s*0(?:px|em|%)?\b|visibility\s*:\s*hidden',
        re.IGNORECASE,
    )

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden_text_parts: list[str] = []
        self._hide_stack: list[bool] = [False]

    def handle_starttag(self, tag, attrs):
        style = dict(attrs).get("style") or ""
        is_hidden_here = bool(self._HIDING_STYLE_RE.search(style))
        self._hide_stack.append(self._hide_stack[-1] or is_hidden_here)

    def handle_endtag(self, tag):
        if len(self._hide_stack) > 1:
            self._hide_stack.pop()

    def handle_data(self, data):
        if self._hide_stack[-1] and data.strip():
            self.hidden_text_parts.append(data.strip())


# Common two-label public suffixes -- without this, last-two-labels alone
# (e.g. "paypal.co.uk" -> "co.uk") makes any two links under the same
# multi-part TLD register as a "mismatch" (paypal.co.uk vs paypal.com.tn
# both reduce to different 2-label tails already, but paypal.com displayed
# vs a real paypal.co.uk href would incorrectly flag as hard evidence).
# Not a full public-suffix-list implementation -- covers the TLDs relevant
# to this bank's Tunisian/French/international context; a gap for anything
# outside this set is a missed detection, not a false positive, which is
# the safer direction to be wrong in for a HARD_EVIDENCE rule.
_MULTI_LABEL_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.tn", "com.tn", "org.tn",
    "net.tn", "gov.tn", "co.jp", "com.au", "co.nz", "com.br", "co.in",
    "co.za", "com.mx",
}


def _registrable_domain(host: str) -> str:
    parts = host.lower().split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_LABEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _find_href_text_mismatches(body_html: str) -> list[dict]:
    """Returns a list of {displayed_domain, actual_host, href} for every
    anchor whose visible text names a domain that doesn't match where the
    href actually goes. Best-effort: malformed HTML or unparseable anchors
    are silently skipped rather than raised (this is a heuristic signal
    layered on top of, not a replacement for, deterministic rules)."""
    if not body_html or "<a" not in body_html.lower():
        return []
    parser = _AnchorExtractor()
    try:
        parser.feed(body_html)
    except Exception:
        return []

    mismatches = []
    for href, text in parser.anchors:
        if not href or not text:
            continue
        href = href.strip()
        if href.lower().startswith(("mailto:", "tel:", "javascript:", "#", "cid:")):
            continue
        text_match = _TEXT_DOMAIN_RE.search(text)
        if not text_match:
            continue
        text_domain = text_match.group(1).lower()
        try:
            href_host = urlparse(href).hostname
        except Exception:
            href_host = None
        if not href_host:
            continue
        href_host = href_host.lower()
        if href_host in _SAFE_LINK_PROXY_DOMAINS:
            continue
        if _registrable_domain(text_domain) != _registrable_domain(href_host):
            mismatches.append({
                "displayed_domain": text_domain,
                "actual_host": href_host,
                "href": href[:200],
            })
    return mismatches


def _find_hidden_destination_links(body_html: str) -> list[dict]:
    """Links whose visible text never discloses a destination at all
    (generic "click here"/"lien"/"voir"-style text) with a real external
    href. This is the OTHER "hidden URL" phishing tactic, distinct from
    _find_href_text_mismatches: that one requires the text to make a FALSE
    domain claim; this one requires no claim at all -- the reader has no
    way to know where the link goes without hovering/clicking. A bare
    "click here" is completely ordinary in legitimate marketing on its
    own, so this is intentionally NOT treated as a standalone signal --
    callers must pair it with an independent lure/urgency signal already
    present on the same email before calling it phishing."""
    if not body_html or "<a" not in body_html.lower():
        return []
    parser = _AnchorExtractor()
    try:
        parser.feed(body_html)
    except Exception:
        return []

    hidden = []
    for href, text in parser.anchors:
        if not href:
            continue
        href = href.strip()
        if href.lower().startswith(("mailto:", "tel:", "javascript:", "#", "cid:")):
            continue
        try:
            href_host = urlparse(href).hostname
        except Exception:
            href_host = None
        if not href_host:
            continue
        if _TEXT_DOMAIN_RE.search(text or ""):
            continue  # text DOES disclose a destination -- that's the mismatch check's job, not this one
        hidden.append({"href": href[:200], "actual_host": href_host.lower()})
    return hidden


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

        # Rule 2b — unrecognized attachment type (default-deny)
        # Extensions already caught by Rule 2 (BLOCKED_EXTENSIONS) are
        # deliberately excluded here -- that rule already flags them, and
        # double-flagging the same attachment under two rule names for the
        # same underlying fact is just analyst-facing noise. This rule is
        # specifically for the THIRD category: not known-safe, not
        # known-dangerous, just never vetted at all -- an attachment with
        # NO extension counts here too (represented as "" by
        # extract_signals, via os.path.splitext) rather than being silently
        # skipped: a stripped extension is, if anything, more suspicious
        # than an unusual-but-present one, not less.
        unknown_exts = [
            (ext if ext else "(no extension)")
            for ext in signals["extensions"]
            if ext not in BLOCKED_EXTENSIONS and ext not in RECOGNIZED_ATTACHMENT_EXTENSIONS
        ]
        if unknown_exts:
            details.append({"rule": "unrecognized_attachment_type", "flagged": True,
                            "reason": f"attachment extension(s) not in any known-safe or "
                                      f"known-dangerous list, default-deny: {', '.join(unknown_exts)}"})
            flags += 1
        else:
            details.append({"rule": "unrecognized_attachment_type", "flagged": False,
                            "reason": "all attachment extensions recognized"})

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
        # Combines body_text AND body_html (matching the pattern Rules 25/27/27b
        # use further down this function) -- an HTML-only email (no text/plain
        # part at all, the common case for real phishing kits) previously made
        # this `body` variable an empty string, silently blinding phishy_body,
        # vishing_callback, and thread_hijack_bec's financial-keyword check to
        # any email that never had a plain-text alternative. Confirmed live:
        # identical urgency+credential-targeting wording caught when placed in
        # body_text but missed entirely when placed only in body_html, before
        # this fix.
        body = _normalize_for_phrase_match(
            ((parsed.get("body_text") or "") + " " + (parsed.get("body_html") or "")).lower())

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

        # Rule 9 — rule 8: Encrypted attachment + password in body
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

        # Check if sender is external (not @attijaribank.com.tn)
        sender_is_external = (
            signals["sender_domain"] and
            signals["sender_domain"] != "attijaribank.com.tn" and
            not signals["sender_domain"].endswith(".attijaribank.com.tn")
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
        # If sender claims @attijaribank.com.tn but authentication fails,
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
        html_matches = []
        body_html = (parsed.get("body_html") or "").lower()
        if body_html:
            _HTML_DANGER_PATTERNS = (
                "<script", "javascript:", "vbscript:",
                "createobjecturl", "new blob(", "new blob (",
                "uint8array", "atob(", "btoa(",
                "mhtml:", "data:application",
            )
            html_matches = [p for p in _HTML_DANGER_PATTERNS if p in body_html]

            # <meta http-equiv="refresh" content="0;url=..."> is a fully
            # JS-free HTML redirect -- no <script>, no event-handler
            # attribute, no <a href>, so it's invisible to every other
            # pattern above AND to the anchor-only masked_link_mismatch /
            # hidden_url_phishing_tactic rules below (both bail out
            # immediately unless the HTML contains an "<a" tag). Confirmed
            # live: a neutral-worded email whose only payload is a
            # meta-refresh to a phishing lookalike domain returned
            # "accepted" with zero rules flagged before this fix.
            meta_refresh_match = _META_REFRESH_RE.search(body_html)
            if meta_refresh_match:
                url_match = _META_REFRESH_URL_RE.search(meta_refresh_match.group(0))
                target = url_match.group(1) if url_match else ""
                html_matches.append(f"meta-refresh-redirect{f' to {target[:120]}' if target else ''}")

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

        # Rule 21b — Brand impersonation in From display name
        display_name_raw, _ = parseaddr(from_raw)
        display_name_norm = _normalize_for_phrase_match(display_name_raw)
        brand_impersonation_flagged = False
        brand_impersonation_reason = ""
        sender_dom_for_brand = (signals.get("sender_domain") or "").lower()
        for brand, legit_domains in _BRAND_DOMAINS.items():
            if not _BRAND_KEYWORD_RE[brand].search(display_name_norm):
                continue
            if sender_dom_for_brand and any(
                sender_dom_for_brand == d or sender_dom_for_brand.endswith("." + d)
                for d in legit_domains
            ):
                continue  # genuinely from the brand's own domain -- not impersonation
            brand_impersonation_flagged = True
            brand_impersonation_reason = (
                f"display name claims '{brand}' but sender domain "
                f"'{sender_dom_for_brand or 'unknown'}' does not match {brand}'s "
                f"legitimate domain(s)"
            )
            break

        if brand_impersonation_flagged:
            details.append({"rule": "brand_impersonation_display_name", "flagged": True,
                            "reason": brand_impersonation_reason})
            flags += 1
        else:
            details.append({"rule": "brand_impersonation_display_name", "flagged": False,
                            "reason": "no brand impersonation in display name detected"})

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

        # Rule 25 — Script/executable markup in EITHER body representation
        # Rule 18 (xss_header_injection) only inspects body_html for inline
        # event-handler/script patterns, and only after the header checks
        # find nothing. EPVME miss review (2026-07-22) found a live
        # SVG+<script> XSS payload delivered as a single-part text/html
        # message via a data:image/svg+xml;base64 URI wrapped in <EMBED> —
        # get_body(preferencelist=("plain",)) returns None for that message
        # (there is no text/plain part), so any body_text-only check misses
        # it entirely, and the "<svg" literal itself is base64-encoded so
        # Rule 18's plain substring match on body_html doesn't see it either
        # — only the undecoded "data:image/svg+xml" wrapper is literal text.
        # This rule checks body_text AND body_html together, and additionally
        # decodes base64 data-URI payloads to catch script tags hidden inside
        # them. Neither representation of an email legitimately contains
        # <script>/<embed>/<iframe> markup or a javascript: URI.
        text_script_flagged = False
        _TEXT_SCRIPT_PATTERNS = (
            "<script", "<embed", "<iframe", "<object", "<svg",
            "javascript:", "vbscript:", "data:text/html", "data:image/svg+xml",
        )
        # Same text_text+body_html combination as `body` above (Rule 4) --
        # aliased rather than recomputed so the two can never drift apart again.
        combined_body_lower = body
        text_script_matches = [p for p in _TEXT_SCRIPT_PATTERNS if p in combined_body_lower]

        # Decode base64 data-URI payloads (SVG/HTML smuggling) and check the
        # decoded content for the same patterns — catches payloads hidden
        # behind base64 where the literal "<script"/"<svg" isn't in the raw text.
        if not text_script_matches:
            import base64 as _b64
            for _durl_match in re.finditer(r'data:[\w/+.\-]+;base64,([a-zA-Z0-9+/=]{16,})', combined_body_lower):
                try:
                    decoded = _b64.b64decode(_durl_match.group(1) + "===").decode("utf-8", errors="ignore").lower()
                    inner_hits = [p for p in _TEXT_SCRIPT_PATTERNS if p in decoded]
                    if inner_hits:
                        text_script_matches = [f"decoded-data-uri:{h}" for h in inner_hits]
                        break
                except Exception:
                    continue

        if text_script_matches:
            text_script_flagged = True

        if text_script_flagged:
            details.append({"rule": "text_body_script_payload", "flagged": True,
                            "reason": f"executable markup in email body: {', '.join(text_script_matches[:3])}"})
            flags += 1
        else:
            details.append({"rule": "text_body_script_payload", "flagged": False,
                            "reason": "no script/markup payload in body"})

        # Rule 26 — Structural injection in header VALUES (Subject/To/From)
        # EPVME miss review found two attack patterns Rule 18/19 missed:
        #   (a) a Subject line that IS raw MIME header syntax
        #       ("Mime-Version:Content-Type:Content-Transfer-Encoding;") with
        #       an empty body — MIME-smuggling via the subject field, not a
        #       real duplicate Content-Type header so Rule 19 never fires.
        #   (b) a To header containing an HTML tag fragment
        #       ("victim<div style=color") — generic markup injection that
        #       Rule 18's narrow onXXX=/<svg pattern list doesn't cover.
        # Note: Rule 19 (mime_confusion_attack) was previously refactored
        # AWAY from subject-keyword matching (2026-07-03) because a bare
        # mention of "content-type" in a normal subject is common and noisy.
        # This rule stays narrow to avoid resurrecting that false-positive
        # rate: the HTML-tag check matches a curated list of real tag names
        # (never a bare "<letter", which would match every ordinary
        # "Display Name <addr@domain>" RFC 5322 mailbox — verified against
        # real EPVME/benign samples during development, since that format
        # is the overwhelming majority of From/Reply-To/To header values),
        # and the MIME-token check requires 2+ distinct real header-name
        # tokens co-occurring in one field, which no legitimate subject/to/
        # from ever contains.
        header_inject_flagged = False
        header_inject_reasons = []
        _MIME_HEADER_TOKENS = ("mime-version", "content-type", "content-transfer-encoding")
        _HEADER_HTML_TAG_NAMES = (
            "div", "script", "embed", "iframe", "object", "svg", "img",
            "style", "form", "body", "html", "table", "span", "input",
            "link", "meta", "a",
        )
        _HEADER_TAG_RE = re.compile(r'<\s*(' + '|'.join(_HEADER_HTML_TAG_NAMES) + r')\b', re.IGNORECASE)
        _HEADER_FIELDS_TO_CHECK = {
            "subject": headers.get("subject") or "",
            "to": headers.get("to") or "",
            "from": headers.get("from") or "",
            "reply-to": headers.get("reply-to") or "",
        }
        for field_name, field_value in _HEADER_FIELDS_TO_CHECK.items():
            fv_lower = field_value.lower()
            mime_token_hits = sum(1 for tok in _MIME_HEADER_TOKENS if tok in fv_lower)
            if mime_token_hits >= 2:
                header_inject_flagged = True
                header_inject_reasons.append(f"{field_name}: MIME header syntax embedded in field value")
            if _HEADER_TAG_RE.search(field_value):
                header_inject_flagged = True
                header_inject_reasons.append(f"{field_name}: HTML tag fragment in header value")

        if header_inject_flagged:
            details.append({"rule": "header_field_injection", "flagged": True,
                            "reason": "; ".join(header_inject_reasons[:3])})
            flags += 1
        else:
            details.append({"rule": "header_field_injection", "flagged": False,
                            "reason": "no structural injection in Subject/To/From/Reply-To"})

        # Rule 27 — Advance-fee fraud / "419" scam vocabulary
        # EPVME miss review found a textbook advance-fee-fraud email
        # ("ATTENTION: Beneficiary", "THE PRESIDENCY", "THE CASTLE VILLA")
        # that no structural or credential-phishing rule catches — it asks
        # for nothing technical, it's pure social-engineering vocabulary.
        # This genre has an extremely distinctive, low-false-positive-risk
        # phrase set (a legitimate bank email will never say "next of kin"
        # or "unclaimed inheritance"), so two independent hits are hard
        # evidence rather than a soft signal.
        # Uses combined_body_lower (text+html), not the text-only `body`
        # used by Rule 4 above — the EPVME 419 sample that motivated this
        # rule is an HTML-only message with no text/plain part, so a
        # text-only check would silently never match it.
        _FRAUD_419_PHRASES = (
            "next of kin", "beneficiary of this fund", "unclaimed fund",
            "unclaimed inheritance", "your inheritance", "unclaimed inheritance",
            "unclaimed estate", "dormant account", "diplomatic courier",
            "diplomatic immunity", "compensation fund", "unclaimed compensation",
            "unclaimed sum", "the presidency", "unclaimed contract sum",
            "unclaimed lottery", "million dollars", "million euros",
            "confidential business proposal", "attention: beneficiary",
            "total inheritance", "abandoned fund",
        )
        fraud_419_matches = [p for p in _FRAUD_419_PHRASES if p in combined_body_lower]
        fraud_419_flagged = len(fraud_419_matches) >= 2

        if fraud_419_flagged:
            details.append({"rule": "advance_fee_fraud", "flagged": True,
                            "reason": f"advance-fee/419 scam vocabulary: {', '.join(fraud_419_matches[:3])}"})
            flags += 1
        else:
            details.append({"rule": "advance_fee_fraud", "flagged": False,
                            "reason": "no advance-fee fraud vocabulary detected"})

        # Rule 27b — Reward/prize/lottery-lure phishing vocabulary
        # phishy_body (Rule 4) requires BOTH coercive urgency AND financial/
        # credential targeting — a fear-based pattern. Reward-bait scams
        # ("vous avez gagné une réduction de 33%... cliquez sur le lien")
        # are a distinct, equally common social-engineering family that
        # matches neither tier: there's no threat of suspension, and
        # "click the link to claim a discount" doesn't match the
        # credential/wire-transfer-specific targeting phrases. Same
        # 2-independent-hits threshold as Rule 27 (advance_fee_fraud) for
        # the same reason: this vocabulary is distinctive enough that two
        # hits is hard evidence, not a soft signal, but a single generic
        # word ("réduction"/"discount" alone) is common in legitimate
        # marketing and must not trip this alone.
        _REWARD_LURE_PHRASES = (
            "vous avez gagne", "vous avez ete selectionne", "vous etes le gagnant",
            "heureux gagnant", "felicitations vous avez gagne", "tirage au sort",
            "vous avez remporte", "bon d'achat", "carte cadeau gratuite",
            "cliquez pour reclamer", "reclamer votre gain", "reclamer votre prix",
            "offre exclusive reservee", "vous avez ete choisi",
            # English equivalents
            "you have won", "you've been selected", "you are the lucky winner",
            "congratulations you have won", "claim your prize", "claim your reward",
            "free gift card", "click to claim", "you have been chosen",
        )
        reward_lure_matches = [p for p in _REWARD_LURE_PHRASES if p in combined_body_lower]
        reward_lure_flagged = len(reward_lure_matches) >= 2

        if reward_lure_flagged:
            details.append({"rule": "reward_lure_phishing", "flagged": True,
                            "reason": f"reward/prize-lure scam vocabulary: {', '.join(reward_lure_matches[:3])}"})
            flags += 1
        else:
            details.append({"rule": "reward_lure_phishing", "flagged": False,
                            "reason": "no reward/prize-lure vocabulary detected"})

        # Rule 27c — "Hidden URL" phishing tactic: link destination never
        # disclosed to the reader (generic "click here"/"lien" text, no
        # domain claim at all -- Rule 29's masked_link_mismatch covers the
        # case where the text DOES claim a domain and lies), paired with an
        # independent lure/urgency signal already found on this same email.
        # Neither signal alone is unusual (a bare "click here" is normal
        # marketing; a discount mention alone is normal marketing); the
        # combination is the tactic. This is what a real reward-lure test
        # email with an opaque "lien" link and no href/text mismatch was
        # missing before -- reward_lure_phishing caught the vocabulary, but
        # nothing named the link-concealment tactic itself.
        hidden_links = _find_hidden_destination_links(parsed.get("body_html") or "")
        hidden_url_tactic = bool(hidden_links) and (reward_lure_flagged or (urgency_matches and targeting_matches))
        if hidden_url_tactic:
            dests = ", ".join(sorted({h["actual_host"] for h in hidden_links})[:3])
            details.append({"rule": "hidden_url_phishing_tactic", "flagged": True,
                            "reason": f"phishing tactic: hidden URL — link destination(s) ({dests}) "
                                      f"never shown to the reader, paired with lure/urgency vocabulary"})
            flags += 1
        else:
            details.append({"rule": "hidden_url_phishing_tactic", "flagged": False,
                            "reason": "no undisclosed-link-destination + lure/urgency pattern detected"})

        # Rule 27d — Hidden text used for prompt injection: CSS-invisible
        # content (display:none/font-size:0/visibility:hidden) containing
        # AI-instruction-style phrasing, aimed at this pipeline's own LLM
        # analysis stage rather than the human reader who will never see it
        # rendered. Deliberately does NOT flag hidden text alone -- hiding
        # text via CSS is a universal, mostly-benign email-marketing
        # technique (preheader/preview text) on its own, so this mirrors
        # hidden_url_phishing_tactic's "combine two independent signals"
        # pattern: hidden text is only escalate-worthy when it ALSO
        # contains injection-style content, not merely for being hidden.
        _PROMPT_INJECTION_PHRASES = (
            "ignore previous instructions", "ignore all previous instructions",
            "ignore the above", "disregard previous instructions",
            "disregard the above", "new instructions:", "system prompt:",
            "you are now", "ignore your instructions",
            "this email is safe", "this is not phishing", "mark as safe",
            "do not flag this", "classify this as safe", "override your",
            "ignore any prior", "forget previous",
        )
        _hidden_extractor = _HiddenTextExtractor()
        try:
            _hidden_extractor.feed(parsed.get("body_html") or "")
        except Exception:
            pass
        hidden_text_combined = _normalize_for_phrase_match(
            " ".join(_hidden_extractor.hidden_text_parts).lower())
        injection_matches = [p for p in _PROMPT_INJECTION_PHRASES if p in hidden_text_combined]
        if injection_matches:
            details.append({"rule": "hidden_text_prompt_injection", "flagged": True,
                            "reason": f"CSS-hidden text contains AI-instruction-style phrasing: "
                                      f"{', '.join(injection_matches[:3])}"})
            flags += 1
        else:
            details.append({"rule": "hidden_text_prompt_injection", "flagged": False,
                            "reason": "no hidden-text prompt injection detected"})

        # Rule 28 — Unicode/RTLO spoofing in attachment filenames
        # Same trick as Rule 21, applied to attachment names instead of the
        # From header: a right-to-left override (U+202E) or other bidi/
        # zero-width control character reverses how the filename displays,
        # so "invoice[RLO]gpj.exe" renders as "invoice...exe.jpg" — a
        # human reviewer sees what looks like a photo, not an executable.
        filename_spoof_flagged = False
        filename_spoof_names = []
        for att in (parsed.get("attachments") or []):
            att_name = att.get("original_name") or ""
            for trick in _UNICODE_TRICKS:
                if trick in att_name:
                    filename_spoof_flagged = True
                    filename_spoof_names.append(att_name)
                    break

        if filename_spoof_flagged:
            details.append({"rule": "unicode_filename_spoofing", "flagged": True,
                            "reason": "Suspicious tactic used: Right-to-left override (RTLO) / Unicode "
                                      "filename disguise — attachment name(s) " +
                                      ", ".join(repr(n) for n in filename_spoof_names[:3]) +
                                      " contain bidi/zero-width control characters that can hide the "
                                      "true file extension from a human reviewer"})
            flags += 1
        else:
            details.append({"rule": "unicode_filename_spoofing", "flagged": False,
                            "reason": "no Unicode/RTLO spoofing in attachment filenames"})

        # Rule 29 — Masked hyperlink ("hidden URL" phishing): displayed link
        # text names one domain but the actual href points somewhere else
        # entirely, e.g. <a href="http://evil.tld/x">https://paypal.com</a>.
        # See _find_href_text_mismatches for why nothing else in this file
        # (flat regex URL extraction, feed-based reputation lookups) ever
        # caught this specific technique.
        link_mismatches = _find_href_text_mismatches(parsed.get("body_html") or "")
        if link_mismatches:
            details.append({"rule": "masked_link_mismatch", "flagged": True,
                            "reason": "; ".join(
                                f'displayed "{m["displayed_domain"]}" but links to "{m["actual_host"]}"'
                                for m in link_mismatches[:3])})
            flags += 1
        else:
            details.append({"rule": "masked_link_mismatch", "flagged": False,
                            "reason": "no displayed-text/href domain mismatch in links"})

        # Determine verdict severity:
        # - "proposed_reject": deterministic hard-evidence rules fired
        #   (blocklist, bad extension, bad hash, threat feed match)
        #   → goes to human review as a proposed rejection
        # - "escalated": only heuristic/soft rules fired (phishy_body)
        #   → goes to human review as ambiguous
        # - "accepted": nothing fired
        HARD_EVIDENCE_RULES = {
            "blocklist_domain", "blocked_extension", "unrecognized_attachment_type", "blocked_hash",
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
            "brand_impersonation_display_name",
            "unicode_filename_spoofing",
            "source_route_injection",
            "malformed_email",
            "mime_body_part_confusion",
            "text_body_script_payload",
            "header_field_injection",
            "advance_fee_fraud",
            "masked_link_mismatch",
            "reward_lure_phishing",
            "hidden_url_phishing_tactic",
            "hidden_text_prompt_injection",
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
