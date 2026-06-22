from email.utils import parseaddr
import os
import re
from urllib.parse import urlparse

from threat_feeds import get_feeds
from url_utils import normalize_url


from pathlib import Path

BLOCKED_EXTENSIONS = {".exe", ".js", ".vbs", ".scr", ".bat", ".ps1", ".jar", ".msi", ".cmd", ".com"}

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_DATA_DIR.mkdir(parents=True, exist_ok=True)
_BLOCKLIST_FILE = _DATA_DIR / "blocked_senders.txt"

# Pre-load blocklist
BLOCKED_SENDER = {"malware-site.com", "phishing-test.xyz"}
if _BLOCKLIST_FILE.exists():
    try:
        lines = _BLOCKLIST_FILE.read_text(encoding="utf-8").splitlines()
        for line in lines:
            if line.strip():
                BLOCKED_SENDER.add(line.strip().lower())
    except Exception:
        pass

BLOCKED_HASH = set()

def add_to_blocklist(sender: str):
    """Add a sender to the persistent blocklist dynamically."""
    if not sender:
        return
    sender = sender.strip().lower()
    if sender in BLOCKED_SENDER:
        return
    
    BLOCKED_SENDER.add(sender)
    try:
        with open(_BLOCKLIST_FILE, "a", encoding="utf-8") as f:
            f.write(f"{sender}\n")
    except Exception:
        pass


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

    # Extract domains from URLs
    url_domains = set()
    for url in urls:
        try:
            h = urlparse(url).hostname
            if h:
                url_domains.add(h.lower())
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

        # Rule 1 — blocklist domain (static)
        if signals["sender_domain"] and signals["sender_domain"] in BLOCKED_SENDER:
            details.append({"rule": "blocklist_domain", "flagged": True,
                            "reason": f"blocked domain: {signals['sender_domain']}"})
            flags += 1
        else:
            details.append({"rule": "blocklist_domain", "flagged": False, "reason": "domain not blocked"})

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

        # Rule 4 — phishing body + invoice-like attachment heuristic
        body = (parsed.get("body_text") or "").lower()
        suspicious_phrases = [
            "unusual charge", "transaction details", "please confirm",
            "please review", "we noticed", "we'll assume",
            "within 48 hours", "attached file", "unexpected charge",
        ]
        invoice_indicators = ["invoice", "bill", "payment", "receipt"]
        attachment_invoice_like = False
        for att in signals.get("attachments", []):
            name = (att.get("original_name") or "").lower()
            if any(ind in name for ind in invoice_indicators):
                attachment_invoice_like = True
            _, ext = os.path.splitext(name)
            if ext in {".doc", ".docx", ".xls", ".xlsx", ".pdf"}:
                attachment_invoice_like = True

        body_matches = [p for p in suspicious_phrases if p in body]
        if body_matches and attachment_invoice_like:
            reasons = [f"suspicious_phrases: {', '.join(body_matches)}", "invoice_like_attachment"]
            details.append({"rule": "phishy_body", "flagged": True, "reason": ", ".join(reasons)})
            flags += 1
        else:
            details.append({"rule": "phishy_body", "flagged": False, "reason": "no subtle phishing detected"})

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

        verdict = "escalated" if flags > 0 else "accepted"

        return {
            "verdict": verdict,
            "rules_run": len(details),
            "flags": flags,
            "details": details,
        }
