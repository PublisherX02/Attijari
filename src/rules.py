from email.utils import parseaddr
import os


BLOCKED_EXTENSIONS = {".exe", ".js", ".vbs", ".scr", ".bat", ".ps1", ".jar", ".msi", ".cmd", ".com"}
BLOCKED_SENDER = {"malware-site.com", "phishing-test.xyz"}
BLOCKED_HASH = set()


def extract_signals(parsed: dict) -> dict:
    # headers in parsed are lower-cased in email_extraction; be defensive
    headers = parsed.get("headers") or {}
    from_field = headers.get("from") or headers.get("From") or ""
    _, addr = parseaddr(from_field)
    domain = addr.split("@")[1].lower() if "@" in addr else None

    extensions = []
    hashes = []
    attachments = parsed.get("attachments") or []
    for att in attachments:
        name = att.get("original_name") or ""
        _, ext = os.path.splitext(name)
        extensions.append(ext.lower())
        hashes.append(att.get("sha256"))

    return {
        "sender_domain": domain,
        "sender_address": addr,
        "extensions": extensions,
        "hashes": hashes,
        "attachments": attachments,
    }


class RuleEngine:
    def analyze(self, parsed: dict) -> dict:
        signals = extract_signals(parsed)
        details = []
        flags = 0

        # Rule 1 — blocklist domain
        if signals["sender_domain"] in BLOCKED_SENDER:
            details.append({"rule": "blocklist_domain", "flagged": True, "reason": f"blocked domain: {signals['sender_domain']}"})
            flags += 1
        else:
            details.append({"rule": "blocklist_domain", "flagged": False, "reason": "domain not blocked"})

        # Rule 2 — blocked extensions
        bad_exts = [ext for ext in signals["extensions"] if ext in BLOCKED_EXTENSIONS]
        if bad_exts:
            details.append({"rule": "blocked_extension", "flagged": True, "reason": f"blocked extension(s): {', '.join(bad_exts)}"})
            flags += 1
        else:
            details.append({"rule": "blocked_extension", "flagged": False, "reason": "no blocked extensions"})

        # Rule 3 — known bad hashes
        bad_hashes = [h for h in signals["hashes"] if h in BLOCKED_HASH]
        if bad_hashes:
            details.append({"rule": "blocked_hash", "flagged": True, "reason": f"known bad hash: {bad_hashes[0][:12]}..."})
            flags += 1
        else:
            details.append({"rule": "blocked_hash", "flagged": False, "reason": "no known bad hashes"})

        # Rule 4 — heuristic: subtle phishing body + invoice-like attachment
        body = (parsed.get("body_text") or "").lower()
        suspicious_phrases = [
            "unusual charge",
            "transaction details",
            "please confirm",
            "please review",
            "we noticed",
            "we'll assume",
            "within 48 hours",
            "attached file",
            "unexpected charge",
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
        phishy = False
        reasons = []
        if body_matches:
            reasons.append(f"suspicious_phrases: {', '.join(body_matches)}")
            phishy = True
        if attachment_invoice_like:
            reasons.append("invoice_like_attachment")
            phishy = phishy and True  # keep phishy true if body matches as well

        # Only flag if both body looks suspicious and there's an invoice-like attachment
        if body_matches and attachment_invoice_like:
            details.append({"rule": "phishy_body", "flagged": True, "reason": ", ".join(reasons)})
            flags += 1
        else:
            details.append({"rule": "phishy_body", "flagged": False, "reason": "no subtle phishing detected"})

        verdict = "escalated" if flags > 0 else "accepted"

        return {
            "verdict": verdict,
            "rules_run": len(details),
            "flags": flags,
            "details": details,
        }