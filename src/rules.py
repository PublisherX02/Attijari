from datetime import datetime
from email.utils import parseaddr


BLOCKLIST_DOMAINS = {
    "example.com",
    "malicious.example",
}

BLOCKED_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".js",
    ".msi",
    ".txt",
    ".ps1",
    ".scr",
    ".vbs",
}

BLOCKED_HASHES = {
    # Populate with known-bad attachment hashes as they are discovered.
}


class RuleEngine:
    """Applies deterministic security rules to a parsed email."""

    def __init__(self):
        self.rules = [
            self._check_blocklist_domain,
            self._check_blocked_extension,
            self._check_blocked_hash,
        ]

    def analyze(self, parsed: dict) -> dict:
        results = [rule_fn(parsed) for rule_fn in self.rules]
        flags = [result for result in results if result["flagged"]]
        verdict = "escalated" if flags else "accepted"

        return {
            "verdict": verdict,
            "rules_run": len(results),
            "flags": len(flags),
            "details": results,
            "analyzed_at": datetime.now().isoformat(),
        }

    def _extract_domains(self, parsed: dict) -> set[str]:
        domains = set()
        for field in ("from", "reply-to", "return-path"):
            value = parsed.get("headers", {}).get(field)
            if not value:
                continue
            _, address = parseaddr(value)
            if "@" in address:
                domains.add(address.rsplit("@", 1)[-1].lower())
        return domains

    def _check_blocklist_domain(self, parsed: dict) -> dict:
        domains = self._extract_domains(parsed)
        blocked = sorted(domains.intersection(BLOCKLIST_DOMAINS))
        return {
            "rule": "blocklist_domain",
            "flagged": bool(blocked),
            "reason": f"Blocked domain(s): {', '.join(blocked)}" if blocked else "OK",
        }

    def _check_blocked_extension(self, parsed: dict) -> dict:
        blocked = []
        for attachment in parsed.get("attachments", []):
            name = (attachment.get("original_name") or "").lower()
            if any(name.endswith(ext) for ext in BLOCKED_EXTENSIONS):
                blocked.append(attachment.get("original_name") or "unnamed")

        return {
            "rule": "blocked_extension",
            "flagged": bool(blocked),
            "reason": f"Blocked extension(s): {', '.join(blocked)}" if blocked else "OK",
        }

    def _check_blocked_hash(self, parsed: dict) -> dict:
        blocked = []
        for attachment in parsed.get("attachments", []):
            sha256 = attachment.get("sha256")
            if sha256 and sha256 in BLOCKED_HASHES:
                blocked.append(attachment.get("original_name") or sha256)

        return {
            "rule": "blocked_hash",
            "flagged": bool(blocked),
            "reason": f"Blocked hash(es): {', '.join(blocked)}" if blocked else "OK",
        }
