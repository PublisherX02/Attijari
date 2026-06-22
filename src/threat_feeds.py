"""threat_feeds.py — Local threat intelligence feed loader

Loads OpenPhish and URLhaus datasets into fast in-memory lookup sets.
Used by the rules engine for deterministic blocking of known-bad
URLs, IPs, and domains before any LLM or API call.

Data files:
  - src/openphish.txt  — one phishing URL per line
  - src/urlhaus.txt    — abuse.ch CSV (id, dateadded, url, status, ...)

These are LOCAL files only — no email content is ever sent externally.
Only metadata (URLs, IPs, domains) from email headers/body are checked.
"""
from __future__ import annotations

import csv
import io
import time
from pathlib import Path
from urllib.parse import urlparse


_SRC_DIR = Path(__file__).resolve().parent
_OPENPHISH_PATH = _SRC_DIR / "openphish.txt"
_URLHAUS_PATH = _SRC_DIR / "urlhaus.txt"

OPENPHISH_URL = "https://openphish.com/feed.txt"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv/"

# Shared infrastructure whitelist — CLAUDE.md: "never auto-block shared
# infrastructure IPs (Gmail, Outlook relays). A whitelist override always wins."
# Attackers host malware on these platforms, but blocking the domain itself
# would block ALL legitimate traffic. Only full URLs are checked, not domains.
WHITELISTED_DOMAINS = {
    # Google
    "google.com", "googleapis.com", "googleusercontent.com",
    "drive.google.com", "docs.google.com", "sites.google.com",
    "drive.usercontent.google.com", "firebasestorage.googleapis.com",
    # Microsoft
    "microsoft.com", "outlook.com", "live.com", "office.com",
    "onedrive.live.com", "sharepoint.com",
    # Other major platforms
    "dropbox.com", "github.com", "amazonaws.com",
    "cloudfront.net", "akamaihd.net",
}


class ThreatFeeds:
    """In-memory threat intelligence from local feed files."""

    def __init__(self):
        self.malicious_urls: set[str] = set()
        self.malicious_domains: set[str] = set()
        self.malicious_ips: set[str] = set()
        self._loaded = False
        self._load_time = 0.0
        self._stats: dict[str, int] = {}

    def load(self) -> dict[str, int]:
        """Load all feed files. Safe to call multiple times (idempotent)."""
        if self._loaded:
            return self._stats

        # HIGH-03 Fix: Check file age
        now = time.time()
        for path, name in [(_OPENPHISH_PATH, "OpenPhish"), (_URLHAUS_PATH, "URLhaus")]:
            if path.exists():
                age_hours = (now - path.stat().st_mtime) / 3600
                if age_hours > 24:
                    print(f"[FEEDS] WARNING: {name} feed is {age_hours:.1f} hours old. Run with --update to refresh.")

        t0 = time.time()
        op_stats = self._load_openphish()
        uh_stats = self._load_urlhaus()

        self._load_time = time.time() - t0
        self._loaded = True
        self._stats = {
            "openphish_urls": op_stats,
            "urlhaus_urls": uh_stats["urls"],
            "total_urls": len(self.malicious_urls),
            "total_domains": len(self.malicious_domains),
            "total_ips": len(self.malicious_ips),
            "load_time_s": round(self._load_time, 2),
        }
        return self._stats

    def _load_openphish(self) -> int:
        """Load OpenPhish feed — one URL per line."""
        count = 0
        if not _OPENPHISH_PATH.exists():
            return 0
        try:
            for line in _OPENPHISH_PATH.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                self._index_url(line)
                count += 1
        except Exception as e:
            print(f"[FEEDS] WARNING: Failed to load OpenPhish: {e}")
        return count

    def _load_urlhaus(self) -> dict[str, int]:
        """Load URLhaus CSV feed — skip comment lines starting with #."""
        stats = {"urls": 0, "skipped": 0}
        if not _URLHAUS_PATH.exists():
            return stats
        try:
            raw = _URLHAUS_PATH.read_text(encoding="utf-8", errors="ignore").replace("\0", "")
            # strip comment lines
            lines = [l for l in raw.splitlines() if l.strip() and not l.startswith("#")]
            reader = csv.reader(io.StringIO("\n".join(lines)))
            for row in reader:
                try:
                    # CSV columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
                    if len(row) < 3:
                        stats["skipped"] += 1
                        continue
                    url = row[2].strip().strip('"')
                    if url:
                        self._index_url(url)
                        stats["urls"] += 1
                except Exception:
                    stats["skipped"] += 1
        except Exception as e:
            print(f"[FEEDS] WARNING: Failed to load URLhaus: {e}")
        return stats

    def _index_url(self, url: str):
        """Index a URL and extract its domain and IP for fast lookup."""
        url_lower = url.lower().strip()
        self.malicious_urls.add(url_lower)

        try:
            parsed = urlparse(url_lower if "://" in url_lower else f"http://{url_lower}")
            host = (parsed.hostname or "").strip()
            if not host:
                return

            # Check if host is an IP address
            if self._is_ip(host):
                self.malicious_ips.add(host)
            else:
                # Skip whitelisted shared infrastructure domains
                # (attackers abuse them but blocking the domain blocks legit traffic)
                base = ".".join(host.split(".")[-2:]) if len(host.split(".")) > 2 else host
                if host in WHITELISTED_DOMAINS or base in WHITELISTED_DOMAINS:
                    return  # URL is still indexed — only domain is skipped
                self.malicious_domains.add(host)
                if len(host.split(".")) > 2:
                    self.malicious_domains.add(base)
        except Exception:
            pass

    @staticmethod
    def _is_ip(host: str) -> bool:
        """Check if host is an IPv4 address."""
        parts = host.split(".")
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

    # ---- Query methods ----

    def check_url(self, url: str) -> bool:
        """Check if a URL is in the malicious feeds."""
        return url.lower().strip() in self.malicious_urls

    def check_domain(self, domain: str) -> bool:
        """Check if a domain is in the malicious feeds."""
        d = domain.lower().strip()
        if d in self.malicious_domains:
            return True
        # check base domain
        parts = d.split(".")
        if len(parts) > 2:
            base = ".".join(parts[-2:])
            return base in self.malicious_domains
        return False

    def check_ip(self, ip: str) -> bool:
        """Check if an IP is in the malicious feeds."""
        return ip.strip() in self.malicious_ips

    def check_all(self, urls: list[str] | None = None,
                   domains: list[str] | None = None,
                   ips: list[str] | None = None) -> dict:
        """Check multiple indicators at once. Returns matches found."""
        matches = {"urls": [], "domains": [], "ips": []}
        for u in (urls or []):
            if self.check_url(u):
                matches["urls"].append(u)
        for d in (domains or []):
            if self.check_domain(d):
                matches["domains"].append(d)
        for ip in (ips or []):
            if self.check_ip(ip):
                matches["ips"].append(ip)
        matches["total_matches"] = sum(len(v) for v in matches.values() if isinstance(v, list))
        return matches


# Module-level singleton — loaded once, reused across pipeline
_feeds: ThreatFeeds | None = None


def get_feeds() -> ThreatFeeds:
    """Get the singleton ThreatFeeds instance (loads on first call)."""
    global _feeds
    if _feeds is None:
        _feeds = ThreatFeeds()
        stats = _feeds.load()
        print(f"[FEEDS] Loaded: {stats['total_urls']} URLs, "
              f"{stats['total_domains']} domains, {stats['total_ips']} IPs "
              f"({stats['load_time_s']}s)")
    return _feeds


def update_feeds():
    """HIGH-03 Fix: Download fresh copies of the threat feeds."""
    from http_client import get_session
    session = get_session()
    
    print("[FEEDS] Updating OpenPhish feed...")
    try:
        resp = session.get(OPENPHISH_URL, timeout=30)
        if resp.status_code == 200:
            _OPENPHISH_PATH.write_bytes(resp.content)
            print("[FEEDS] OpenPhish updated.")
        else:
            print(f"[FEEDS] OpenPhish update failed: HTTP {resp.status_code}")
    except Exception as e:
        print(f"[FEEDS] OpenPhish update failed: {e}")

    print("[FEEDS] Updating URLhaus feed...")
    try:
        resp = session.get(URLHAUS_URL, timeout=30)
        if resp.status_code == 200:
            _URLHAUS_PATH.write_bytes(resp.content)
            print("[FEEDS] URLhaus updated.")
        else:
            print(f"[FEEDS] URLhaus update failed: HTTP {resp.status_code}")
    except Exception as e:
        print(f"[FEEDS] URLhaus update failed: {e}")


if __name__ == "__main__":
    import sys
    # Ensure src directory is in path for imports
    sys.path.insert(0, str(_SRC_DIR))
    
    if "--update" in sys.argv:
        update_feeds()
    else:
        print("Usage: python -m src.threat_feeds --update")
