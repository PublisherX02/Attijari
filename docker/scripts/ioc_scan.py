"""Sandboxed IOC extraction."""
import json
import sys

try:
    from ioc_finder import ioc_finder

    text = open("/work/input", "r", encoding="utf-8", errors="ignore").read()
    if not text.strip():
        json.dump({"tool": "ioc_finder", "status": "ok", "iocs": {}}, sys.stdout)
        sys.exit(0)

    iocs = ioc_finder.parse_iocs(text)
    filtered = {}
    for key in ("ipv4s", "ipv6s", "domains", "urls", "email_addresses",
                 "md5s", "sha256s", "sha1s", "bitcoin_addresses"):
        vals = iocs.get(key, [])
        if vals:
            filtered[key] = vals[:50]

    json.dump({"tool": "ioc_finder", "status": "ok", "iocs": filtered}, sys.stdout)
except Exception as e:
    json.dump({"tool": "ioc_finder", "status": "error", "error": str(e)}, sys.stdout)
