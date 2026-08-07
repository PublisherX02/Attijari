"""Sandboxed IOC extraction."""
import json
import sys

try:
    from ioc_finder import ioc_finder

    text = open("/work/input", "r", encoding="utf-8", errors="ignore").read()
    if not text.strip():
        json.dump({"tool": "ioc_finder", "status": "ok", "iocs": {}}, sys.stdout)
        sys.exit(0)

    # ioc-finder==9.4.1 has no unified parse_iocs() -- only individual
    # parse_<type>() functions. Confirmed 2026-08-05, same fix as
    # extraction.py's _local_iocs.
    parsers = {
        "ipv4s": "parse_ipv4_addresses",
        "ipv6s": "parse_ipv6_addresses",
        "domains": "parse_domain_names",
        "urls": "parse_urls",
        "email_addresses": "parse_email_addresses",
        "md5s": "parse_md5s",
        "sha256s": "parse_sha256s",
        "sha1s": "parse_sha1s",
        "bitcoin_addresses": "parse_bitcoin_addresses",
    }
    filtered = {}
    for key, fn_name in parsers.items():
        vals = getattr(ioc_finder, fn_name)(text)
        if vals:
            filtered[key] = vals[:50]

    json.dump({"tool": "ioc_finder", "status": "ok", "iocs": filtered}, sys.stdout)
except Exception as e:
    json.dump({"tool": "ioc_finder", "status": "error", "error": str(e)}, sys.stdout)
