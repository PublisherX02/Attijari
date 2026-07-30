"""abuseipdb.py — AbuseIPDB IP reputation checker

Queries the /check endpoint for IP abuse confidence scores.
Only sends IP addresses — NEVER email content (CLAUDE.md compliance).

Usage:
    from abuseipdb import check_ip
    result = check_ip("185.220.101.1")
    # {"source": "abuseipdb", "ip": "...", "abuse_score": 100, "is_malicious": True, ...}
"""
from __future__ import annotations

import os
import time

import requests  # for exception types only
from dotenv import load_dotenv
from http_client import get_session

load_dotenv()

BASE_URL = "https://api.abuseipdb.com/api/v2/check"

# IPs above this score are considered malicious
ABUSE_THRESHOLD = 75

# Shared infrastructure IPs — never flag these (CLAUDE.md rule)
# Gmail, Outlook, major CDN relays
WHITELISTED_RANGES = {
    "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
    "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.",
}


def _is_private_ip(ip: str) -> bool:
    """Skip private/loopback IPs — they have no AbuseIPDB data."""
    return any(ip.startswith(prefix) for prefix in WHITELISTED_RANGES)


def _resolve_key(api_key: str | None) -> str:
    from secrets_client import get_api_key
    return api_key or get_api_key("abuseipdb")


def check_ip(ip: str, api_key: str | None = None,
             max_age_days: int = 90, retries: int = 2,
             timeout: int = 10) -> dict:
    """Query AbuseIPDB /check for an IP's abuse confidence score.

    Args:
        ip: IPv4 address to check
        api_key: override key (defaults to ABUSEIPDB_API_KEY env var)
        max_age_days: how far back to look for reports (default 90)
        retries: number of retry attempts on failure
        timeout: HTTP timeout in seconds

    Returns:
        dict with keys: source, ip, abuse_score, is_malicious, total_reports,
                        country_code, isp, domain, usage_type, error (optional)
    """
    ip = (ip or "").strip()
    if not ip:
        return {"source": "abuseipdb", "ip": ip, "abuse_score": 0,
                "is_malicious": False, "error": "empty_ip"}

    if _is_private_ip(ip):
        return {"source": "abuseipdb", "ip": ip, "abuse_score": 0,
                "is_malicious": False, "skipped": "private_ip"}

    key = _resolve_key(api_key)
    if not key:
        return {"source": "abuseipdb", "ip": ip, "abuse_score": 0,
                "is_malicious": False, "error": "no_api_key"}

    headers = {
        "Key": key,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": str(max_age_days),
        "verbose": "",
    }

    attempt = 0
    while attempt <= retries:
        try:
            resp = get_session().get(BASE_URL, headers=headers, params=params, timeout=timeout)
            status = resp.status_code

            if status == 429:
                # rate limited — back off and retry
                if attempt < retries:
                    backoff = 2 + attempt * 3
                    time.sleep(backoff)
                    attempt += 1
                    continue
                return {"source": "abuseipdb", "ip": ip, "abuse_score": 0,
                        "is_malicious": False, "error": "rate_limited"}

            if status != 200:
                if 500 <= status < 600 and attempt < retries:
                    time.sleep(1 + attempt * 2)
                    attempt += 1
                    continue
                return {"source": "abuseipdb", "ip": ip, "abuse_score": 0,
                        "is_malicious": False, "error": f"HTTP {status}",
                        "status_code": status}

            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)

            return {
                "source": "abuseipdb",
                "ip": ip,
                "abuse_score": score,
                "is_malicious": score >= ABUSE_THRESHOLD,
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "usage_type": data.get("usageType"),
                "is_tor": data.get("isTor", False),
                "last_reported": data.get("lastReportedAt"),
            }

        except requests.RequestException as e:
            if attempt < retries:
                time.sleep(1 + attempt * 2)
                attempt += 1
                continue
            return {"source": "abuseipdb", "ip": ip, "abuse_score": 0,
                    "is_malicious": False, "error": str(e)}

    return {"source": "abuseipdb", "ip": ip, "abuse_score": 0,
            "is_malicious": False, "error": "retries_exhausted"}


def check_ips(ips: list[str], api_key: str | None = None) -> list[dict]:
    """Check multiple IPs. Deduplicates and skips private IPs."""
    seen = set()
    results = []
    for ip in ips:
        ip = (ip or "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        results.append(check_ip(ip, api_key=api_key))
    return results
