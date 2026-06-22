"""alienvault_otx.py — AlienVault OTX threat intelligence

Queries OTX for contextual threat intel on IPs, domains, and file hashes.
Provides campaign context, malware family info, and pulse references.

Only sends metadata (IP, domain, hash) — NEVER email content.

Works without an API key (public API), but rate limits are stricter.
Set OTX_API_KEY in .env for higher limits.
"""
from __future__ import annotations

import os
import time

import requests  # for exception types only
from dotenv import load_dotenv
from http_client import get_session

load_dotenv()

BASE_URL = "https://otx.alienvault.com/api/v1"


def _otx_headers() -> dict:
    key = os.getenv("OTX_API_KEY")
    headers = {"Accept": "application/json"}
    if key:
        headers["X-OTX-API-KEY"] = key
    return headers


def _otx_get(endpoint: str, retries: int = 2, timeout: int = 10) -> dict | None:
    """Generic OTX GET with retry logic."""
    url = f"{BASE_URL}/{endpoint}"
    attempt = 0
    while attempt <= retries:
        try:
            resp = get_session().get(url, headers=_otx_headers(), timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 404:
                return None  # not found = clean
            if resp.status_code == 429 and attempt < retries:
                time.sleep(2 + attempt * 3)
                attempt += 1
                continue
            if 500 <= resp.status_code < 600 and attempt < retries:
                time.sleep(1 + attempt * 2)
                attempt += 1
                continue
            return {"error": f"HTTP {resp.status_code}"}
        except requests.RequestException as e:
            if attempt < retries:
                time.sleep(1 + attempt * 2)
                attempt += 1
                continue
            return {"error": str(e)}
    return {"error": "retries_exhausted"}


def check_ip(ip: str) -> dict:
    """Check an IP against OTX for threat intel."""
    ip = (ip or "").strip()
    if not ip:
        return {"source": "otx", "indicator": ip, "type": "ip", "found": False, "error": "empty"}

    result = {"source": "otx", "indicator": ip, "type": "ip", "found": False}

    # General info
    data = _otx_get(f"indicators/IPv4/{ip}/general")
    if data is None:
        return result
    if isinstance(data, dict) and data.get("error"):
        result["error"] = data["error"]
        return result

    pulse_count = data.get("pulse_info", {}).get("count", 0)
    result["found"] = pulse_count > 0
    result["pulse_count"] = pulse_count
    result["reputation"] = data.get("reputation", 0)
    result["country"] = data.get("country_code")
    result["asn"] = data.get("asn")

    if pulse_count > 0:
        pulses = data.get("pulse_info", {}).get("pulses", [])
        result["pulse_names"] = [p.get("name", "") for p in pulses[:5]]
        result["tags"] = list(set(
            tag for p in pulses[:10] for tag in (p.get("tags") or [])
        ))[:10]
        result["malware_families"] = list(set(
            fam.get("display_name", "")
            for p in pulses[:10]
            for fam in (p.get("malware_families") or [])
        ))[:5]

    return result


def check_domain(domain: str) -> dict:
    """Check a domain against OTX for threat intel."""
    domain = (domain or "").strip().lower()
    if not domain:
        return {"source": "otx", "indicator": domain, "type": "domain", "found": False, "error": "empty"}

    result = {"source": "otx", "indicator": domain, "type": "domain", "found": False}

    data = _otx_get(f"indicators/domain/{domain}/general")
    if data is None:
        return result
    if isinstance(data, dict) and data.get("error"):
        result["error"] = data["error"]
        return result

    pulse_count = data.get("pulse_info", {}).get("count", 0)
    result["found"] = pulse_count > 0
    result["pulse_count"] = pulse_count

    if pulse_count > 0:
        pulses = data.get("pulse_info", {}).get("pulses", [])
        result["pulse_names"] = [p.get("name", "") for p in pulses[:5]]
        result["tags"] = list(set(
            tag for p in pulses[:10] for tag in (p.get("tags") or [])
        ))[:10]

    # WHOIS info (bonus)
    whois = data.get("whois")
    if whois:
        result["registrar"] = whois.get("registrar")
        result["creation_date"] = whois.get("creation_date")

    return result


def check_hash(sha256: str) -> dict:
    """Check a file hash against OTX. SHA-256 only, NEVER upload files."""
    sha256 = (sha256 or "").strip().lower()
    if not sha256 or len(sha256) != 64:
        return {"source": "otx", "indicator": sha256, "type": "hash", "found": False, "error": "invalid_hash"}

    result = {"source": "otx", "indicator": sha256, "type": "hash", "found": False}

    data = _otx_get(f"indicators/file/{sha256}/general")
    if data is None:
        return result
    if isinstance(data, dict) and data.get("error"):
        result["error"] = data["error"]
        return result

    pulse_count = data.get("pulse_info", {}).get("count", 0)
    result["found"] = pulse_count > 0
    result["pulse_count"] = pulse_count

    # File analysis info
    analysis = data.get("analysis")
    if isinstance(analysis, dict):
        info = analysis.get("analysis", {}).get("info", {})
        result["file_type"] = info.get("file_type") or info.get("file_class")
        plugins = analysis.get("analysis", {}).get("plugins", {})
        if isinstance(plugins, dict):
            av = plugins.get("avast", {}) or plugins.get("clamav", {})
            if av.get("results", {}).get("detection"):
                result["av_detection"] = av["results"]["detection"]

    if pulse_count > 0:
        pulses = data.get("pulse_info", {}).get("pulses", [])
        result["pulse_names"] = [p.get("name", "") for p in pulses[:5]]
        result["malware_families"] = list(set(
            fam.get("display_name", "")
            for p in pulses[:10]
            for fam in (p.get("malware_families") or [])
        ))[:5]

    return result
