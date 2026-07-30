"""virustotal.py — VirusTotal hash reputation checker

CRITICAL COMPLIANCE RULE (from CLAUDE.md):
  - Hash lookups: YES — sending a SHA-256 reveals nothing about content
  - File uploads: ABSOLUTELY NOT — uploading exposes confidential data
  - This is a compliance incident, not a bug

Only SHA-256 hashes are sent. NEVER file content, names, or email body.
"""
from __future__ import annotations

import os
import time

import requests  # for exception types only
from dotenv import load_dotenv
from http_client import get_session, VT_RATE_LIMITER

load_dotenv()

BASE_URL = "https://www.virustotal.com/api/v3/files"

# If this many engines flag a hash, consider it malicious
DETECTION_THRESHOLD = 3


def _resolve_key(api_key: str | None) -> str:
    from secrets_client import get_api_key
    return api_key or get_api_key("virustotal")


def check_hash(sha256: str, api_key: str | None = None,
               retries: int = 2, timeout: int = 15) -> dict:
    """Query VirusTotal for a file hash reputation.

    Only sends SHA-256. NEVER uploads files.

    Returns:
        dict with: source, sha256, detected, detection_count, total_engines,
                   malware_names, error (optional)
    """
    sha256 = (sha256 or "").strip().lower()
    if not sha256 or len(sha256) != 64:
        return {"source": "virustotal", "sha256": sha256,
                "detected": False, "error": "invalid_hash"}

    from api_cache import api_cache
    cache_key = f"vt_{sha256}"
    cached = api_cache.get_cached(cache_key)
    if cached:
        return cached

    key = _resolve_key(api_key)
    if not key:
        return {"source": "virustotal", "sha256": sha256,
                "detected": False, "error": "no_api_key"}

    headers = {"x-apikey": key}
    url = f"{BASE_URL}/{sha256}"

    attempt = 0
    while attempt <= retries:
        try:
            VT_RATE_LIMITER.wait()
            resp = get_session().get(url, headers=headers, timeout=timeout)
            status = resp.status_code

            # 404 = hash not in VT database (not seen before, not necessarily clean)
            if status == 404:
                return {"source": "virustotal", "sha256": sha256,
                        "detected": False, "detection_count": 0,
                        "note": "hash_not_found_in_vt"}

            # 429 = rate limited
            if status == 429:
                if attempt < retries:
                    time.sleep(15 + attempt * 15)  # VT free tier: 4 req/min
                    attempt += 1
                    continue
                return {"source": "virustotal", "sha256": sha256,
                        "detected": False, "error": "rate_limited"}

            if status != 200:
                if 500 <= status < 600 and attempt < retries:
                    time.sleep(2 + attempt * 3)
                    attempt += 1
                    continue
                return {"source": "virustotal", "sha256": sha256,
                        "detected": False, "error": f"HTTP {status}",
                        "status_code": status}

            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            detection_count = malicious + suspicious

            # Extract top malware names from engine results
            malware_names = []
            results = data.get("last_analysis_results", {})
            for engine, info in results.items():
                if isinstance(info, dict) and info.get("category") in ("malicious", "suspicious"):
                    name = info.get("result")
                    if name and name not in malware_names:
                        malware_names.append(name)
                    if len(malware_names) >= 5:
                        break

            res = {
                "source": "virustotal",
                "sha256": sha256,
                "detected": detection_count >= DETECTION_THRESHOLD,
                "detection_count": detection_count,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_engines": total,
                "malware_names": malware_names,
                "meaningful_name": data.get("meaningful_name"),
                "type_description": data.get("type_description"),
            }
            api_cache.set_cache(cache_key, res, 86400)
            return res

        except requests.RequestException as e:
            if attempt < retries:
                time.sleep(2 + attempt * 3)
                attempt += 1
                continue
            return {"source": "virustotal", "sha256": sha256,
                    "detected": False, "error": str(e)}

    return {"source": "virustotal", "sha256": sha256,
            "detected": False, "error": "retries_exhausted"}
