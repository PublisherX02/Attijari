import os
import time

import requests  # for exception types only
from dotenv import load_dotenv
from http_client import get_session

load_dotenv()

BASE_URL = "https://threatfox-api.abuse.ch/api/v1/"


def _resolve_key(api_key: str | None) -> str:
    from secrets_client import get_api_key
    return api_key or get_api_key("threatfox")


def check_threatfox(indicator: str, indicator_type: str = "hash", api_key: str | None = None, retries: int = 2, timeout: int = 10) -> dict:
    """
    Query ThreatFox Community API using correct headers and payloads.

    indicator_type: 'hash' | 'domain' | 'ip' | 'url'
    Returns a dict with keys: source, indicator, indicator_type, found (bool), status_code, raw, error (optional)
    """
    from api_cache import api_cache
    cache_key = f"threatfox_{indicator_type}_{indicator}"
    cached = api_cache.get_cached(cache_key)
    if cached:
        return cached
    api_cache.enforce_rate_limit("threatfox", 10)

    if not indicator:
        return {"source": "threatfox", "indicator": indicator, "indicator_type": indicator_type, "found": False, "error": "empty indicator"}

    key = _resolve_key(api_key)
    headers = {"User-Agent": "attijari-ai/1.0"}
    if key:
        headers["Auth-Key"] = key

    # build payload according to ThreatFox docs
    if indicator_type == "hash":
        payload = {"query": "search_hash", "hash": indicator}
    else:
        # domain, ip, url and generic searches use search_ioc
        payload = {"query": "search_ioc", "search_term": indicator, "exact_match": True}

    attempt = 0
    while attempt <= retries:
        try:
            resp = get_session().post(BASE_URL, json=payload, headers=headers, timeout=timeout)
            status = resp.status_code
            text = resp.text
            # try parse json
            try:
                data = resp.json()
            except Exception:
                data = {"text": text}

            # Non-200: decide to retry on 5xx, otherwise return error
            if status != 200:
                if 500 <= status < 600 and attempt < retries:
                    backoff = 1 + attempt * 2
                    time.sleep(backoff)
                    attempt += 1
                    continue
                return {
                    "source": "threatfox",
                    "indicator": indicator,
                    "indicator_type": indicator_type,
                    "found": False,
                    "status_code": status,
                    "raw": data,
                    "error": f"HTTP {status}: {text[:200]}",
                }

            # status 200 -> inspect payload
            found = False
            if isinstance(data, dict):
                # many ThreatFox endpoints return {'query_status':'ok','data': [...]}
                if data.get("query_status") == "ok":
                    d = data.get("data")
                    if isinstance(d, list) and len(d) > 0:
                        found = True
                # some endpoints may return 'data' as dict with keys
                elif data.get("data") and isinstance(data.get("data"), dict) and len(data.get("data")) > 0:
                    found = True

            res = {
                "source": "threatfox",
                "indicator": indicator,
                "indicator_type": indicator_type,
                "found": found,
                "status_code": status,
                "raw": data,
            }
            api_cache.set_cache(cache_key, res, 86400)
            return res

        except requests.exceptions.RequestException as e:
            # transient network error: retry
            if attempt < retries:
                backoff = 1 + attempt * 2
                time.sleep(backoff)
                attempt += 1
                continue
            return {
                "source": "threatfox",
                "indicator": indicator,
                "indicator_type": indicator_type,
                "found": False,
                "error": str(e),
            }

    # fallback
    return {"source": "threatfox", "indicator": indicator, "indicator_type": indicator_type, "found": False, "error": "retries exhausted"}