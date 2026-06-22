"""dnstwist_check.py — Domain typosquatting detection via dnstwister.report API

Detects lookalike domains that could be used for phishing/spoofing.
Uses the dnstwister.report public API (configured via DNSTWIST_API_KEY JSON in .env).

CLAUDE.md context: dnstwist is for precomputed watchlist, not live per-email.
We check sender domains against known typosquats of attijaribank.com.tn and
other watched domains.
"""
from __future__ import annotations

import json
import os
import time

import requests  # for exception types only
from dotenv import load_dotenv
from http_client import get_session

load_dotenv()

# Domains we watch for typosquatting (the bank's real domains)
WATCHED_DOMAINS = [
    "attijaribank.com.tn",
    "attijariwafabank.com",
    "attijari.com.tn",
]


def _load_config() -> dict:
    """Load dnstwist config from DNSTWIST_API_KEY env var (JSON)."""
    raw = os.getenv("DNSTWIST_API_KEY", "")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"api_key": raw}  # treat as plain key if not JSON


def _domain_to_hex(domain: str) -> str:
    """Convert domain to hex encoding for dnstwister API."""
    return domain.encode("utf-8").hex()


def get_typosquats(domain: str, timeout: int = 15, retries: int = 2) -> dict:
    """Fetch fuzzing/typosquat results for a domain.

    Returns:
        dict with: source, domain, fuzzy_domains (list), count, error (optional)
    """
    config = _load_config()
    url_template = config.get("domain_fuzzer_url", "")

    if not url_template:
        # Try local dnstwist library as fallback
        return _local_dnstwist(domain)

    domain_hex = _domain_to_hex(domain)
    url = url_template.replace("{domain_as_hexadecimal}", domain_hex)

    attempt = 0
    while attempt <= retries:
        try:
            resp = get_session().get(url, timeout=timeout)
            if resp.status_code == 200:
                data = resp.json()
                fuzzy = data.get("fuzzy_domains", [])
                domains = []
                for entry in fuzzy:
                    d = entry.get("domain", "")
                    if d and d != domain:
                        domains.append({
                            "domain": d,
                            "hex": entry.get("domain-hex", ""),
                        })
                return {
                    "source": "dnstwist",
                    "domain": domain,
                    "fuzzy_domains": domains[:100],
                    "count": len(domains),
                }
            if resp.status_code == 429 and attempt < retries:
                time.sleep(3 + attempt * 5)
                attempt += 1
                continue
            return {"source": "dnstwist", "domain": domain,
                    "fuzzy_domains": [], "count": 0,
                    "error": f"HTTP {resp.status_code}"}
        except requests.RequestException as e:
            if attempt < retries:
                time.sleep(1 + attempt * 2)
                attempt += 1
                continue
            return {"source": "dnstwist", "domain": domain,
                    "fuzzy_domains": [], "count": 0, "error": str(e)}

    return {"source": "dnstwist", "domain": domain,
            "fuzzy_domains": [], "count": 0, "error": "retries_exhausted"}


def _local_dnstwist(domain: str) -> dict:
    """Fallback: use local dnstwist library if installed.

    Modern dnstwist (v20220228+) uses Fuzzer class.
    Older versions used DomainFuzz — we try both for compatibility.
    """
    try:
        # pyrefly: ignore [missing-import]
        import dnstwist

        # Modern API: dnstwist.Fuzzer (current versions)
        fuzzer_cls = getattr(dnstwist, "Fuzzer", None)
        if fuzzer_cls is None:
            # Legacy API: dnstwist.DomainFuzz (pre-2022)
            fuzzer_cls = getattr(dnstwist, "DomainFuzz", None)

        if fuzzer_cls is None:
            return {"source": "dnstwist", "domain": domain,
                    "fuzzy_domains": [], "count": 0,
                    "error": "dnstwist installed but no Fuzzer/DomainFuzz class found"}

        scanner = fuzzer_cls(domain)
        scanner.generate()

        # Extract results — handle both old and new result formats
        raw_domains = getattr(scanner, "domains", []) or []
        domains = []
        for d in raw_domains:
            name = d.get("domain", "") if isinstance(d, dict) else str(d)
            if name and name != domain:
                entry = {"domain": name}
                # Modern dnstwist includes fuzzer type
                if isinstance(d, dict) and d.get("fuzzer"):
                    entry["fuzzer"] = d["fuzzer"]
                domains.append(entry)

        return {
            "source": "dnstwist_local",
            "domain": domain,
            "fuzzy_domains": domains[:100],
            "count": len(domains),
        }
    except ImportError:
        return {"source": "dnstwist", "domain": domain,
                "fuzzy_domains": [], "count": 0,
                "error": "dnstwist not installed and no API configured"}
    except Exception as e:
        return {"source": "dnstwist", "domain": domain,
                "fuzzy_domains": [], "count": 0, "error": str(e)}


# Cached typosquat sets — built once at startup
_typosquat_cache: dict[str, set[str]] | None = None


def load_watchlist() -> dict[str, set[str]]:
    """Pre-compute typosquat sets for all watched domains.

    Returns dict: watched_domain -> set of known typosquats.
    """
    global _typosquat_cache
    if _typosquat_cache is not None:
        return _typosquat_cache

    _typosquat_cache = {}
    for wd in WATCHED_DOMAINS:
        print(f"[DNSTWIST] Loading typosquats for {wd}...")
        result = get_typosquats(wd)
        squats = {d["domain"] for d in result.get("fuzzy_domains", []) if d.get("domain")}
        _typosquat_cache[wd] = squats
        if result.get("error"):
            print(f"[DNSTWIST] {wd}: error — {result['error']}")
        else:
            print(f"[DNSTWIST] {wd}: {len(squats)} typosquats loaded")

    return _typosquat_cache


def is_typosquat(domain: str) -> dict:
    """Check if a domain is a known typosquat of a watched domain.

    Returns:
        dict with: is_typosquat (bool), impersonates (str or None)
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return {"is_typosquat": False, "impersonates": None}

    watchlist = load_watchlist()
    for watched, squats in watchlist.items():
        if domain in squats:
            return {"is_typosquat": True, "impersonates": watched}

    return {"is_typosquat": False, "impersonates": None}
