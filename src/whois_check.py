"""whois_check.py — Domain age and registration lookup via RDAP/whoisit

Checks domain registration date to detect newly registered domains.
CLAUDE.md: "Newly registered domain = strong signal"

Only sends the domain name — NEVER email content.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

try:
    import whoisit
    _HAS_WHOISIT = True
except ImportError:
    _HAS_WHOISIT = False

# Domains younger than this are suspicious
NEW_DOMAIN_DAYS = 30


def check_domain_age(domain: str, timeout: int = 10) -> dict:
    """Look up domain registration date via RDAP.

    Returns:
        dict with: source, domain, registered_date, domain_age_days,
                   is_new_domain, registrar, error (optional)
    """
    domain = (domain or "").strip().lower()
    if not domain:
        return {"source": "whois", "domain": domain, "is_new_domain": False, "error": "empty_domain"}

    if not _HAS_WHOISIT:
        return {"source": "whois", "domain": domain, "is_new_domain": False, "error": "whoisit_not_installed"}

    # Strip to root domain — subdomains don't have their own WHOIS records
    # e.g. m.learn.coursera.org → coursera.org, info.glovoapp.com → glovoapp.com
    original_domain = domain
    parts = domain.split(".")
    # Handle common multi-part TLDs: .com.tn, .co.uk, .com.au etc.
    _multi_tlds = {"com.tn", "com.au", "co.uk", "org.uk", "com.br", "co.jp", "com.sa"}
    if len(parts) >= 3 and ".".join(parts[-2:]) in _multi_tlds:
        domain = ".".join(parts[-3:])  # e.g. imaniabank.com.tn
    elif len(parts) > 2:
        domain = ".".join(parts[-2:])  # e.g. coursera.org

    try:
        # Bootstrap RDAP servers with overrides for non-standard TLDs (.tn, .co, etc.)
        try:
            whoisit.bootstrap(overrides=True)
        except Exception:
            try:
                whoisit.bootstrap()
            except Exception:
                pass

        data = whoisit.domain(domain)

        if not data:
            return {"source": "whois", "domain": domain, "is_new_domain": False,
                    "error": "no_rdap_data"}

        # Extract registration date
        reg_date = data.get("registration_date")
        expiry_date = data.get("expiration_date")
        registrar = None
        entities = data.get("entities", {})
        if isinstance(entities, dict):
            reg_entity = entities.get("registrar", [])
            if reg_entity and isinstance(reg_entity, list):
                registrar = reg_entity[0] if reg_entity else None

        result = {
            "source": "whois",
            "domain": domain,
            "registered_date": reg_date.isoformat() if isinstance(reg_date, datetime) else str(reg_date) if reg_date else None,
            "expiry_date": expiry_date.isoformat() if isinstance(expiry_date, datetime) else str(expiry_date) if expiry_date else None,
            "registrar": registrar,
            "is_new_domain": False,
            "domain_age_days": None,
        }

        # Calculate age
        if isinstance(reg_date, datetime):
            now = datetime.now(timezone.utc)
            if reg_date.tzinfo is None:
                reg_date = reg_date.replace(tzinfo=timezone.utc)
            age_days = (now - reg_date).days
            result["domain_age_days"] = age_days
            result["is_new_domain"] = age_days < NEW_DOMAIN_DAYS

        return result

    except Exception as e:
        return {"source": "whois", "domain": domain, "is_new_domain": False, "error": str(e)}
