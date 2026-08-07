"""dkim_verify.py — DKIM and SPF/DMARC email authentication

Verifies cryptographic email signatures using:
  - dkimpy: DKIM signature verification
  - checkdmarc: SPF and DMARC policy lookup

These are LOCAL checks against DNS — no email content is sent externally.
Only the signing domain is queried via DNS.

Rule: LLM can NEVER emit "accepter" if SPF/DKIM fails.
"""
from __future__ import annotations

import re

try:
    import dkim
    _HAS_DKIM = True
except ImportError:
    _HAS_DKIM = False

try:
    import checkdmarc
    _HAS_CHECKDMARC = True
except ImportError:
    _HAS_CHECKDMARC = False


def verify_dkim(raw_email: bytes) -> dict:
    """Verify DKIM signature on a raw email.

    Args:
        raw_email: raw RFC822 email bytes

    Returns:
        dict with: tool, status, valid, details, error (optional)
    """
    if not _HAS_DKIM:
        return {"tool": "dkim", "status": "unavailable"}

    try:
        valid = dkim.verify(raw_email)
        return {
            "tool": "dkim",
            "status": "ok",
            "valid": bool(valid),
            "details": "DKIM signature valid" if valid else "DKIM signature FAILED",
        }
    except dkim.DKIMException as e:
        return {
            "tool": "dkim",
            "status": "ok",
            "valid": False,
            "details": f"DKIM verification error: {e}",
        }
    except Exception as e:
        return {"tool": "dkim", "status": "error", "valid": False, "error": str(e)}


def check_spf_dmarc(domain: str) -> dict:
    """Look up SPF and DMARC records for a domain.

    Args:
        domain: sender domain to check

    Returns:
        dict with: tool, status, spf, dmarc, error (optional)
    """
    if not _HAS_CHECKDMARC:
        return {"tool": "checkdmarc", "status": "unavailable"}

    if not domain or not domain.strip():
        return {"tool": "checkdmarc", "status": "error", "error": "empty_domain"}

    result = {
        "tool": "checkdmarc",
        "status": "ok",
        "domain": domain,
        "spf": None,
        "dmarc": None,
    }

    try:
        dns_results = checkdmarc.check_domains([domain])
        if isinstance(dns_results, list) and dns_results:
            d = dns_results[0]
        elif isinstance(dns_results, dict):
            d = dns_results
        else:
            d = {}

        # SPF
        spf_data = d.get("spf", {})
        if isinstance(spf_data, dict):
            result["spf"] = {
                "record": spf_data.get("record"),
                "valid": spf_data.get("valid", False),
                "warnings": spf_data.get("warnings", []),
            }

        # DMARC
        dmarc_data = d.get("dmarc", {})
        if isinstance(dmarc_data, dict):
            record = dmarc_data.get("record")
            tags = dmarc_data.get("tags", {})
            policy = tags.get("p", {}).get("value") if isinstance(tags, dict) else None
            result["dmarc"] = {
                "record": record,
                "valid": dmarc_data.get("valid", False),
                "policy": policy,
                "warnings": dmarc_data.get("warnings", []),
            }

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result


def parse_authentication_results(auth_header: str | None) -> dict:
    """Parse the Authentication-Results header for SPF/DKIM/DMARC verdicts.

    This is a fast check using the MTA's own verification results
    (already computed by the receiving server). Complements live DKIM verify.
    """
    if not auth_header:
        return {"spf": "none", "dkim": "none", "dmarc": "none"}

    header = str(auth_header).lower()
    result = {"spf": "none", "dkim": "none", "dmarc": "none"}

    # SPF
    spf_match = re.search(r'spf\s*=\s*(pass|fail|softfail|neutral|temperror|permerror|none)', header)
    if spf_match:
        result["spf"] = spf_match.group(1)

    # DKIM
    dkim_match = re.search(r'dkim\s*=\s*(pass|fail|temperror|permerror|none)', header)
    if dkim_match:
        result["dkim"] = dkim_match.group(1)

    # DMARC
    dmarc_match = re.search(r'dmarc\s*=\s*(pass|fail|bestguesspass|temperror|permerror|none)', header)
    if dmarc_match:
        result["dmarc"] = dmarc_match.group(1)

    return result


def verify_all(raw_email: bytes, sender_domain: str | None = None,
               auth_header: str | None = None) -> dict:
    """Run all authentication checks and return unified result.

    Returns:
        dict with: dkim_result, spf_dmarc_result, auth_header_parsed,
                   any_failure (bool), summary (str)
    """
    dkim_result = verify_dkim(raw_email)
    spf_dmarc_result = check_spf_dmarc(sender_domain) if sender_domain else {
        "tool": "checkdmarc", "status": "skipped", "error": "no_sender_domain"}
    auth_parsed = parse_authentication_results(auth_header)

    # Determine if any authentication failed
    failures = []

    if dkim_result.get("status") == "ok" and not dkim_result.get("valid"):
        failures.append("DKIM_FAIL")
    if auth_parsed.get("dkim") == "fail":
        failures.append("DKIM_HEADER_FAIL")
    if auth_parsed.get("spf") in ("fail", "softfail"):
        failures.append(f"SPF_{auth_parsed['spf'].upper()}")
    if auth_parsed.get("dmarc") == "fail":
        failures.append("DMARC_FAIL")

    spf = spf_dmarc_result.get("spf")
    if isinstance(spf, dict) and not spf.get("valid"):
        failures.append("SPF_RECORD_INVALID")
    dmarc = spf_dmarc_result.get("dmarc")
    if isinstance(dmarc, dict) and not dmarc.get("valid"):
        failures.append("DMARC_RECORD_INVALID")

    return {
        "dkim": dkim_result,
        "spf_dmarc": spf_dmarc_result,
        "auth_header": auth_parsed,
        "any_failure": len(failures) > 0,
        "failures": failures,
        "summary": ", ".join(failures) if failures else "all_pass",
    }
