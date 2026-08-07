"""validators.py — Input validation for all indicators before external API calls

Prevents:
  - Invalid IPs being sent to AbuseIPDB / OTX (CRIT-03)
  - Internal/private domains leaking to external APIs (CRIT-05)
  - Malformed hashes wasting API quota
  - SSRF-adjacent attacks via crafted From: headers

Every indicator extracted from attacker-controlled email headers MUST pass
through these validators before being sent to any external service.
"""
from __future__ import annotations

import ipaddress
import re


# ---------- IP validation ----------

def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid, non-private, non-reserved IPv4/IPv6 address.

    Returns True only for globally-routable addresses worth querying via APIs.
    """
    ip = (ip or "").strip()
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return (
            not addr.is_private
            and not addr.is_loopback
            and not addr.is_reserved
            and not addr.is_multicast
            and not addr.is_link_local
            and not addr.is_unspecified
        )
    except ValueError:
        return False


# "never auto-block shared infrastructure IPs (Gmail, Outlook relays)"
# These are well-known mail relay prefixes whose IPs frequently appear in OTX pulses
# but should NOT trigger escalation — they serve millions of legitimate senders.
_SHARED_INFRA_PREFIXES = (
    # Google / Gmail
    "74.125.", "209.85.", "172.217.", "142.250.", "108.177.",
    # Microsoft / Outlook / O365
    "40.92.", "40.93.", "40.94.", "40.107.", "52.100.", "52.101.",
    "104.47.",
    # Amazon SES
    "54.240.",
    # SendGrid
    "167.89.", "198.21.",
)


def is_shared_infrastructure_ip(ip: str) -> bool:
    """Check if an IP belongs to known shared mail infrastructure.

    These IPs must never trigger escalation or be auto-blocklisted.
    """
    ip = (ip or "").strip()
    return any(ip.startswith(p) for p in _SHARED_INFRA_PREFIXES)


def filter_valid_ips(ips: list[str]) -> list[str]:
    """Filter a list of IP strings to only valid, routable addresses."""
    return [ip.strip() for ip in ips if is_valid_ip(ip.strip())]


# ---------- Domain validation ----------

# RFC-compliant domain regex: labels separated by dots, each 1-63 chars,
# TLD must be at least 2 alphabetic characters (blocks raw IPs and .local)
_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

# Domains that must never be sent to external APIs
_BLOCKED_DOMAIN_SUFFIXES = {
    ".local", ".internal", ".localhost", ".localdomain",
    ".test", ".invalid", ".example", ".onion",
    ".corp", ".home", ".lan",
}


def is_valid_domain(domain: str) -> bool:
    """Check if a domain is valid and safe to query via external APIs.

    Blocks:
      - Empty / None values
      - Domains > 253 chars (RFC limit)
      - Internal suffixes (.local, .internal, .onion, etc.)
      - Malformed labels
    """
    domain = (domain or "").strip().lower()
    if not domain or len(domain) > 253:
        return False

    # Block internal/reserved TLDs
    for suffix in _BLOCKED_DOMAIN_SUFFIXES:
        if domain.endswith(suffix) or domain == suffix.lstrip("."):
            return False

    return bool(_DOMAIN_RE.match(domain))


# ---------- SHA-256 hash validation ----------

_SHA256_RE = re.compile(r'^[a-f0-9]{64}$')


def is_valid_sha256(sha256: str) -> bool:
    """Check if a string is a valid SHA-256 hex digest."""
    sha256 = (sha256 or "").strip().lower()
    return bool(_SHA256_RE.match(sha256))


# ---------- IPv4 + IPv6 extraction from text ----------

# IPv4 pattern (same as existing, but we validate after)
_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# Simplified IPv6 pattern — catches common formats, validated via ipaddress after
_IPV6_RE = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b'
    r'|'
    r'\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b'
    r'|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:\b'
)


def extract_ips_from_text(text: str) -> list[str]:
    """Extract and validate all IPv4 + IPv6 addresses from text.

    Returns only globally-routable addresses (filters out private/loopback/reserved).
    Fixes CRIT-03 (invalid IPs) and CRIT-07 (IPv6 ignored).
    """
    if not text:
        return []

    raw_v4 = _IPV4_RE.findall(text)
    raw_v6 = _IPV6_RE.findall(text)

    # Deduplicate and validate
    seen = set()
    valid = []
    for ip in raw_v4 + raw_v6:
        ip = ip.strip()
        if ip not in seen and is_valid_ip(ip):
            seen.add(ip)
            valid.append(ip)

    return valid
