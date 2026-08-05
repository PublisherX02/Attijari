"""secrets_client.py — HashiCorp Vault-backed secrets access.

Not to be confused with src/vault.py, which is a different system (Fernet
at-rest encryption of quarantined emails/TOTP secrets). This module is the
client for HashiCorp Vault, the secrets manager that (as of this module)
stores the Fernet key vault.py uses, among other secrets.

Fail-closed: any failure to authenticate or read a required secret raises
immediately. There is no fallback to a missing/default value.
"""
from __future__ import annotations

import os
import time

import hvac

_client: "hvac.Client | None" = None
_cache: dict[str, tuple[float, dict]] = {}
_CACHE_TTL_SECONDS = 300


def get_client() -> hvac.Client:
    """Returns a cached, authenticated Vault client -- re-logging in
    whenever the cached token is no longer valid.

    The bootstrap AppRole issues tokens with a 15-minute TTL
    (scripts/vault_bootstrap.py's token_ttl="15m"). Caching the client
    forever after its first login (the original behavior here) meant every
    long-running process (the FastAPI app, the RQ worker -- both meant to
    run for hours) silently lost Vault access 15 minutes after startup:
    optional secrets (threat-intel/SMTP/webhook/CAPE keys) quietly
    degraded to "not configured" via _read_optional_secret's broad except,
    and any must-have read attempted mid-process (e.g.
    database._migrate_encrypt_totp_secrets(), which calls
    get_vault_encryption_key() fresh on every pipeline run, not just at
    startup) failed outright with "permission denied"/"invalid token" --
    confirmed live, not theoretical. is_authenticated() calls Vault's own
    token-lookup-self endpoint, so an expired/revoked token is detected
    and transparently replaced before any caller sees a failure.
    """
    global _client
    if _client is None or not _client.is_authenticated():
        vault_addr = os.getenv("VAULT_ADDR")
        role_id = os.getenv("VAULT_ROLE_ID")
        secret_id = os.getenv("VAULT_SECRET_ID")
        if not vault_addr or not role_id or not secret_id:
            raise RuntimeError(
                "VAULT_ADDR, VAULT_ROLE_ID, and VAULT_SECRET_ID must all be set. "
                "Run scripts/vault_bootstrap.py against your Vault server to obtain "
                "VAULT_ROLE_ID/VAULT_SECRET_ID."
            )
        client = hvac.Client(url=vault_addr)
        client.auth.approle.login(role_id=role_id, secret_id=secret_id)
        if not client.is_authenticated():
            raise RuntimeError(f"AppRole login to Vault at {vault_addr} failed.")
        _client = client
    return _client


def read_secret(path: str) -> dict:
    """Read secret/attijari/<path> (KV v2), cached for _CACHE_TTL_SECONDS."""
    now = time.monotonic()
    cached = _cache.get(path)
    if cached is not None and (now - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]

    client = get_client()
    try:
        response = client.secrets.kv.v2.read_secret_version(
            path=f"attijari/{path}", mount_point="secret", raise_on_deleted_version=True
        )
    except hvac.exceptions.InvalidPath as exc:
        raise RuntimeError(f"Vault path secret/attijari/{path} does not exist.") from exc

    data = response["data"]["data"]
    _cache[path] = (now, data)
    return data


def _read_optional_secret(path: str) -> dict:
    """Like read_secret, but a missing path OR any failure to reach/auth
    against Vault means "not configured" (empty dict) rather than a hard
    failure. Only for optional integrations (threat-intel keys,
    SMTP/webhooks, CAPE tokens) that were always tolerant of an unset env
    var pre-Vault — NOT for must-have secrets (database, jwt,
    vault_encryption_key), which still fail closed via read_secret().

    Catches Exception broadly, not just RuntimeError: get_client()/hvac can
    fail in several ways that aren't RuntimeError — connection refused
    (requests.exceptions.ConnectionError), a hung/unreachable server
    (requests.exceptions.Timeout), or a stale/revoked AppRole secret_id
    (hvac.exceptions.InvalidRequest/Forbidden). An earlier version of this
    function only caught RuntimeError, then was narrowed to also catch
    ConnectionError specifically — but that still left the AppRole-auth
    failure mode uncaught, which crashed import of any module (e.g.
    detonation_config.py) reading an optional secret at module load time.
    Since every caller here is explicitly optional, any failure to reach a
    real secret value is equivalent to "not configured"."""
    try:
        return read_secret(path)
    except Exception:
        return {}


def get_database_url() -> str:
    return read_secret("database")["url"]


def get_jwt_secret() -> str:
    return read_secret("jwt")["secret"]


def get_vault_encryption_key() -> str:
    return read_secret("vault_encryption_key")["key"]


def get_api_key(name: str) -> str:
    """name is one of: virustotal, threatfox, abuseipdb, otx, dnstwist."""
    return _read_optional_secret("threat_intel").get(name, "")


def get_smtp_creds() -> dict:
    """Returns {"user": ..., "password": ...}."""
    data = _read_optional_secret("smtp")
    return {"user": data.get("user", ""), "password": data.get("password", "")}


def get_webhook_url(name: str) -> str:
    """name is one of: slack, teams."""
    return _read_optional_secret("webhooks").get(name, "")


def get_cape_token(name: str) -> str:
    """name is one of: api_token, vm_wrapper_token."""
    return _read_optional_secret("cape").get(name, "")
