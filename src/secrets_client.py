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
    global _client
    if _client is None:
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
    """Like read_secret, but a missing path means "not configured" (empty
    dict) rather than a hard failure. Only for optional integrations
    (threat-intel keys, SMTP/webhooks, CAPE tokens) that were always
    tolerant of an unset env var pre-Vault — NOT for must-have secrets
    (database, jwt, vault_encryption_key), which still fail closed via
    read_secret()."""
    try:
        return read_secret(path)
    except RuntimeError:
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
