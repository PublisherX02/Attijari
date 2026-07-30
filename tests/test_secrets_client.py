"""test_secrets_client.py — lazy singleton client, reachable against the
real local dev-mode Vault instance (this project's test convention for
lazy-singleton clients — no fakes, see test_redis_client.py). Requires
VAULT_ADDR/VAULT_ROLE_ID/VAULT_SECRET_ID in the environment.

The attijari-app AppRole policy is deliberately read-only (secret/attijari/*
"read" only — see scripts/vault_bootstrap.py), so secrets_client.get_client()
can never write. Tests that need to seed a secret use a separate root-token
hvac.Client (_seed_secret below), mirroring how a real operator/migration
script — not the app itself — would write secrets in production."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import hvac


def _seed_secret(path: str, secret: dict) -> None:
    root_client = hvac.Client(url=os.environ["VAULT_ADDR"], token=os.environ["VAULT_TOKEN"])
    root_client.secrets.kv.v2.create_or_update_secret(path=f"attijari/{path}", secret=secret)


def test_get_client_returns_working_singleton():
    import secrets_client
    c1 = secrets_client.get_client()
    c2 = secrets_client.get_client()
    assert c1 is c2
    assert c1.is_authenticated()


def test_read_secret_round_trip():
    import secrets_client
    _seed_secret("_smoke_test", {"hello": "world"})
    data = secrets_client.read_secret("_smoke_test")
    assert data["hello"] == "world"


def test_read_secret_missing_path_raises():
    import secrets_client
    import pytest
    with pytest.raises(RuntimeError):
        secrets_client.read_secret("_definitely_does_not_exist")


def test_read_secret_is_cached_within_ttl():
    import secrets_client
    _seed_secret("_cache_test", {"value": "first"})
    first = secrets_client.read_secret("_cache_test")
    # Update Vault directly (as root), bypassing the client's cache
    _seed_secret("_cache_test", {"value": "second"})
    cached = secrets_client.read_secret("_cache_test")
    assert first["value"] == "first"
    assert cached["value"] == "first"  # still cached, TTL not expired


def test_typed_getters_round_trip():
    import secrets_client

    _seed_secret("database", {"url": "postgresql://u:p@host/db"})
    _seed_secret("jwt", {"secret": "jwt-signing-key"})
    _seed_secret("vault_encryption_key", {"key": "fernet-key-value"})
    _seed_secret(
        "threat_intel",
        {"virustotal": "vt-key", "threatfox": "tf-key", "abuseipdb": "ab-key",
         "otx": "otx-key", "dnstwist": "{}"},
    )
    _seed_secret("smtp", {"user": "smtp-user", "password": "smtp-pass"})
    _seed_secret("webhooks", {"slack": "https://hooks.slack/x", "teams": "https://teams/y"})
    _seed_secret("cape", {"api_token": "cape-token", "vm_wrapper_token": "wrapper-token"})

    secrets_client._cache.clear()  # force a fresh read for this test

    assert secrets_client.get_database_url() == "postgresql://u:p@host/db"
    assert secrets_client.get_jwt_secret() == "jwt-signing-key"
    assert secrets_client.get_vault_encryption_key() == "fernet-key-value"
    assert secrets_client.get_api_key("virustotal") == "vt-key"
    assert secrets_client.get_api_key("threatfox") == "tf-key"
    assert secrets_client.get_api_key("abuseipdb") == "ab-key"
    assert secrets_client.get_api_key("otx") == "otx-key"
    assert secrets_client.get_api_key("dnstwist") == "{}"
    assert secrets_client.get_smtp_creds() == {"user": "smtp-user", "password": "smtp-pass"}
    assert secrets_client.get_webhook_url("slack") == "https://hooks.slack/x"
    assert secrets_client.get_webhook_url("teams") == "https://teams/y"
    assert secrets_client.get_cape_token("api_token") == "cape-token"
    assert secrets_client.get_cape_token("vm_wrapper_token") == "wrapper-token"
