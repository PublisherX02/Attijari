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
