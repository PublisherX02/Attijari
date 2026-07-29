"""TOTP replay cache: Redis SETEX with per-key TTL (fixes SEC-L1's wholesale-
flush issue), fail-open on Redis outage."""
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")

import redis
import redis_client


def _cleanup(key):
    redis_client.get_client().delete(key)


def test_fresh_code_is_not_replayed():
    from routers import auth
    key = "totp_used:test-fresh@example.com:111111"
    _cleanup(key)
    assert auth._is_totp_replayed(key) is False


def test_marked_code_is_replayed_within_ttl():
    from routers import auth
    key = "totp_used:test-replay@example.com:222222"
    _cleanup(key)
    auth._mark_totp_used(key, ttl_seconds=60)
    assert auth._is_totp_replayed(key) is True
    _cleanup(key)


def test_marked_code_expires_after_ttl():
    from routers import auth
    key = "totp_used:test-expiry@example.com:333333"
    _cleanup(key)
    auth._mark_totp_used(key, ttl_seconds=1)
    assert auth._is_totp_replayed(key) is True
    time.sleep(1.5)
    assert auth._is_totp_replayed(key) is False


def test_replay_check_fails_open_when_redis_unreachable():
    from routers import auth
    with patch("routers.auth.get_client") as mock_get_client:
        mock_get_client.return_value.exists.side_effect = redis.exceptions.RedisError("down")
        assert auth._is_totp_replayed("totp_used:whatever:000000") is False


def test_mark_used_does_not_raise_when_redis_unreachable():
    from routers import auth
    with patch("routers.auth.get_client") as mock_get_client:
        mock_get_client.return_value.setex.side_effect = redis.exceptions.RedisError("down")
        auth._mark_totp_used("totp_used:whatever:000000")  # must not raise
