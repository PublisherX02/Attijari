"""detonation_state backed by Redis: same public-API contract as before
(atomic try_begin, cross-thread AND now cross-process), plus a TTL backstop
so a crash that skips end() still self-clears, plus fail-closed behavior
when Redis is unreachable."""
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import redis


def test_try_begin_claims_and_refuses_when_active():
    import detonation_state as ds
    ds.end()
    assert ds.try_begin("t1") is True
    assert ds.is_active() is True
    assert ds.try_begin("t2") is False
    ds.end()
    assert ds.try_begin("t3") is True
    ds.end()


def test_try_begin_race_exactly_one_winner():
    import threading
    from concurrent.futures import ThreadPoolExecutor
    import detonation_state as ds
    ds.end()
    n = 16
    barrier = threading.Barrier(n)

    def claim(_):
        barrier.wait()
        return ds.try_begin("race")

    with ThreadPoolExecutor(max_workers=n) as ex:
        results = list(ex.map(claim, range(n)))
    ds.end()
    assert results.count(True) == 1
    assert results.count(False) == n - 1


def test_lock_self_clears_after_ttl_if_end_never_called():
    import detonation_state as ds
    ds.end()
    original_ttl = ds._LOCK_TTL_SECONDS
    ds._LOCK_TTL_SECONDS = 1  # shrink TTL for the test
    try:
        assert ds.try_begin("crash-sim") is True
        time.sleep(1.5)
        assert ds.is_active() is False  # self-cleared, no end() was called
    finally:
        ds._LOCK_TTL_SECONDS = original_ttl
        ds.end()


def test_try_begin_fails_closed_when_redis_unreachable():
    import detonation_state as ds
    with patch("detonation_state.get_client") as mock_get_client:
        mock_get_client.return_value.set.side_effect = redis.exceptions.RedisError("down")
        assert ds.try_begin("should-fail") is False


def test_is_active_fails_closed_when_redis_unreachable():
    import detonation_state as ds
    with patch("detonation_state.get_client") as mock_get_client:
        mock_get_client.return_value.exists.side_effect = redis.exceptions.RedisError("down")
        assert ds.is_active() is True  # fail closed: behave as if a window IS active


def test_end_never_raises_when_redis_unreachable():
    import detonation_state as ds
    with patch("detonation_state.get_client") as mock_get_client:
        mock_get_client.return_value.delete.side_effect = redis.exceptions.RedisError("down")
        ds.end()  # must not raise
