"""RedisAsyncLock: async-context-manager wrapper around redis.lock.Lock.
Serializes concurrent 'async with' blocks; fails closed (raises) if Redis is
unreachable or genuinely contended past the timeout. Used by api.py's
pipeline scan lock (_scan_lock = RedisAsyncLock("pipeline_scan", ...))."""
import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")

import redis
from redis_client import get_client


def _cleanup(name):
    get_client().delete(name)


def test_serializes_two_concurrent_holders():
    from redis_async_lock import RedisAsyncLock
    _cleanup("test_scan_lock_serial")
    lock = RedisAsyncLock("test_scan_lock_serial", timeout=10)
    order = []

    async def holder(label, hold_seconds):
        async with lock:
            order.append(f"{label}-enter")
            await asyncio.sleep(hold_seconds)
            order.append(f"{label}-exit")

    async def run():
        await asyncio.gather(holder("a", 0.3), holder("b", 0.0))

    asyncio.run(run())
    # Whichever ran first must fully exit before the second enters — no interleaving.
    assert order in (["a-enter", "a-exit", "b-enter", "b-exit"], ["b-enter", "b-exit", "a-enter", "a-exit"])
    _cleanup("test_scan_lock_serial")


def test_raises_timeout_error_when_redis_unreachable():
    from redis_async_lock import RedisAsyncLock
    lock = RedisAsyncLock("test_scan_lock_down", timeout=10)

    async def run():
        with patch("redis_async_lock.get_client") as mock_get_client:
            mock_get_client.return_value.set.side_effect = redis.exceptions.RedisError("down")
            async with lock:
                pass  # should never get here

    try:
        asyncio.run(run())
        assert False, "expected TimeoutError"
    except TimeoutError:
        pass


def test_scan_lock_instance_in_api_is_a_redis_async_lock():
    # api.py's _scan_lock must be this class, so the tests above genuinely
    # cover what api.py actually uses.
    from redis_async_lock import RedisAsyncLock
    import api
    assert isinstance(api._scan_lock, RedisAsyncLock)
