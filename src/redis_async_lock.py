"""redis_async_lock.py — async-context-manager mutual exclusion backed by Redis.

Extracted out of api.py (ARCH-1, 2026-07-29) to keep api.py under its
enforced line-count budget (see tests/test_benchmark_compliance.py). Used
for api.py's pipeline scan lock so at most one pipeline tick runs at a time,
even across multiple workers/processes.
"""
from __future__ import annotations

import asyncio
import contextvars

import redis

from redis_client import get_client

# Holds the currently-acquired Lock object for whichever asyncio Task is
# inside a `async with lock:` block. A plain instance attribute (self._lock)
# would NOT work here: if a shared RedisAsyncLock instance is ever entered
# by two concurrent asyncio Tasks (verified empirically during planning, via
# asyncio.gather in this module's own test), the second __aenter__
# overwrites self._lock before the first Task's __aexit__ runs, so the
# first Task ends up releasing the WRONG Lock object — the real one never
# gets released and sits until its TTL expires. contextvars.ContextVar is
# copy-on-write per asyncio Task, so each concurrent `async with` sees only
# its own lock here, with no cross-task interference.
_current_lock: contextvars.ContextVar = contextvars.ContextVar("_redis_async_lock_current")


class RedisAsyncLock:
    """Async-context-manager wrapper around redis.lock.Lock — for use inside
    an async loop, where redis-py's Lock (synchronous) needs its acquire/
    release run in the default executor.

    thread_local=False is required on the Lock itself: acquire() and
    release() each run inside a loop.run_in_executor(None, ...) call, which
    is NOT guaranteed to land on the same worker thread across the two
    calls. With the default thread_local=True, the lock's ownership token
    lives in thread-local storage, so a release() on a different worker
    thread than the one that acquired it raises redis.exceptions.LockError
    even for the same Lock object (verified empirically during planning).
    thread_local=False keeps the token on the Lock object itself instead,
    which survives across worker threads.

    Fails CLOSED: a Redis outage or genuine contention past `timeout` raises
    TimeoutError rather than silently letting two callers proceed at once.
    """
    def __init__(self, name: str, timeout: int = 600):
        self._name = name
        self._timeout = timeout

    async def __aenter__(self):
        lock = redis.lock.Lock(get_client(), name=self._name, timeout=self._timeout, thread_local=False)
        loop = asyncio.get_running_loop()
        try:
            acquired = await loop.run_in_executor(None, lambda: lock.acquire(blocking=True, blocking_timeout=30))
        except redis.exceptions.RedisError as e:
            raise TimeoutError(f"{self._name} lock: Redis unreachable ({e})")
        if not acquired:
            raise TimeoutError(f"{self._name} lock: could not acquire within 30s — Redis down or lock genuinely held")
        _current_lock.set(lock)
        return self

    async def __aexit__(self, *exc):
        lock = _current_lock.get()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._release_safely, lock)

    def _release_safely(self, lock):
        try:
            lock.release()
        except (redis.lock.LockNotOwnedError, redis.exceptions.RedisError) as e:
            print(f"[{self._name.upper()}-LOCK] Release warning (non-fatal): {e}")
