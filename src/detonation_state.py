"""detonation_state.py — Global "detonation in progress" flag.

While a drained detonation window is active, the pipeline is torn down (Ollama
models unloaded, Docker stopped) to free RAM for the CAPE Ubuntu VM. The
background poller, the scheduler, and the manual /api/scan endpoint must all
refuse to start a new pipeline run during that window — otherwise they'd reload
the models and blow the memory budget on a 16 GB machine.

Backed by Redis (ARCH-1, 2026-07-29) so this holds across processes/workers,
not just threads within one process — a plain threading.Lock only synchronized
this process, which broke the instant the app ran more than one worker.

Fail-safe design, unchanged in spirit from the original threading.Lock version:
- The lock carries a TTL (DETONATION_CYCLE_TIMEOUT + grace margin) so a crash
  that skips end() still self-clears, rather than getting stuck "paused" forever.
- If Redis itself is unreachable, every operation FAILS CLOSED: try_begin()
  returns False (refuse to start a new window), is_active() returns True
  (behave as if a window IS active, so callers refuse to start pipeline runs).
  Concurrent double-run risk (blown RAM budget) is worse than a missed tick.

Deliberately does NOT use redis.lock.Lock: its release() requires an
ownership token from the SAME acquiring call, but end() here must work
regardless of who called begin()/try_begin() (a watchdog, a different
request, a different process) — exactly the "anyone can release, no
ownership check" semantics the original threading.Lock-based code already
had. Plain SET NX / DELETE / EXISTS need no such token.
"""
from __future__ import annotations

import json
import time

import redis

from redis_client import get_client
from detonation_config import DETONATION_CYCLE_TIMEOUT

_LOCK_NAME = "detonation_window"
_META_KEY = "detonation_window:meta"
_LOCK_TTL_SECONDS = DETONATION_CYCLE_TIMEOUT + 120  # grace margin over the normal cycle


def begin(reason: str = "") -> None:
    try:
        get_client().set(_LOCK_NAME, "1", ex=_LOCK_TTL_SECONDS)  # unconditional claim, matches original begin()
        get_client().set(_META_KEY, json.dumps({"reason": reason, "since": time.time()}), ex=_LOCK_TTL_SECONDS)
    except redis.exceptions.RedisError as e:
        print(f"[DETONATION-STATE] Redis unreachable in begin(): {e}")
        raise


def try_begin(reason: str = "") -> bool:
    """Atomically claim the window. Returns False if already active OR if
    Redis is unreachable (fail closed — never let two windows run at once)."""
    try:
        acquired = get_client().set(_LOCK_NAME, "1", nx=True, ex=_LOCK_TTL_SECONDS)
        if not acquired:
            return False
        get_client().set(_META_KEY, json.dumps({"reason": reason, "since": time.time()}), ex=_LOCK_TTL_SECONDS)
        return True
    except redis.exceptions.RedisError as e:
        print(f"[DETONATION-STATE] Redis unreachable in try_begin(), failing closed: {e}")
        return False


def end() -> None:
    """Must never raise — this is the fail-safe release path itself.
    Unconditional delete, callable by anyone regardless of who began()."""
    try:
        get_client().delete(_LOCK_NAME, _META_KEY)
    except redis.exceptions.RedisError as e:
        print(f"[DETONATION-STATE] Redis unreachable in end() (non-fatal): {e}")


def is_active() -> bool:
    """Fails closed: if Redis is unreachable, behave as if a window IS
    active, so callers refuse to start new pipeline runs."""
    try:
        return get_client().exists(_LOCK_NAME) == 1
    except redis.exceptions.RedisError as e:
        print(f"[DETONATION-STATE] Redis unreachable in is_active(), failing closed (active=True): {e}")
        return True


def status() -> dict:
    try:
        active = get_client().exists(_LOCK_NAME) == 1
        if not active:
            return {"active": False, "reason": "", "elapsed_s": 0}
        meta_raw = get_client().get(_META_KEY)
        meta = json.loads(meta_raw) if meta_raw else {"reason": "", "since": time.time()}
        return {
            "active": True,
            "reason": meta.get("reason", ""),
            "elapsed_s": round(time.time() - meta.get("since", time.time()), 1),
        }
    except redis.exceptions.RedisError as e:
        print(f"[DETONATION-STATE] Redis unreachable in status(), failing closed: {e}")
        return {"active": True, "reason": "redis-unreachable", "elapsed_s": 0}
