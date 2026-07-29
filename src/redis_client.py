"""redis_client.py — shared Redis connection for security-critical state
(rate limits, TOTP replay cache, detonation window lock, pipeline scan lock).

Callers handle redis.exceptions.RedisError themselves — this module does
not swallow errors, since fail-open vs. fail-closed on a Redis outage is a
per-caller decision (see docs/superpowers/specs/2026-07-29-arch1-redis-state-externalization-design.md).
"""
from __future__ import annotations

import os
import redis

REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")

_client: "redis.Redis | None" = None


def get_client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.Redis.from_url(
            REDIS_URL, decode_responses=True,
            socket_connect_timeout=2, socket_timeout=2,
        )
    return _client
