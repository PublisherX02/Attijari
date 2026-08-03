import sys
from pathlib import Path

import pytest
from limits.storage import MemoryStorage
from redis.exceptions import RedisError

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from smtp_rate_limit import SmtpRateLimiter


def _limiter():
    return SmtpRateLimiter(storage=MemoryStorage())


def test_sender_under_limit_is_allowed():
    limiter = _limiter()
    for _ in range(20):
        assert limiter.allow("attacker@example.com") is True


def test_sender_over_limit_is_rejected():
    limiter = _limiter()
    for _ in range(20):
        assert limiter.allow("attacker@example.com") is True
    assert limiter.allow("attacker@example.com") is False


def test_domain_limit_trips_across_different_senders():
    limiter = _limiter()
    allowed = 0
    for i in range(61):
        sender = f"user{i}@spray.example.com"
        if limiter.allow(sender):
            allowed += 1
    # 61 distinct senders, each individually well under the 20/min
    # per-sender cap, but the shared domain cap is 60/min.
    assert allowed == 60


def test_malformed_sender_with_no_at_sign_is_judged_on_sender_key_only():
    limiter = _limiter()
    for _ in range(20):
        assert limiter.allow("malformed-no-domain") is True
    assert limiter.allow("malformed-no-domain") is False


def test_redis_outage_fails_open():
    limiter = _limiter()

    def _raise(*args, **kwargs):
        raise RedisError("connection refused")

    limiter._strategy.hit = _raise
    assert limiter.allow("anyone@example.com") is True
