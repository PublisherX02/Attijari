"""Per-sender/domain rate limiting for inbound SMTP.

Fails open on a Redis outage — this is defense-in-depth on top of the
rules engine and sandboxed extraction, not the primary security boundary
(see docs/superpowers/specs/2026-07-29-arch1-redis-state-externalization-design.md,
which made the same call for the HTTP-route rate limiter in api_core.py).
"""
from __future__ import annotations

import logging

from limits import parse
from limits.storage import Storage, storage_from_string
from limits.strategies import FixedWindowRateLimiter
from redis.exceptions import RedisError

from redis_client import REDIS_URL

logger = logging.getLogger("attijari.smtp_rate_limit")


class SmtpRateLimiter:
    """Fixed-window rate limiter keyed on SMTP sender address and domain."""

    SENDER_LIMIT = parse("20/minute")
    DOMAIN_LIMIT = parse("60/minute")

    def __init__(self, storage: Storage | None = None):
        self._storage = storage if storage is not None else storage_from_string(REDIS_URL)
        self._strategy = FixedWindowRateLimiter(self._storage)

    def allow(self, mail_from: str) -> bool:
        """Return True if this sender/domain is under quota, False to reject.

        Fails open (returns True) if Redis is unreachable.
        """
        sender_key = mail_from.strip().lower()
        try:
            if not self._strategy.hit(self.SENDER_LIMIT, "smtp:sender", sender_key):
                return False
            if "@" in sender_key:
                domain = sender_key.rsplit("@", 1)[-1]
                if not self._strategy.hit(self.DOMAIN_LIMIT, "smtp:domain", domain):
                    return False
            return True
        except RedisError:
            logger.warning(
                "[SMTP-RATE-LIMIT] Redis unavailable, failing open for sender %s",
                sender_key,
            )
            return True
