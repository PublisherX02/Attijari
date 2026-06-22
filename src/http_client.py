"""http_client.py — Shared HTTP session with enforced security

Centralizes all outbound HTTP calls with:
  - Explicit TLS certificate verification (CRIT-04)
  - Default timeout (prevents hangs if a module forgets timeout=)
  - Connection pooling (reuses TCP connections across API calls)
  - Consistent User-Agent header
  - Request/response logging hooks for audit trail

All API modules should use get_session() instead of raw requests.get/post.
"""
from __future__ import annotations

import threading
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Global Rate Limiters for APIs that need them
class RateLimiter:
    def __init__(self, calls_per_minute: int):
        self.min_interval = 60.0 / calls_per_minute
        self.lock = threading.Lock()
        self.last_call = 0.0
    
    def wait(self):
        with self.lock:
            now = time.time()
            wait_time = self.last_call + self.min_interval - now
            if wait_time > 0:
                time.sleep(wait_time)
            self.last_call = time.time()

# Shared limiters
# VirusTotal public API is strictly 4 per minute
VT_RATE_LIMITER = RateLimiter(calls_per_minute=4)

# Singleton session
_session: requests.Session | None = None

# Defaults
DEFAULT_TIMEOUT = 15  # seconds — applies when caller doesn't specify
USER_AGENT = "tijari-ai/1.0"


class _TimeoutAdapter(HTTPAdapter):
    """HTTPAdapter that enforces a default timeout on every request."""

    def __init__(self, default_timeout: int = DEFAULT_TIMEOUT, **kwargs):
        self.default_timeout = default_timeout
        super().__init__(**kwargs)

    def send(self, request, **kwargs):
        # Only set timeout if caller didn't explicitly provide one
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = self.default_timeout
        return super().send(request, **kwargs)


def get_session() -> requests.Session:
    """Get the shared HTTP session with enforced TLS and default timeout.

    Thread-safe for read-only access (requests.Session is thread-safe
    for concurrent requests).
    """
    global _session
    if _session is not None:
        return _session

    s = requests.Session()

    # Enforce TLS verification globally
    s.verify = True

    # Consistent headers
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    })

    # Mount adapter with default timeout and connection pooling
    adapter = _TimeoutAdapter(
        default_timeout=DEFAULT_TIMEOUT,
        pool_connections=10,
        pool_maxsize=10,
    )
    s.mount("https://", adapter)
    s.mount("http://", adapter)

    _session = s
    return _session
