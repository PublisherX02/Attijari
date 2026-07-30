"""One shared, Redis-backed Limiter — no more per-router instances with
separate in-memory buckets."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")


def test_auth_and_mailboxes_import_the_same_limiter_as_api_core():
    import api_core
    from routers import auth as auth_router_mod
    from routers import mailboxes as mailboxes_router_mod
    assert auth_router_mod._limiter is api_core.limiter
    assert mailboxes_router_mod._limiter is api_core.limiter


def test_limiter_uses_redis_storage():
    import api_core
    # api_core.limiter.limiter is the bound FixedWindowRateLimiter strategy;
    # .storage is the backing store — limits' RedisStorage class name varies
    # by version but always contains "Redis".
    assert "Redis" in type(api_core.limiter.limiter.storage).__name__


def test_rate_limit_hit_persists_in_redis_across_lookups():
    import redis_client
    import api_core
    c = redis_client.get_client()
    for k in c.keys("LIMITS*test_rate_key*"):
        c.delete(k)
    from limits import RateLimitItemPerMinute
    item = RateLimitItemPerMinute(5)
    # Reuse the shared limiter's own bound strategy rather than constructing
    # a second one — this is exactly what every @limiter.limit(...) decorator
    # uses under the hood.
    strategy = api_core.limiter.limiter
    assert strategy.hit(item, "test_rate_key") is True
    assert strategy.hit(item, "test_rate_key") is True
    stats = strategy.get_window_stats(item, "test_rate_key")
    assert stats.remaining == 3
    for k in c.keys("LIMITS*test_rate_key*"):
        c.delete(k)
