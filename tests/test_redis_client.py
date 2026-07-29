"""redis_client: lazy singleton client, reachable against the real local
Memurai/Redis instance (this project's test convention — no fakes)."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def test_get_client_returns_working_singleton():
    import redis_client
    c1 = redis_client.get_client()
    c2 = redis_client.get_client()
    assert c1 is c2  # singleton
    assert c1.ping() is True


def test_get_client_can_set_and_get():
    import redis_client
    c = redis_client.get_client()
    c.set("arch1_smoke_test", "ok", ex=5)
    assert c.get("arch1_smoke_test") == "ok"


def test_redis_url_defaults_to_localhost():
    import redis_client
    if "REDIS_URL" not in os.environ:
        assert redis_client.REDIS_URL == "redis://127.0.0.1:6379/0"
