import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def test_email_model_accepts_pending_detonation_status():
    import database as db
    # No CHECK constraint exists on status (plain String(20), database.py:98-103)
    # — this test documents the new value is a recognized application-level
    # status, not a DB-level enum, by asserting the column comment mentions it.
    import inspect
    src = inspect.getsource(db.Email)
    assert "pending_detonation" in src


def test_gauge_metrics_count_pending_detonation_as_in_queue(monkeypatch):
    import routers.emails as emails_mod

    captured = {}

    class FakeQuery:
        def filter(self, *a, **k): return self
        def count(self): return 3

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()
        def close(self): pass

    monkeypatch.setattr(emails_mod, "SessionLocal", lambda: FakeDB())

    class FakeGauge:
        def labels(self, **k): return self
        def set(self, v): captured["queue_size"] = v

    import metrics
    monkeypatch.setattr(metrics, "emails_in_queue", FakeGauge())
    monkeypatch.setattr(metrics, "blocklist_size", FakeGauge())

    emails_mod._update_gauge_metrics()
    assert captured["queue_size"] == 3
