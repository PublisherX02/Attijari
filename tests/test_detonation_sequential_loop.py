import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class _FakeRow:
    _seq = 0
    def __init__(self, sha256, priority=False, stored_path="/tmp/x", filename="x.exe", email_id=1):
        _FakeRow._seq += 1
        self.id = _FakeRow._seq
        self.sha256 = sha256
        self.priority = priority
        self.stored_path = stored_path
        self.filename = filename
        self.email_id = email_id
        self.status = "queued"
        self.attempts = 0
        self.result = None


class _FakeSession:
    def close(self): pass
    def commit(self): pass


def test_priority_row_inserted_mid_run_is_picked_up_next(monkeypatch):
    """Two rows (A, B) queued at start. While A is detonating, a priority
    row P gets inserted. The loop must process A, then P, then B — never
    interrupting A, and never waiting for a whole pre-fetched batch."""
    import detonation
    import detonation_state as state
    state.end()  # ensure clean slate regardless of test order

    row_a = _FakeRow("a" * 64)
    row_b = _FakeRow("b" * 64)
    queue = [row_a, row_b]
    processed_order = []

    def fake_get_queued(db, limit=1):
        return queue[:1]  # always "the current front of the queue"

    def fake_count_queued(db):
        return len(queue)

    def fake_recover_stale(db, *a, **k):
        return 0

    monkeypatch.setattr("database.SessionLocal", lambda: _FakeSession())
    monkeypatch.setattr("database.get_queued_detonations", fake_get_queued)
    monkeypatch.setattr("database.count_queued_detonations", fake_count_queued)
    monkeypatch.setattr("database.recover_stale_running_detonations", fake_recover_stale)

    monkeypatch.setattr(detonation, "_drain", lambda: None)
    monkeypatch.setattr(detonation, "_resume_vm", lambda: True)
    monkeypatch.setattr(detonation, "_restore", lambda: None)
    monkeypatch.setattr(detonation, "_apply_result_to_email", lambda db, row, result: None)

    def fake_process_one(row):
        processed_order.append(row.sha256)
        queue.remove(row)
        if row.sha256 == "a" * 64:
            # Simulate a priority insert arriving while A is "running"
            row_p = _FakeRow("p" * 64, priority=True)
            queue.insert(0, row_p)
        return {"tool": "detonation", "detonated": True, "status": "done", "escalate": False}

    monkeypatch.setattr(detonation, "_process_one", fake_process_one)
    monkeypatch.setattr(detonation.cfg, "DETONATION_IDLE_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(detonation.cfg, "DETONATION_IDLE_POLL_SECONDS", 0)

    summary = detonation.process_detonation_queue()

    assert processed_order == ["a" * 64, "p" * 64, "b" * 64]
    assert summary["processed"] == 3
