import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def test_get_recent_detonation_events_reports_running_and_done(monkeypatch):
    import database as db

    class Row:
        def __init__(self, id, email_id, filename, status):
            self.id = id
            self.email_id = email_id
            self.filename = filename
            self.status = status

    rows = [
        Row(1, 10, "invoice.pdf", "running"),
        Row(2, 11, "report.docx", "done"),
        Row(3, 12, "x.exe", "queued"),  # not yet started -> no event
    ]

    class FakeQuery:
        def __init__(self, data):
            self._data = data
        def filter(self, *a, **k):
            return FakeQuery([r for r in self._data if r.status in ("running", "done", "error")])
        def order_by(self, *a, **k): return self
        def limit(self, *a, **k): return self
        def all(self): return self._data

    class FakeDB:
        def query(self, *a, **k): return FakeQuery(rows)

    events = db.get_recent_detonation_events(FakeDB())
    kinds = {(e["email_id"], e["event"]) for e in events}
    assert (10, "detonating") in kinds
    assert (11, "report_ready") in kinds
    assert all(e["email_id"] != 12 for e in events)
