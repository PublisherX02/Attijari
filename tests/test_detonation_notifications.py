import sys, os, uuid
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest


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


@pytest.fixture
def db_session():
    from database import Base, PendingDetonation, SessionLocal, engine

    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    created_row_ids = []
    session.info["created_row_ids"] = created_row_ids
    yield session
    session.rollback()
    session.query(PendingDetonation).filter(PendingDetonation.id.in_(created_row_ids)).delete(synchronize_session=False)
    session.commit()
    session.close()


def _make_row(db, status, email_id=None, filename=None):
    from database import PendingDetonation

    row = PendingDetonation(
        email_id=email_id, sha256=uuid.uuid4().hex,
        stored_path="C:\\fake\\path.bin", status=status, filename=filename,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    db.info["created_row_ids"].append(row.id)
    return row


def test_get_recent_detonation_events_includes_manual_detonations(db_session):
    """Manual (non-email) detonations must also produce a completion event --
    those are precisely the ones the operator triggered and is watching.
    Uses a real DB session (not a fake query) so the actual SQLAlchemy
    .filter() clause, including any email_id condition, is really exercised."""
    import database as db

    running = _make_row(db_session, "running", email_id=None, filename="manual_upload.exe")
    done = _make_row(db_session, "done", email_id=None, filename="manual_upload2.pdf")
    errored = _make_row(db_session, "error", email_id=None, filename="manual_upload3.zip")

    events = db.get_recent_detonation_events(db_session)
    kinds = {(e["id"], e["event"]) for e in events}
    assert (running.id, "detonating") in kinds
    assert (done.id, "report_ready") in kinds
    assert (errored.id, "report_ready") in kinds
