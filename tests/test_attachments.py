"""Tests for the Attachment table and safe/unsafe attachment gating.

Follows the hermetic style of tests/test_jwt_revocation.py for anything
touching the real DB (via SessionLocal/engine, cleaned up by id after each
test — this repo's tests run against the real configured Postgres, so never
truncate a whole table), and the monkeypatch style of
tests/test_manual_detonation.py for pure-logic functions.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")

import pytest


def test_attachment_table_columns():
    import database as db
    cols = db.Attachment.__table__.columns.keys()
    for c in ("id", "email_id", "sha256", "stored_path", "filename", "real_type", "size_bytes", "created_at"):
        assert c in cols, f"Attachment missing column {c}"


@pytest.fixture
def db_session():
    from database import Base, SessionLocal, engine
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    session.info["attachment_ids"] = []
    session.info["email_ids"] = []
    yield session
    session.rollback()
    from database import Attachment, Email
    ids = session.info["attachment_ids"]
    if ids:
        session.query(Attachment).filter(Attachment.id.in_(ids)).delete(synchronize_session=False)
    eids = session.info["email_ids"]
    if eids:
        session.query(Email).filter(Email.id.in_(eids)).delete(synchronize_session=False)
    session.commit()
    session.close()


def _mk_email(session, idem_key):
    from database import Email
    e = Email(idempotency_key=idem_key, raw_sha256="0" * 64, attachment_count=0, status="recu")
    session.add(e)
    session.commit()
    session.refresh(e)
    session.info["email_ids"].append(e.id)
    return e


def test_save_attachments_persists_every_attachment(db_session):
    from database import save_attachments
    email = _mk_email(db_session, "test-attachments-save-1")

    parsed_attachments = [
        {"sha256": "a" * 64, "stored_path": "/tmp/a.pdf", "original_name": "invoice.pdf",
         "real_type": "application/pdf", "size_bytes": 100},
        # A fully-clean attachment that was NEVER a detonation candidate —
        # must still be persisted (this is the whole point of the table).
        {"sha256": "b" * 64, "stored_path": "/tmp/b.png", "original_name": "logo.png",
         "real_type": "image/png", "size_bytes": 50},
        # A failed extraction (oversized/error) has no stored_path — must be skipped, not crash.
        {"error": "oversized", "original_name": "huge.zip"},
    ]

    rows = save_attachments(db_session, email.id, parsed_attachments)
    db_session.info["attachment_ids"].extend(r.id for r in rows)

    assert len(rows) == 2
    shas = {r.sha256 for r in rows}
    assert shas == {"a" * 64, "b" * 64}
    for r in rows:
        assert r.email_id == email.id
    pdf_row = next(r for r in rows if r.sha256 == "a" * 64)
    assert pdf_row.filename == "invoice.pdf"
    assert pdf_row.real_type == "application/pdf"
    assert pdf_row.size_bytes == 100


def test_save_attachments_empty_list_no_commit(db_session, monkeypatch):
    from database import save_attachments
    email = _mk_email(db_session, "test-attachments-save-2")
    committed = {"n": 0}
    orig_commit = db_session.commit
    def counting_commit():
        committed["n"] += 1
        orig_commit()
    monkeypatch.setattr(db_session, "commit", counting_commit)

    rows = save_attachments(db_session, email.id, [{"error": "oversized", "original_name": "x"}])
    assert rows == []
    assert committed["n"] == 0


# ---------------------------------------------------------------------------
# attachment_safety_status / resolve_attachment
# ---------------------------------------------------------------------------

def test_safety_status_no_row_is_unverified():
    from attachments import attachment_safety_status, STATUS_UNVERIFIED

    class FakeQuery:
        def filter(self, *a, **k): return self
        def order_by(self, *a, **k): return self
        def first(self): return None

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()

    assert attachment_safety_status(FakeDB(), "x" * 64) == STATUS_UNVERIFIED


def _fake_db_returning(row):
    class FakeQuery:
        def filter(self, *a, **k): return self
        def order_by(self, *a, **k): return self
        def first(self): return row

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()

    return FakeDB()


def test_safety_status_queued_or_running_is_pending():
    from attachments import attachment_safety_status, STATUS_PENDING

    class Row:
        status = "queued"
        result = None

    assert attachment_safety_status(_fake_db_returning(Row()), "x" * 64) == STATUS_PENDING
    Row.status = "running"
    assert attachment_safety_status(_fake_db_returning(Row()), "x" * 64) == STATUS_PENDING


def test_safety_status_done_clean_is_safe():
    from attachments import attachment_safety_status, STATUS_SAFE
    import detonation_config as cfg

    class Row:
        status = "done"
        result = {"malscore": cfg.CAPE_MALSCORE_SUSPICIOUS - 0.1}

    assert attachment_safety_status(_fake_db_returning(Row()), "x" * 64) == STATUS_SAFE


def test_safety_status_done_at_threshold_is_unsafe():
    """malscore >= threshold, per detonation_config's own comment ('malscore
    >= this -> mark suspicious'), so equality must NOT count as safe."""
    from attachments import attachment_safety_status, STATUS_UNSAFE
    import detonation_config as cfg

    class Row:
        status = "done"
        result = {"malscore": cfg.CAPE_MALSCORE_SUSPICIOUS}

    assert attachment_safety_status(_fake_db_returning(Row()), "x" * 64) == STATUS_UNSAFE


def test_safety_status_done_missing_malscore_is_unsafe():
    """Fail-safe: an unparseable/missing malscore must never default to safe."""
    from attachments import attachment_safety_status, STATUS_UNSAFE

    class Row:
        status = "done"
        result = {}

    assert attachment_safety_status(_fake_db_returning(Row()), "x" * 64) == STATUS_UNSAFE


def test_safety_status_error_is_unsafe():
    from attachments import attachment_safety_status, STATUS_UNSAFE

    class Row:
        status = "error"
        result = None

    assert attachment_safety_status(_fake_db_returning(Row()), "x" * 64) == STATUS_UNSAFE


def test_resolve_attachment_not_found():
    from attachments import resolve_attachment

    class FakeQuery:
        def filter(self, *a, **k): return self
        def first(self): return None

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()

    assert resolve_attachment(FakeDB(), email_id=1, attachment_id=99) == {"found": False}


def test_resolve_attachment_found_computes_status(monkeypatch):
    import attachments as att_mod

    class FakeAttachment:
        id = 5
        email_id = 1
        sha256 = "c" * 64
        stored_path = "/tmp/x.pdf"
        filename = "x.pdf"

    class FakeQuery:
        def filter(self, *a, **k): return self
        def first(self): return FakeAttachment()

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()

    monkeypatch.setattr(att_mod, "attachment_safety_status", lambda db, sha: "safe")
    out = att_mod.resolve_attachment(FakeDB(), email_id=1, attachment_id=5)
    assert out["found"] is True
    assert out["status"] == "safe"
    assert out["attachment"].id == 5


# ---------------------------------------------------------------------------
# insist_open
# ---------------------------------------------------------------------------

def _install_insist_fakes(monkeypatch):
    """Mirrors test_manual_detonation.py's _install_fakes — same pattern,
    applied to the attachments module."""
    import attachments as att_mod
    state = {"enqueued": [], "audits": [], "window_started": 0, "active": False}

    class FakeRow:
        _seq = 0
        def __init__(self, **kw):
            FakeRow._seq += 1
            self.id = FakeRow._seq
            self.__dict__.update(kw)

    def fake_enqueue(db, sha256, stored_path, filename=None, email_id=None,
                     idempotency_key=None, reason=None, created_by=None,
                     priority=False, status="queued"):
        row = FakeRow(sha256=sha256, stored_path=stored_path, filename=filename,
                      email_id=email_id, created_by=created_by, priority=priority,
                      status=status, reason=reason)
        state["enqueued"].append(row)
        return row

    def fake_audit(db, action, actor="system", email_id=None, details=None):
        state["audits"].append({"action": action, "actor": actor, "email_id": email_id, "details": details})

    monkeypatch.setattr(att_mod, "_window_active", lambda: state["active"])
    monkeypatch.setattr(att_mod, "_start_window", lambda: state.__setitem__("window_started", state["window_started"] + 1))

    import database
    monkeypatch.setattr(database, "enqueue_detonation", fake_enqueue)
    monkeypatch.setattr(database, "add_audit_entry", fake_audit)

    return att_mod, state


class _FakeAttachment:
    def __init__(self, id=1, email_id=10, sha256="e" * 64, stored_path="/tmp/e.pdf", filename="e.pdf"):
        self.id = id
        self.email_id = email_id
        self.sha256 = sha256
        self.stored_path = stored_path
        self.filename = filename


def test_insist_open_starts_window_when_inactive(monkeypatch):
    att_mod, state = _install_insist_fakes(monkeypatch)
    out = att_mod.insist_open(db=None, attachment=_FakeAttachment(), username="alice")
    assert out["window"] == "started"
    assert state["window_started"] == 1
    row = state["enqueued"][0]
    assert row.sha256 == "e" * 64
    assert row.reason == "analyst_insist"
    assert row.priority is True
    assert row.created_by == "alice"
    assert state["audits"][0]["action"] == "attachment_insist_open"
    assert state["audits"][0]["email_id"] == 10
    assert state["audits"][0]["details"]["attachment_id"] == 1


def test_insist_open_window_already_active(monkeypatch):
    att_mod, state = _install_insist_fakes(monkeypatch)
    state["active"] = True
    out = att_mod.insist_open(db=None, attachment=_FakeAttachment(), username="bob")
    assert out["window"] == "active"
    assert state["window_started"] == 0
