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
