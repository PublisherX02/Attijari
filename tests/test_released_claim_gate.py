"""Tests for the release gate: a claim only becomes visible to Insurance
Operators once a SOC operator (analyst/admin) has explicitly released it.
Same pattern as tests/test_urgency_table.py — real DB, rows scoped/cleaned
up per test.
"""
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from database import (
    Base, Email, ReleasedClaim, AuditLog, AnalystFeedback, SessionLocal, engine,
    mark_claim_released, unmark_claim_released,
)


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    created_email_ids = []
    session.info["created_email_ids"] = created_email_ids
    yield session
    session.rollback()
    session.query(ReleasedClaim).filter(ReleasedClaim.email_id.in_(created_email_ids)).delete(synchronize_session=False)
    # release_email (with a reason)/quarantine_email/override_verdict/revert_action
    # all write AuditLog/AnalystFeedback rows referencing the email — must clear
    # those before the FK allows deleting the email itself.
    session.query(AuditLog).filter(AuditLog.email_id.in_(created_email_ids)).delete(synchronize_session=False)
    session.query(AnalystFeedback).filter(AnalystFeedback.email_id.in_(created_email_ids)).delete(synchronize_session=False)
    session.query(Email).filter(Email.id.in_(created_email_ids)).delete(synchronize_session=False)
    session.commit()
    session.close()


def _make_email(db, idempotency_key=None):
    email = Email(idempotency_key=idempotency_key or f"released-claim-test-{uuid.uuid4()}", raw_sha256="a" * 64, status="escalated")
    db.add(email)
    db.commit()
    db.refresh(email)
    db.info["created_email_ids"].append(email.id)
    return email


def test_mark_claim_released_creates_row(db_session):
    email = _make_email(db_session)
    mark_claim_released(db_session, email.id, released_by="analyst1")
    db_session.commit()
    row = db_session.query(ReleasedClaim).filter(ReleasedClaim.email_id == email.id).first()
    assert row is not None
    assert row.released_by == "analyst1"


def test_mark_claim_released_is_idempotent(db_session):
    email = _make_email(db_session)
    mark_claim_released(db_session, email.id, released_by="analyst1")
    mark_claim_released(db_session, email.id, released_by="analyst2")
    db_session.commit()
    count = db_session.query(ReleasedClaim).filter(ReleasedClaim.email_id == email.id).count()
    assert count == 1
    # first release wins — a second release call doesn't overwrite who released it
    row = db_session.query(ReleasedClaim).filter(ReleasedClaim.email_id == email.id).first()
    assert row.released_by == "analyst1"


def test_unmark_claim_released_removes_row(db_session):
    email = _make_email(db_session)
    mark_claim_released(db_session, email.id, released_by="analyst1")
    db_session.commit()
    unmark_claim_released(db_session, email.id)
    db_session.commit()
    row = db_session.query(ReleasedClaim).filter(ReleasedClaim.email_id == email.id).first()
    assert row is None


def test_unmark_claim_released_is_safe_when_absent(db_session):
    email = _make_email(db_session)
    unmark_claim_released(db_session, email.id)  # never released — must not raise
    db_session.commit()
    assert db_session.query(ReleasedClaim).filter(ReleasedClaim.email_id == email.id).count() == 0


def test_release_email_marks_claim_released(db_session):
    from routing import release_email
    email = _make_email(db_session)
    email.status = "escalated"
    db_session.commit()

    result = release_email(email.id, actor="analyst1", reason="false positive")
    assert result["success"] is True

    row = db_session.query(ReleasedClaim).filter(ReleasedClaim.email_id == email.id).first()
    assert row is not None
    assert row.released_by == "analyst1"


def test_revert_release_unmarks_claim_released(db_session):
    from routing import release_email, revert_action
    email = _make_email(db_session)
    email.status = "escalated"
    db_session.commit()

    release_email(email.id, actor="analyst1")
    assert db_session.query(ReleasedClaim).filter(ReleasedClaim.email_id == email.id).count() == 1

    revert_action(email.id, actor="analyst1")
    assert db_session.query(ReleasedClaim).filter(ReleasedClaim.email_id == email.id).count() == 0


def test_quarantine_after_release_unmarks_claim_released(db_session):
    from routing import release_email, quarantine_email
    email = _make_email(db_session)
    email.status = "escalated"
    db_session.commit()

    release_email(email.id, actor="analyst1")
    assert db_session.query(ReleasedClaim).filter(ReleasedClaim.email_id == email.id).count() == 1

    quarantine_email(email.id, actor="analyst1", cascade_block=False)
    assert db_session.query(ReleasedClaim).filter(ReleasedClaim.email_id == email.id).count() == 0


def test_override_to_released_marks_claim_released(db_session):
    from routing import override_verdict
    email = _make_email(db_session)
    email.status = "escalated"
    db_session.commit()

    override_verdict(email.id, "released", actor="analyst1", notes="manual override")
    assert db_session.query(ReleasedClaim).filter(ReleasedClaim.email_id == email.id).count() == 1


def test_override_away_from_released_unmarks_claim_released(db_session):
    from routing import release_email, override_verdict
    email = _make_email(db_session)
    email.status = "escalated"
    db_session.commit()

    release_email(email.id, actor="analyst1")
    assert db_session.query(ReleasedClaim).filter(ReleasedClaim.email_id == email.id).count() == 1

    override_verdict(email.id, "escalated", actor="analyst1", notes="reconsidered")
    assert db_session.query(ReleasedClaim).filter(ReleasedClaim.email_id == email.id).count() == 0
