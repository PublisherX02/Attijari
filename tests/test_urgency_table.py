import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from database import (
    Base, Urgency, Email, SessionLocal, engine,
    upsert_urgency, get_urgency_queue, confirm_settlement,
    ALL_PERMISSIONS,
)


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    created_email_ids = []
    session.info["created_email_ids"] = created_email_ids
    yield session
    session.rollback()
    session.query(Urgency).filter(Urgency.email_id.in_(created_email_ids)).delete(synchronize_session=False)
    session.query(Email).filter(Email.id.in_(created_email_ids)).delete(synchronize_session=False)
    session.commit()
    session.close()


def _make_email(db, idempotency_key=None):
    email = Email(idempotency_key=idempotency_key or f"urgency-test-{uuid.uuid4()}", raw_sha256="a" * 64, status="recu")
    db.add(email)
    db.commit()
    db.refresh(email)
    db.info["created_email_ids"].append(email.id)
    return email


def test_claims_settle_permission_exists():
    assert "claims.settle" in ALL_PERMISSIONS


def test_upsert_urgency_creates_row_with_correct_priority(db_session):
    email = _make_email(db_session)
    claim_verdict = {
        "urgency": "critical", "urgency_reasoning": "severe damage",
        "missing_information": [], "settlement_type": "assistive",
        "settlement_recommendation": "send to adjuster",
    }
    row = upsert_urgency(db_session, email.id, claim_verdict)
    assert row.level == "critical"
    assert row.priority == 3
    assert row.settlement_confirmed is False


def test_upsert_urgency_updates_existing_row(db_session):
    email = _make_email(db_session)
    upsert_urgency(db_session, email.id, {"urgency": "low"})
    updated = upsert_urgency(db_session, email.id, {"urgency": "high"})
    assert updated.level == "high"
    assert updated.priority == 2
    count = db_session.query(Urgency).filter(Urgency.email_id == email.id).count()
    assert count == 1  # updated, not duplicated


def test_upsert_urgency_returns_none_for_empty_claim_verdict(db_session):
    email = _make_email(db_session)
    assert upsert_urgency(db_session, email.id, {}) is None
    assert upsert_urgency(db_session, email.id, None) is None


def test_get_urgency_queue_sorts_critical_first(db_session):
    e1 = _make_email(db_session, "urgency-low")
    e2 = _make_email(db_session, "urgency-critical")
    e3 = _make_email(db_session, "urgency-medium")
    upsert_urgency(db_session, e1.id, {"urgency": "low"})
    upsert_urgency(db_session, e2.id, {"urgency": "critical"})
    upsert_urgency(db_session, e3.id, {"urgency": "medium"})
    queue = get_urgency_queue(db_session)
    levels = [r.level for r in queue]
    assert levels == ["critical", "medium", "low"]


def test_confirm_settlement_sets_fields(db_session):
    email = _make_email(db_session)
    upsert_urgency(db_session, email.id, {"urgency": "low", "settlement_type": "automated"})
    confirmed = confirm_settlement(db_session, email.id, "alice")
    assert confirmed.settlement_confirmed is True
    assert confirmed.settlement_confirmed_by == "alice"
    assert confirmed.settlement_confirmed_at is not None


def test_confirm_settlement_returns_none_when_no_row(db_session):
    email = _make_email(db_session)
    assert confirm_settlement(db_session, email.id, "alice") is None
