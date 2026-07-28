"""Tests for recover_stale_running_detonations — self-healing for
pending_detonation rows orphaned by a crashed/restarted server process.

Live-DB tests, same fixture pattern as tests/test_urgency_table.py (hackathon
fork) / other live-DB detonation tests in this repo.
"""
import sys
import uuid
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from database import (
    Base, PendingDetonation, Email, SessionLocal, engine, utcnow,
    enqueue_detonation, recover_stale_running_detonations,
)


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    created_email_ids = []
    created_row_ids = []
    session.info["created_email_ids"] = created_email_ids
    session.info["created_row_ids"] = created_row_ids
    yield session
    session.rollback()
    session.query(PendingDetonation).filter(PendingDetonation.id.in_(created_row_ids)).delete(synchronize_session=False)
    session.query(Email).filter(Email.id.in_(created_email_ids)).delete(synchronize_session=False)
    session.commit()
    session.close()


def _make_email(db, status="escalated"):
    email = Email(idempotency_key=f"detonation-recovery-{uuid.uuid4()}", raw_sha256="a" * 64, status=status)
    db.add(email)
    db.commit()
    db.refresh(email)
    db.info["created_email_ids"].append(email.id)
    return email


def _make_running_row(db, age_seconds, attempts=1, email_id=None, sha256=None):
    row = PendingDetonation(
        email_id=email_id, sha256=sha256 or uuid.uuid4().hex,
        stored_path="C:\\fake\\path.bin", status="running", attempts=attempts,
    )
    db.add(row)
    db.commit()
    row.updated_at = utcnow() - timedelta(seconds=age_seconds)
    db.commit()
    db.refresh(row)
    db.info["created_row_ids"].append(row.id)
    return row


def test_recent_running_row_is_left_alone(db_session):
    # Note: recover_stale_running_detonations scans the whole table, so this
    # only asserts on the row this test owns — it does not assume the table
    # is otherwise empty.
    row = _make_running_row(db_session, age_seconds=30)
    recover_stale_running_detonations(db_session, stale_after_seconds=1800)
    db_session.refresh(row)
    assert row.status == "running"


def test_stale_running_row_under_max_attempts_requeues(db_session):
    row = _make_running_row(db_session, age_seconds=3600, attempts=1)
    recover_stale_running_detonations(db_session, stale_after_seconds=1800, max_attempts=3)
    db_session.refresh(row)
    assert row.status == "queued"


def test_stale_running_row_at_max_attempts_errors_and_escalates(db_session):
    email = _make_email(db_session, status="accepted")
    row = _make_running_row(db_session, age_seconds=3600, attempts=3, email_id=email.id)
    recover_stale_running_detonations(db_session, stale_after_seconds=1800, max_attempts=3)
    db_session.refresh(row)
    assert row.status == "error"
    assert row.result.get("escalate") is True
    db_session.refresh(email)
    assert email.status == "escalated"


def test_recovered_row_can_be_requeued_by_dedup_check(db_session):
    # Regression: before recovery, a stuck 'running' row blocks
    # enqueue_detonation from ever re-queueing the same sha256.
    sha = uuid.uuid4().hex
    stuck = _make_running_row(db_session, age_seconds=3600, attempts=1, sha256=sha)
    same_file = enqueue_detonation(db_session, sha256=sha, stored_path="C:\\fake\\path.bin")
    assert same_file.id == stuck.id  # de-duped, still stuck, no new row
    db_session.info["created_row_ids"].append(same_file.id)

    recover_stale_running_detonations(db_session, stale_after_seconds=1800)
    db_session.refresh(stuck)
    assert stuck.status == "queued"  # now eligible to actually run again
