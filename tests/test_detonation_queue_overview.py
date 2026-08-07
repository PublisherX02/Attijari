"""Tests for the Detonation Queue panel's backing functions:
database.get_detonation_queue_overview and database.set_detonation_priority.

Live-DB tests, same fixture pattern as tests/test_detonation_recovery.py.
"""
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from database import Base, PendingDetonation, SessionLocal, engine


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    created_row_ids = []
    session.info["created_row_ids"] = created_row_ids
    yield session
    session.rollback()
    session.query(PendingDetonation).filter(PendingDetonation.id.in_(created_row_ids)).delete(synchronize_session=False)
    session.commit()
    session.close()


def _make_row(db, status, email_id=None, filename=None, priority=False, reason=None):
    row = PendingDetonation(
        email_id=email_id, sha256=uuid.uuid4().hex,
        stored_path="C:\\fake\\path.bin", status=status, filename=filename,
        priority=priority, reason=reason,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    db.info["created_row_ids"].append(row.id)
    return row


def test_queue_overview_groups_by_status(db_session):
    from database import get_detonation_queue_overview

    running = _make_row(db_session, "running", filename="a.pdf")
    queued = _make_row(db_session, "queued", filename="b.docx")
    deferred = _make_row(db_session, "deferred", filename="c.exe")
    ready = _make_row(db_session, "ready", filename="d.zip")
    done = _make_row(db_session, "done", filename="e.pdf")  # must not appear

    overview = get_detonation_queue_overview(db_session)

    running_ids = {r["id"] for r in overview["running"]}
    queued_ids = {r["id"] for r in overview["queued"]}
    deferred_ids = {r["id"] for r in overview["manual_deferred"]}
    ready_ids = {r["id"] for r in overview["manual_ready"]}
    all_ids = running_ids | queued_ids | deferred_ids | ready_ids

    assert running.id in running_ids
    assert queued.id in queued_ids
    assert deferred.id in deferred_ids
    assert ready.id in ready_ids
    assert done.id not in all_ids


def test_queue_overview_orders_priority_first_then_oldest(db_session):
    from database import get_detonation_queue_overview

    old_normal = _make_row(db_session, "queued", filename="old.pdf", priority=False)
    new_priority = _make_row(db_session, "queued", filename="urgent.pdf", priority=True)

    overview = get_detonation_queue_overview(db_session)
    queued_ids_in_order = [r["id"] for r in overview["queued"] if r["id"] in (old_normal.id, new_priority.id)]
    assert queued_ids_in_order == [new_priority.id, old_normal.id]


def test_set_detonation_priority_flips_queued_row(db_session):
    from database import set_detonation_priority

    row = _make_row(db_session, "queued", filename="b.docx", priority=False)
    updated = set_detonation_priority(db_session, row.id)
    assert updated.priority is True

    db_session.refresh(row)
    assert row.priority is True


def test_set_detonation_priority_noop_on_non_queued_row(db_session):
    from database import set_detonation_priority

    row = _make_row(db_session, "running", filename="a.pdf", priority=False)
    updated = set_detonation_priority(db_session, row.id)
    assert updated.priority is False  # unchanged -- can't jump a queue you already left


def test_set_detonation_priority_returns_none_for_missing_row(db_session):
    from database import set_detonation_priority

    assert set_detonation_priority(db_session, 999999999) is None
