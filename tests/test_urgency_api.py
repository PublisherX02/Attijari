import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from database import Base, Urgency, Email, AuditLog, SessionLocal, engine, upsert_urgency


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    created_email_ids = []
    session.info["created_email_ids"] = created_email_ids
    yield session
    session.rollback()
    session.query(AuditLog).filter(AuditLog.email_id.in_(created_email_ids)).delete(synchronize_session=False)
    session.query(Urgency).filter(Urgency.email_id.in_(created_email_ids)).delete(synchronize_session=False)
    session.query(Email).filter(Email.id.in_(created_email_ids)).delete(synchronize_session=False)
    session.commit()
    session.close()


def _make_email(db, idempotency_key=None):
    email = Email(idempotency_key=idempotency_key or f"urgency-api-test-{uuid.uuid4()}", raw_sha256="a" * 64, status="recu")
    db.add(email)
    db.commit()
    db.refresh(email)
    db.info["created_email_ids"].append(email.id)
    return email


def test_urgency_routes_registered():
    from routers.emails import emails_router
    paths = {getattr(r, "path", "") for r in emails_router.routes}
    assert "/api/urgency" in paths
    assert "/api/emails/{email_id}/settlement/confirm" in paths


def test_get_urgency_queue_api_returns_sorted_items(db_session):
    from routers.emails import get_urgency_queue_api

    e1 = _make_email(db_session)
    e2 = _make_email(db_session)
    upsert_urgency(db_session, e1.id, {"urgency": "low"})
    upsert_urgency(db_session, e2.id, {"urgency": "critical"})

    out = get_urgency_queue_api(user=SimpleNamespace(username="admin"))
    levels = [i["level"] for i in out["items"] if i["email_id"] in (e1.id, e2.id)]
    assert levels.index("critical") < levels.index("low")


def test_confirm_settlement_api_sets_audit_entry(db_session, monkeypatch):
    from routers.emails import confirm_settlement_api
    import database

    email = _make_email(db_session)
    upsert_urgency(db_session, email.id, {"urgency": "low", "settlement_type": "automated"})

    audits = []
    original_add_audit = database.add_audit_entry
    def _spy_add_audit(db, **kw):
        audits.append(kw)
        return original_add_audit(db, **kw)
    monkeypatch.setattr(database, "add_audit_entry", _spy_add_audit)

    out = confirm_settlement_api(email.id, user=SimpleNamespace(username="admin"))
    assert out["settlement_confirmed"] is True
    assert audits and audits[0]["action"] == "settlement_confirm"
    assert audits[0]["actor"] == "admin"


def test_confirm_settlement_api_404_when_no_urgency_row(db_session):
    from fastapi import HTTPException
    from routers.emails import confirm_settlement_api

    email = _make_email(db_session)

    try:
        confirm_settlement_api(email.id, user=SimpleNamespace(username="admin"))
        assert False, "expected HTTPException 404"
    except HTTPException as e:
        assert e.status_code == 404


def test_get_email_api_includes_settlement_confirmed(db_session):
    import asyncio
    from routers.emails import api_get_email

    email = _make_email(db_session)
    upsert_urgency(db_session, email.id, {"urgency": "low", "settlement_type": "assistive"})

    out = asyncio.run(api_get_email(email.id, user=SimpleNamespace(username="admin")))
    assert out["settlement_confirmed"] is False

    from database import confirm_settlement
    confirm_settlement(db_session, email.id, "admin")
    out2 = asyncio.run(api_get_email(email.id, user=SimpleNamespace(username="admin")))
    assert out2["settlement_confirmed"] is True


def test_get_email_api_settlement_confirmed_false_when_no_urgency_row(db_session):
    import asyncio
    from routers.emails import api_get_email

    email = _make_email(db_session)

    out = asyncio.run(api_get_email(email.id, user=SimpleNamespace(username="admin")))
    assert out["settlement_confirmed"] is False
