"""Switching the active mailbox changes what api_list_emails/api_get_email
return, without deleting the other mailbox's rows."""
import asyncio
import os
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")

import pytest
from database import (
    Base, Email, MailboxAccount, SessionLocal, engine, utcnow,
    add_mailbox_account, set_active_mailbox,
)
import vault
from routers import emails as emails_router_mod

VIEWER = SimpleNamespace(username="viewer", role="admin", user_id=1)


@pytest.fixture
def scoped_data():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    mailbox_ids, email_ids = [], []
    try:
        m1 = add_mailbox_account(db, email="p1@gmail.com", provider="gmail",
                                 imap_host="imap.gmail.com", imap_port=993,
                                 password_encrypted=vault.encrypt_field("x"))
        m2 = add_mailbox_account(db, email="p2@outlook.com", provider="outlook",
                                 imap_host="outlook.office365.com", imap_port=993,
                                 password_encrypted=vault.encrypt_field("x"))
        mailbox_ids += [m1.id, m2.id]

        e1 = Email(idempotency_key="scope-test-e1", raw_sha256="a" * 64,
                   sender="a@x.com", subject="scope-test-marker From person 1", status="recu",
                   account="p1@gmail.com")
        e2 = Email(idempotency_key="scope-test-e2", raw_sha256="b" * 64,
                   sender="b@x.com", subject="scope-test-marker From person 2", status="recu",
                   account="p2@outlook.com")
        db.add_all([e1, e2])
        db.commit()
        email_ids += [e1.id, e2.id]

        yield SimpleNamespace(db=db, m1=m1, m2=m2, e1_id=e1.id, e2_id=e2.id)
    finally:
        db.query(Email).filter(Email.id.in_(email_ids)).delete(synchronize_session=False)
        db.query(MailboxAccount).filter(MailboxAccount.id.in_(mailbox_ids)).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_list_scoped_to_active_mailbox(scoped_data):
    set_active_mailbox(scoped_data.db, scoped_data.m1.id)
    result = asyncio.run(emails_router_mod.api_list_emails(
        status=None, search="scope-test-marker", page=1, per_page=25, user=VIEWER))
    subjects = {e["subject"] for e in result["emails"]}
    assert "scope-test-marker From person 1" in subjects
    assert "scope-test-marker From person 2" not in subjects


def test_switching_back_restores_the_view(scoped_data):
    set_active_mailbox(scoped_data.db, scoped_data.m1.id)
    set_active_mailbox(scoped_data.db, scoped_data.m2.id)
    result_p2 = asyncio.run(emails_router_mod.api_list_emails(
        status=None, search="scope-test-marker", page=1, per_page=25, user=VIEWER))
    assert any(e["subject"] == "scope-test-marker From person 2" for e in result_p2["emails"])

    set_active_mailbox(scoped_data.db, scoped_data.m1.id)  # switch back
    result_p1 = asyncio.run(emails_router_mod.api_list_emails(
        status=None, search="scope-test-marker", page=1, per_page=25, user=VIEWER))
    subjects = {e["subject"] for e in result_p1["emails"]}
    assert "scope-test-marker From person 1" in subjects
    assert "scope-test-marker From person 2" not in subjects  # not deleted, just filtered out


def test_get_email_404s_for_other_mailbox(scoped_data):
    from fastapi import HTTPException
    set_active_mailbox(scoped_data.db, scoped_data.m1.id)
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(emails_router_mod.api_get_email(scoped_data.e2_id, user=VIEWER))
    assert exc_info.value.status_code == 404


def test_null_account_rows_remain_visible_regardless_of_active_mailbox(scoped_data):
    """NULL-account rows have no definite owning mailbox — they can come from
    pre-migration legacy data, or from ingestion that ran with no active
    mailbox and no IMAP_USER set in .env (a supported fallback state). Either
    way, excluding them from every mailbox's view would make them
    permanently invisible (silent data loss) the moment any mailbox is
    activated, which is worse than the small cosmetic cost of showing them
    in every mailbox's view. So a NULL-account row must remain visible no
    matter which mailbox is active."""
    legacy = Email(idempotency_key="scope-test-legacy", raw_sha256="c" * 64,
                    sender="legacy@x.com", subject="scope-test-marker legacy NULL row",
                    status="recu", account=None)
    scoped_data.db.add(legacy)
    scoped_data.db.commit()
    try:
        set_active_mailbox(scoped_data.db, scoped_data.m1.id)
        result = asyncio.run(emails_router_mod.api_list_emails(
            status=None, search="scope-test-marker", page=1, per_page=25, user=VIEWER))
        subjects = {e["subject"] for e in result["emails"]}
        assert "scope-test-marker legacy NULL row" in subjects

        set_active_mailbox(scoped_data.db, scoped_data.m2.id)
        result2 = asyncio.run(emails_router_mod.api_list_emails(
            status=None, search="scope-test-marker", page=1, per_page=25, user=VIEWER))
        subjects2 = {e["subject"] for e in result2["emails"]}
        assert "scope-test-marker legacy NULL row" in subjects2
    finally:
        scoped_data.db.query(Email).filter(Email.id == legacy.id).delete(synchronize_session=False)
        scoped_data.db.commit()


def test_email_ingested_with_no_active_mailbox_stays_visible_after_activation(scoped_data):
    """Finding 2 scenario: an ingest ran with no dashboard mailbox active and
    no IMAP_USER configured in .env, so the email was saved with
    account=None (see main.py's `_account_tag = os.getenv("IMAP_USER")`
    fallback). That row must not vanish once an admin later activates a
    mailbox in the dashboard."""
    orphan = Email(idempotency_key="scope-test-orphan", raw_sha256="d" * 64,
                   sender="orphan@x.com", subject="scope-test-marker orphaned ingest row",
                   status="recu", account=None)
    scoped_data.db.add(orphan)
    scoped_data.db.commit()
    try:
        # No mailbox active yet at ingest time; now an admin activates one.
        set_active_mailbox(scoped_data.db, scoped_data.m1.id)
        result = asyncio.run(emails_router_mod.api_list_emails(
            status=None, search="scope-test-marker", page=1, per_page=25, user=VIEWER))
        subjects = {e["subject"] for e in result["emails"]}
        assert "scope-test-marker orphaned ingest row" in subjects
    finally:
        scoped_data.db.query(Email).filter(Email.id == orphan.id).delete(synchronize_session=False)
        scoped_data.db.commit()
