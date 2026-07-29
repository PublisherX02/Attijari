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
