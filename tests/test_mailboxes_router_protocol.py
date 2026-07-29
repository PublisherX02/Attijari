"""Router-level tests for the protocol field and outbound-SMTP-relay endpoint."""
import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")

import pytest
from database import Base, MailboxAccount, SessionLocal, engine
from routers import mailboxes as mailboxes_router_mod
import mailboxes as mailboxes_service

ADMIN = SimpleNamespace(username="admin", role="admin", user_id=1)


@pytest.fixture
def db_cleanup():
    Base.metadata.create_all(bind=engine)
    ids = []
    yield ids
    session = SessionLocal()
    session.query(MailboxAccount).filter(MailboxAccount.id.in_(ids)).delete(synchronize_session=False)
    session.commit()
    session.close()


def test_add_endpoint_accepts_pop3_protocol(db_cleanup):
    body = mailboxes_router_mod.TestMailboxRequest(
        email="router-pop3@example.com", provider="custom", password="right",
        host="pop.example.com", port=995, protocol="pop3",
    )
    with patch.object(mailboxes_service, "test_connection", return_value=(True, None)):
        result = asyncio.run(mailboxes_router_mod.api_add_mailbox(body, ADMIN))
    db_cleanup.append(result["mailbox"]["id"])
    assert result["mailbox"]["protocol"] == "pop3"


def test_add_endpoint_rejects_bad_protocol():
    with pytest.raises(Exception):
        mailboxes_router_mod.TestMailboxRequest(
            email="router-badproto@example.com", provider="custom", password="right",
            host="mail.example.com", protocol="smtp",
        )


def test_outbound_smtp_set_then_clear(db_cleanup):
    body = mailboxes_router_mod.TestMailboxRequest(
        email="router-outbound@gmail.com", provider="gmail", password="right",
    )
    with patch.object(mailboxes_service, "test_connection", return_value=(True, None)):
        result = asyncio.run(mailboxes_router_mod.api_add_mailbox(body, ADMIN))
    db_cleanup.append(result["mailbox"]["id"])
    mailbox_id = result["mailbox"]["id"]

    set_body = mailboxes_router_mod.OutboundSmtpRequest(
        host="smtp.example.com", port=587, user="relay@example.com", password="relay-pass",
    )
    outcome = asyncio.run(mailboxes_router_mod.api_set_outbound_smtp(mailbox_id, set_body, ADMIN))
    assert outcome["success"] is True
    assert outcome["mailbox"]["smtp_out_host"] == "smtp.example.com"
    assert "password" not in outcome["mailbox"]

    clear_body = mailboxes_router_mod.OutboundSmtpRequest(host=None, port=None, user=None, password=None)
    cleared = asyncio.run(mailboxes_router_mod.api_set_outbound_smtp(mailbox_id, clear_body, ADMIN))
    assert cleared["mailbox"]["smtp_out_host"] is None
