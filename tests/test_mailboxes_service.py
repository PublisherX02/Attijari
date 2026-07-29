import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import pytest
from database import Base, MailboxAccount, SessionLocal, engine
import mailboxes


@pytest.fixture
def db_session():
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    ids = []
    session.info["ids"] = ids
    yield session
    session.rollback()
    session.query(MailboxAccount).filter(MailboxAccount.id.in_(ids)).delete(synchronize_session=False)
    session.commit()
    session.close()


def test_resolve_host_port_gmail_ignores_custom_host():
    assert mailboxes.resolve_host_port("gmail", host="whatever", port=1234) == ("imap.gmail.com", 993)


def test_resolve_host_port_outlook():
    assert mailboxes.resolve_host_port("outlook", host=None, port=None) == ("outlook.office365.com", 993)


def test_resolve_host_port_custom_requires_host():
    with pytest.raises(ValueError):
        mailboxes.resolve_host_port("custom", host=None, port=None)
    assert mailboxes.resolve_host_port("custom", host="mail.corp.com", port=1993) == ("mail.corp.com", 1993)


def test_add_and_test_mailbox_success(db_session):
    with patch.object(mailboxes, "test_connection", return_value=(True, None)):
        row = mailboxes.add_and_test_mailbox(
            db_session, email="ok@gmail.com", provider="gmail",
            password="app-pw", added_by="admin",
        )
    db_session.info["ids"].append(row.id)
    assert row.status == "verified"
    assert row.password_encrypted != "app-pw"  # encrypted, not plaintext


def test_add_and_test_mailbox_failure_does_not_persist(db_session):
    with patch.object(mailboxes, "test_connection", return_value=(False, "AUTHENTICATIONFAILED")):
        with pytest.raises(ValueError, match="AUTHENTICATIONFAILED"):
            mailboxes.add_and_test_mailbox(
                db_session, email="bad@gmail.com", provider="gmail",
                password="wrong-pw", added_by="admin",
            )
    from database import list_mailbox_accounts
    assert not any(r.email == "bad@gmail.com" for r in list_mailbox_accounts(db_session))


def test_get_active_mailbox_credentials_none_when_unset(db_session):
    assert mailboxes.get_active_mailbox_credentials(db_session) is None


def test_get_active_mailbox_credentials_decrypts_password(db_session):
    with patch.object(mailboxes, "test_connection", return_value=(True, None)):
        row = mailboxes.add_and_test_mailbox(
            db_session, email="creds@outlook.com", provider="outlook",
            password="super-secret", added_by="admin",
        )
    db_session.info["ids"].append(row.id)
    mailboxes.activate_mailbox(db_session, row.id)
    creds = mailboxes.get_active_mailbox_credentials(db_session)
    assert creds == {
        "host": "outlook.office365.com", "user": "creds@outlook.com",
        "port": 993, "password": "super-secret", "protocol": "imap",
    }


def test_deactivate_mailbox_restores_env_fallback(db_session):
    with patch.object(mailboxes, "test_connection", return_value=(True, None)):
        row = mailboxes.add_and_test_mailbox(
            db_session, email="revert@gmail.com", provider="gmail",
            password="app-pw", added_by="admin",
        )
    db_session.info["ids"].append(row.id)
    mailboxes.activate_mailbox(db_session, row.id)
    assert mailboxes.get_active_mailbox_credentials(db_session) is not None

    mailboxes.deactivate_mailbox(db_session)
    assert mailboxes.get_active_mailbox_credentials(db_session) is None

    db_session.refresh(row)
    assert row.is_active is False
    # deactivating doesn't delete anything — the row can be reactivated later
    from database import list_mailbox_accounts
    assert any(r.id == row.id for r in list_mailbox_accounts(db_session))
