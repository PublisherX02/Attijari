"""Per-mailbox outbound SMTP relay: reporting.send_smtp_report() can be
handed a mailbox's own relay creds instead of falling back to .env SMTP_*."""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import pytest
from database import Base, MailboxAccount, SessionLocal, engine, add_mailbox_account, set_active_mailbox
import mailboxes
import reporting
import vault


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


def _add_and_activate(db, email):
    row = add_mailbox_account(
        db, email=email, provider="custom", imap_host="mail.example.com", imap_port=993,
        password_encrypted=vault.encrypt_field("app-password"), added_by="admin",
    )
    db.info["ids"].append(row.id)
    set_active_mailbox(db, row.id)
    return row


def test_get_active_mailbox_outbound_smtp_none_when_unconfigured(db_session):
    _add_and_activate(db_session, "outbound-unconfig@example.com")
    assert mailboxes.get_active_mailbox_outbound_smtp(db_session) is None


def test_update_and_get_active_mailbox_outbound_smtp(db_session):
    row = _add_and_activate(db_session, "outbound-configured@example.com")
    mailboxes.update_mailbox_outbound_smtp(
        db_session, row.id, host="smtp.example.com", port=587, user="relay@example.com", password="relay-pass",
    )
    creds = mailboxes.get_active_mailbox_outbound_smtp(db_session)
    assert creds == {"host": "smtp.example.com", "port": 587, "user": "relay@example.com", "password": "relay-pass"}


def test_send_smtp_report_uses_mailbox_override(monkeypatch):
    fake_report = {
        "period": "daily",
        "counts": {"total": 1, "accepted": 1, "escalated": 0, "quarantined": 0, "released": 0, "recu": 0},
        "period_start": "2026-01-01T00:00:00+00:00",
        "period_end": "2026-01-02T00:00:00+00:00",
        "generated_at": "2026-01-02T01:00:00+00:00",
        "top_threats": [],
        "details": [],
    }
    captured = {}

    class FakeSMTPSSL:
        def __init__(self, host, port):
            captured["host"] = host
            captured["port"] = port
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def login(self, user, password):
            captured["user"] = user
            captured["password"] = password
        def send_message(self, msg):
            captured["sent"] = True

    monkeypatch.setattr(reporting.smtplib, "SMTP_SSL", FakeSMTPSSL)
    ok = reporting.send_smtp_report(
        fake_report, recipients=["dest@example.com"],
        mailbox={"host": "smtp.example.com", "port": 587, "user": "relay@example.com", "password": "relay-pass"},
    )
    assert ok is True
    assert captured == {"host": "smtp.example.com", "port": 587, "user": "relay@example.com", "password": "relay-pass", "sent": True}


def test_send_smtp_report_falls_back_to_env_when_mailbox_none(monkeypatch):
    fake_report = {
        "period": "daily",
        "counts": {"total": 1, "accepted": 1, "escalated": 0, "quarantined": 0, "released": 0, "recu": 0},
        "period_start": "2026-01-01T00:00:00+00:00",
        "period_end": "2026-01-02T00:00:00+00:00",
        "generated_at": "2026-01-02T01:00:00+00:00",
        "top_threats": [],
        "details": [],
    }
    monkeypatch.setenv("SMTP_HOST", "env-smtp.example.com")
    monkeypatch.setenv("SMTP_USER", "env-user@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "env-pass")
    captured = {}

    class FakeSMTPSSL:
        def __init__(self, host, port):
            captured["host"] = host
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def login(self, user, password):
            captured["user"] = user
        def send_message(self, msg):
            pass

    monkeypatch.setattr(reporting.smtplib, "SMTP_SSL", FakeSMTPSSL)
    ok = reporting.send_smtp_report(fake_report, recipients=["dest@example.com"], mailbox=None)
    assert ok is True
    assert captured["host"] == "env-smtp.example.com"
    assert captured["user"] == "env-user@example.com"
