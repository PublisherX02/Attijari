"""New MailboxAccount columns: protocol (default imap) and outbound SMTP relay fields."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import pytest
from database import (
    Base, MailboxAccount, SessionLocal, engine,
    add_mailbox_account, set_mailbox_outbound_smtp, get_mailbox_account,
)
import vault


@pytest.fixture
def db_session():
    from database import _migrate_mailbox_protocol_and_outbound_smtp
    Base.metadata.create_all(bind=engine)
    _migrate_mailbox_protocol_and_outbound_smtp()
    session = SessionLocal()
    ids = []
    session.info["ids"] = ids
    yield session
    session.rollback()
    session.query(MailboxAccount).filter(MailboxAccount.id.in_(ids)).delete(synchronize_session=False)
    session.commit()
    session.close()


def _add(db, email, protocol="imap"):
    row = add_mailbox_account(
        db, email=email, provider="custom", imap_host="mail.example.com", imap_port=993,
        password_encrypted=vault.encrypt_field("app-password"), added_by="admin", protocol=protocol,
    )
    db.info["ids"].append(row.id)
    return row


def test_protocol_defaults_to_imap(db_session):
    row = _add(db_session, "protocol-default@example.com")
    assert row.protocol == "imap"


def test_protocol_can_be_pop3(db_session):
    row = _add(db_session, "protocol-pop3@example.com", protocol="pop3")
    assert row.protocol == "pop3"


def test_outbound_smtp_defaults_to_none(db_session):
    row = _add(db_session, "outbound-default@example.com")
    assert row.smtp_out_host is None
    assert row.smtp_out_port is None
    assert row.smtp_out_password_encrypted is None


def test_set_and_clear_outbound_smtp(db_session):
    row = _add(db_session, "outbound-set@example.com")
    updated = set_mailbox_outbound_smtp(
        db_session, row.id, host="smtp.example.com", port=587,
        user="relay@example.com", password_encrypted=vault.encrypt_field("relay-pass"),
    )
    assert updated.smtp_out_host == "smtp.example.com"
    assert updated.smtp_out_port == 587
    assert vault.decrypt_field(updated.smtp_out_password_encrypted) == "relay-pass"

    cleared = set_mailbox_outbound_smtp(db_session, row.id, host=None, port=None, user=None, password_encrypted=None)
    assert cleared.smtp_out_host is None
    assert cleared.smtp_out_port is None
    assert cleared.smtp_out_user is None
    assert cleared.smtp_out_password_encrypted is None


def test_migration_adds_columns_to_existing_table(monkeypatch):
    """Simulates a pre-existing mailbox_accounts table without the new columns."""
    from sqlalchemy import inspect, text as sa_text
    from database import engine, _migrate_mailbox_protocol_and_outbound_smtp

    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    existing = {c["name"] for c in inspector.get_columns("mailbox_accounts")}
    if "protocol" not in existing:
        pytest.skip("column already absent — nothing to simulate, migration will add it below")

    with engine.begin() as conn:
        conn.execute(sa_text('ALTER TABLE mailbox_accounts DROP COLUMN protocol'))
        conn.execute(sa_text('ALTER TABLE mailbox_accounts DROP COLUMN smtp_out_host'))
        conn.execute(sa_text('ALTER TABLE mailbox_accounts DROP COLUMN smtp_out_port'))
        conn.execute(sa_text('ALTER TABLE mailbox_accounts DROP COLUMN smtp_out_user'))
        conn.execute(sa_text('ALTER TABLE mailbox_accounts DROP COLUMN smtp_out_password_encrypted'))

    _migrate_mailbox_protocol_and_outbound_smtp()

    inspector = inspect(engine)
    existing = {c["name"] for c in inspector.get_columns("mailbox_accounts")}
    assert {"protocol", "smtp_out_host", "smtp_out_port", "smtp_out_user", "smtp_out_password_encrypted"} <= existing
