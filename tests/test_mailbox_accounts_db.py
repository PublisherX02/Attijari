"""mailbox_accounts: exactly one active row at a time, nothing deleted on switch."""
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
    add_mailbox_account, list_mailbox_accounts, get_active_mailbox,
    set_active_mailbox, delete_mailbox_account, mark_mailbox_tested,
)
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


def _add(db, email, provider="gmail", host="imap.gmail.com", port=993):
    row = add_mailbox_account(
        db, email=email, provider=provider, imap_host=host, imap_port=port,
        password_encrypted=vault.encrypt_field("app-password"), added_by="admin",
    )
    db.info["ids"].append(row.id)
    return row


def test_add_and_list(db_session):
    _add(db_session, "person1@gmail.com")
    _add(db_session, "person2@outlook.com", provider="outlook", host="outlook.office365.com")
    rows = list_mailbox_accounts(db_session)
    emails = {r.email for r in rows}
    assert {"person1@gmail.com", "person2@outlook.com"} <= emails


def test_only_one_active_at_a_time(db_session):
    a = _add(db_session, "activate-a@gmail.com")
    b = _add(db_session, "activate-b@gmail.com")
    set_active_mailbox(db_session, a.id)
    assert get_active_mailbox(db_session).id == a.id
    set_active_mailbox(db_session, b.id)
    active = get_active_mailbox(db_session)
    assert active.id == b.id
    db_session.refresh(a)
    assert a.is_active is False


def test_switching_back_restores_previous_active(db_session):
    a = _add(db_session, "switch-a@gmail.com")
    b = _add(db_session, "switch-b@gmail.com")
    set_active_mailbox(db_session, a.id)
    set_active_mailbox(db_session, b.id)
    set_active_mailbox(db_session, a.id)  # switch back
    assert get_active_mailbox(db_session).id == a.id
    # b's row still exists — nothing was deleted by switching
    assert any(r.id == b.id for r in list_mailbox_accounts(db_session))


def test_cannot_delete_active_mailbox(db_session):
    a = _add(db_session, "delete-me@gmail.com")
    set_active_mailbox(db_session, a.id)
    with pytest.raises(ValueError):
        delete_mailbox_account(db_session, a.id)


def test_mark_tested_updates_status(db_session):
    a = _add(db_session, "test-status@gmail.com")
    mark_mailbox_tested(db_session, a.id, ok=False, error="AUTHENTICATIONFAILED")
    db_session.refresh(a)
    assert a.status == "failed"
    assert "AUTHENTICATIONFAILED" in a.last_test_error
    mark_mailbox_tested(db_session, a.id, ok=True)
    db_session.refresh(a)
    assert a.status == "verified"
    assert a.last_test_error is None


def test_migrate_email_account_column_backfills_legacy_rows(monkeypatch):
    """_migrate_email_account_column must backfill pre-existing NULL rows to
    IMAP_USER when it adds the column — otherwise those rows have no owner
    and (depending on the filter) either vanish or leak everywhere."""
    from sqlalchemy import inspect, text as sa_text
    from database import engine, _migrate_email_account_column, Email

    monkeypatch.setenv("IMAP_USER", "legacy-owner@gmail.com")

    inspector = inspect(engine)
    if "emails" in inspector.get_table_names():
        existing = {c["name"] for c in inspector.get_columns("emails")}
        if "account" in existing:
            pytest.skip("column already present on this DB — backfill path not exercised")

    Base.metadata.create_all(bind=engine)  # creates 'emails' with the account column already
    with engine.begin() as conn:
        conn.execute(sa_text('ALTER TABLE emails DROP COLUMN "account"'))

    session = SessionLocal()
    row = Email(idempotency_key="migrate-test-legacy", raw_sha256="d" * 64,
                sender="legacy@x.com", subject="migrate-test-marker", status="recu")
    session.add(row)
    session.commit()
    row_id = row.id
    session.close()

    try:
        _migrate_email_account_column()
        session = SessionLocal()
        refreshed = session.query(Email).filter(Email.id == row_id).first()
        assert refreshed.account == "legacy-owner@gmail.com"
        session.close()
    finally:
        session = SessionLocal()
        session.query(Email).filter(Email.id == row_id).delete(synchronize_session=False)
        session.commit()
        session.close()


def test_mailboxes_manage_is_admin_only_by_default():
    from database import ALL_PERMISSIONS, ANALYST_PERMISSIONS, VIEWER_PERMISSIONS
    assert "mailboxes.manage" in ALL_PERMISSIONS
    assert "mailboxes.manage" not in ANALYST_PERMISSIONS
    assert "mailboxes.manage" not in VIEWER_PERMISSIONS
