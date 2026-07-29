"""mailboxes.py — dashboard-managed mailbox accounts (add/test/activate/delete).

Business logic only, no FastAPI here (mirrors routing.py). The HTTP layer
lives in routers/mailboxes.py.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from database import (
    MailboxAccount,
    add_mailbox_account,
    list_mailbox_accounts,
    get_mailbox_account,
    get_active_mailbox,
    set_active_mailbox,
    delete_mailbox_account,
    mark_mailbox_tested,
)
from email_extraction import EmailIngestion
import vault

PROVIDER_PRESETS: dict[str, tuple[str, int]] = {
    "gmail": ("imap.gmail.com", 993),
    "outlook": ("outlook.office365.com", 993),
}


def resolve_host_port(provider: str, host: Optional[str], port: Optional[int]) -> tuple[str, int]:
    """Gmail/Outlook use their fixed preset regardless of what's passed in;
    'custom' requires an explicit host (port defaults to 993 if omitted)."""
    if provider in PROVIDER_PRESETS:
        return PROVIDER_PRESETS[provider]
    if not host:
        raise ValueError("host is required for provider 'custom'")
    return host, port or 993


def test_connection(host: str, user: str, password: str, port: int = 993) -> tuple[bool, Optional[str]]:
    """Attempt a real IMAP login. Returns (ok, error_message)."""
    ingestion = EmailIngestion(host=host, user=user, password=password, port=port)
    try:
        ingestion.connect()
    except Exception as e:
        return False, str(e)[:500]
    finally:
        try:
            ingestion.disconnect()
        except Exception:
            pass
    return True, None


def add_and_test_mailbox(db: Session, email: str, provider: str, password: str,
                         host: Optional[str] = None, port: Optional[int] = None,
                         added_by: Optional[str] = None) -> MailboxAccount:
    """Test the connection FIRST; only persist (with encrypted password) on success."""
    resolved_host, resolved_port = resolve_host_port(provider, host, port)
    ok, error = test_connection(resolved_host, email, password, resolved_port)
    if not ok:
        raise ValueError(error or "IMAP connection failed")

    row = add_mailbox_account(
        db, email=email, provider=provider, imap_host=resolved_host,
        imap_port=resolved_port, password_encrypted=vault.encrypt_field(password),
        added_by=added_by,
    )
    mark_mailbox_tested(db, row.id, ok=True)
    db.refresh(row)
    return row


def retest_mailbox(db: Session, mailbox_id: int) -> MailboxAccount:
    row = get_mailbox_account(db, mailbox_id)
    if not row:
        raise ValueError(f"Mailbox {mailbox_id} not found")
    password = vault.decrypt_field(row.password_encrypted)
    ok, error = test_connection(row.imap_host, row.email, password, row.imap_port)
    return mark_mailbox_tested(db, mailbox_id, ok=ok, error=error)


def activate_mailbox(db: Session, mailbox_id: int) -> MailboxAccount:
    return set_active_mailbox(db, mailbox_id)


def remove_mailbox(db: Session, mailbox_id: int) -> bool:
    return delete_mailbox_account(db, mailbox_id)


def get_active_mailbox_credentials(db: Session) -> Optional[dict]:
    """Credentials for the pipeline to use, or None to fall back to .env."""
    active = get_active_mailbox(db)
    if not active:
        return None
    return {
        "host": active.imap_host,
        "user": active.email,
        "port": active.imap_port,
        "password": vault.decrypt_field(active.password_encrypted),
    }
