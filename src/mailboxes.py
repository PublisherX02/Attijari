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
    deactivate_all_mailboxes,
    delete_mailbox_account,
    mark_mailbox_tested,
)
from email_extraction import EmailIngestion, Pop3Ingestion
import vault

PROVIDER_PRESETS: dict[str, tuple[str, int]] = {
    "gmail": ("imap.gmail.com", 993),
    "outlook": ("outlook.office365.com", 993),
}


def resolve_host_port(provider: str, host: Optional[str], port: Optional[int],
                      protocol: str = "imap") -> tuple[str, int]:
    """Gmail/Outlook use their fixed IMAP preset regardless of what's passed
    in (these presets are IMAP-only; POP3 mailboxes should use provider
    'custom'). 'custom' requires an explicit host — port defaults to 993 for
    IMAP or 995 for POP3 if omitted."""
    if provider in PROVIDER_PRESETS:
        return PROVIDER_PRESETS[provider]
    if not host:
        raise ValueError("host is required for provider 'custom'")
    default_port = 993 if protocol == "imap" else 995
    return host, port or default_port


def test_connection(host: str, user: str, password: str, port: int = 993,
                    protocol: str = "imap") -> tuple[bool, Optional[str]]:
    """Attempt a real IMAP or POP3 login depending on protocol. Returns (ok, error_message)."""
    if protocol == "pop3":
        ingestion = Pop3Ingestion(host=host, user=user, password=password, port=port)
    else:
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
                         added_by: Optional[str] = None, protocol: str = "imap") -> MailboxAccount:
    """Test the connection FIRST; only persist (with encrypted password) on success."""
    resolved_host, resolved_port = resolve_host_port(provider, host, port, protocol)
    ok, error = test_connection(resolved_host, email, password, resolved_port, protocol)
    if not ok:
        raise ValueError(error or f"{protocol.upper()} connection failed")

    row = add_mailbox_account(
        db, email=email, provider=provider, imap_host=resolved_host,
        imap_port=resolved_port, password_encrypted=vault.encrypt_field(password),
        added_by=added_by, protocol=protocol,
    )
    mark_mailbox_tested(db, row.id, ok=True)
    db.refresh(row)
    return row


def retest_mailbox(db: Session, mailbox_id: int) -> MailboxAccount:
    row = get_mailbox_account(db, mailbox_id)
    if not row:
        raise ValueError(f"Mailbox {mailbox_id} not found")
    password = vault.decrypt_field(row.password_encrypted)
    ok, error = test_connection(row.imap_host, row.email, password, row.imap_port, row.protocol)
    return mark_mailbox_tested(db, mailbox_id, ok=ok, error=error)


def activate_mailbox(db: Session, mailbox_id: int) -> MailboxAccount:
    return set_active_mailbox(db, mailbox_id)


def deactivate_mailbox(db: Session) -> None:
    """No mailbox active -> pipeline falls back to the .env IMAP_* credentials."""
    deactivate_all_mailboxes(db)


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
        "protocol": active.protocol,
    }


def get_active_mailbox_outbound_smtp(db: Session) -> Optional[dict]:
    """Outbound relay creds for the active mailbox, or None if unconfigured
    (caller falls back to .env SMTP_*)."""
    active = get_active_mailbox(db)
    if not active or not active.smtp_out_host:
        return None
    return {
        "host": active.smtp_out_host,
        "port": active.smtp_out_port,
        "user": active.smtp_out_user,
        "password": vault.decrypt_field(active.smtp_out_password_encrypted),
    }


def update_mailbox_outbound_smtp(db: Session, mailbox_id: int, host: Optional[str],
                                 port: Optional[int], user: Optional[str],
                                 password: Optional[str]) -> MailboxAccount:
    """host=None or empty clears the outbound relay config entirely.

    When host is being set (kept/updated) but password is left blank (the API
    never returns stored passwords, so an admin editing e.g. just the port has
    no way to resupply it), the existing encrypted password is preserved
    instead of being wiped. Only an explicit host=None/empty clears everything,
    including the password.
    """
    from database import set_mailbox_outbound_smtp
    host = host or None
    if not host:
        encrypted = None
    elif password:
        encrypted = vault.encrypt_field(password)
    else:
        current = get_mailbox_account(db, mailbox_id)
        encrypted = current.smtp_out_password_encrypted if current else None
    return set_mailbox_outbound_smtp(db, mailbox_id, host=host, port=port, user=user, password_encrypted=encrypted)
