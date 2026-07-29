# Dashboard-Managed Mailbox Accounts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an admin add, test, and select mailboxes (Gmail/Outlook/custom IMAP) from the dashboard's User Management page instead of editing `.env`, with every stored email attributed to the mailbox that fetched it so switching the active mailbox changes what's visible without ever deleting another mailbox's history.

**Architecture:** A new `mailbox_accounts` table (encrypted passwords via the existing `vault.py` Fernet helper) holds one row per configured mailbox with exactly one `is_active=True` at a time. `EmailIngestion` (already provider-agnostic) is reused unchanged for the actual IMAP connection/test. `run_pipeline()` and `gmail_smtp_bridge.py` read credentials from the active mailbox row (falling back to `.env` if none is configured yet, so today's Gmail setup keeps working on deploy day). Every saved `Email` row is stamped with `account` = the active mailbox's email address; dashboard read endpoints filter by the currently active mailbox's address (treating `account IS NULL` rows — pre-migration history — as always visible).

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy (PostgreSQL), `imaplib`/`EmailIngestion` (existing), `vault.py` (Fernet, existing), Jinja2 + vanilla JS dashboard (existing `admin.html` conventions).

## Global Constraints

- Never break the current Gmail polling path: `run_pipeline()` and `gmail_smtp_bridge.py` must keep working exactly as today when `mailbox_accounts` is empty (`.env` fallback).
- Never delete `Email` rows or hide them permanently — switching the active mailbox only changes what a *query* returns; data stays in Postgres.
- Passwords are never stored in plaintext (reuse `vault.encrypt_field`/`decrypt_field`) and never echoed back in any API response after creation.
- Mailbox management is admin-only: new permission `mailboxes.manage`, granted to `admin` implicitly, not added to `ANALYST_PERMISSIONS`/`VIEWER_PERMISSIONS` defaults.
- Follow existing patterns exactly: business logic in a plain module (`src/mailboxes.py`, mirroring `src/routing.py`), thin FastAPI layer in `src/routers/mailboxes.py` (mirroring `src/routers/users.py`), tests as direct function calls against a real Postgres `SessionLocal` with cleanup fixtures (mirroring `tests/test_jwt_revocation.py`), frontend as a plain `<script>` block using the existing `registerAction`/`data-action`/`modal-overlay` conventions in `admin.html`.

---

### Task 1: `EmailIngestion` respects a configurable IMAP port

**Files:**
- Modify: `src/email_extraction.py:69-89`
- Test: `tests/test_email_ingestion_port.py` (new)

**Interfaces:**
- Produces: `EmailIngestion.__init__(self, host, user, password, folder="INBOX", port=993)` — new `port` param, default preserves current behavior. `self.port` attribute used by `connect()`.

Today `EmailIngestion.connect()` calls `imaplib.IMAP4_SSL(self.host, ssl_context=ctx)`, which always uses the default port 993 no matter what — fine for Gmail/Outlook (both 993) but silently wrong for a future "Custom IMAP" mailbox on a non-standard port. Fix this now since Task 3's connection tester depends on it being correct.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_email_ingestion_port.py
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from email_extraction import EmailIngestion


def test_connect_uses_custom_port():
    ingestion = EmailIngestion(host="imap.example.com", user="u", password="p", port=1993)
    with patch("imaplib.IMAP4_SSL") as mock_imap:
        mock_conn = MagicMock()
        mock_imap.return_value = mock_conn
        ingestion.connect()
        args, kwargs = mock_imap.call_args
        assert args[0] == "imap.example.com"
        assert kwargs.get("port", args[1] if len(args) > 1 else None) == 1993


def test_connect_defaults_to_993():
    ingestion = EmailIngestion(host="imap.gmail.com", user="u", password="p")
    with patch("imaplib.IMAP4_SSL") as mock_imap:
        mock_conn = MagicMock()
        mock_imap.return_value = mock_conn
        ingestion.connect()
        args, kwargs = mock_imap.call_args
        assert kwargs.get("port", args[1] if len(args) > 1 else None) == 993
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_email_ingestion_port.py -v`
Expected: FAIL — `TypeError: __init__() got an unexpected keyword argument 'port'`

- [ ] **Step 3: Implement**

In `src/email_extraction.py`, change lines 69-89 from:

```python
    def __init__(self , host: str , user:str , password: str , folder: str = "INBOX" ):
        self.host = host
        self.user = user
        self.password = password
        self.folder = folder
        self.parser = BytesParser(policy = policy.default) #MIME policy rules

    def connect(self):
        print(f"[CONNECT] Connecting to {self.host}...")
        t0 = time.time()
        # Explicit SSL context — enforce certificate verification (CRIT-02)
        ctx = ssl.create_default_context()
        self.conn = imaplib.IMAP4_SSL(self.host, ssl_context=ctx)
```

to:

```python
    def __init__(self , host: str , user:str , password: str , folder: str = "INBOX" , port: int = 993 ):
        self.host = host
        self.user = user
        self.password = password
        self.folder = folder
        self.port = port
        self.parser = BytesParser(policy = policy.default) #MIME policy rules

    def connect(self):
        print(f"[CONNECT] Connecting to {self.host}:{self.port}...")
        t0 = time.time()
        # Explicit SSL context — enforce certificate verification (CRIT-02)
        ctx = ssl.create_default_context()
        self.conn = imaplib.IMAP4_SSL(self.host, port=self.port, ssl_context=ctx)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_email_ingestion_port.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add src/email_extraction.py tests/test_email_ingestion_port.py
git commit -m "feat: EmailIngestion accepts a configurable IMAP port (default 993)"
```

---

### Task 2: `mailbox_accounts` table + `emails.account` column + DB helpers

**Files:**
- Modify: `src/database.py`
- Test: `tests/test_mailbox_accounts_db.py` (new)

**Interfaces:**
- Produces (all in `database.py`):
  - `class MailboxAccount(Base)` — see schema below.
  - `Email.account` column (nullable String(320), indexed).
  - `add_mailbox_account(db, email, provider, imap_host, imap_port, password_encrypted, added_by=None) -> MailboxAccount`
  - `list_mailbox_accounts(db) -> list[MailboxAccount]`
  - `get_mailbox_account(db, mailbox_id) -> Optional[MailboxAccount]`
  - `set_active_mailbox(db, mailbox_id) -> MailboxAccount` — clears every other row's `is_active`, sets this one, raises `ValueError` if `mailbox_id` doesn't exist.
  - `get_active_mailbox(db) -> Optional[MailboxAccount]`
  - `delete_mailbox_account(db, mailbox_id) -> bool` — raises `ValueError` if the row is currently active (must deactivate/activate another first).
  - `mark_mailbox_tested(db, mailbox_id, ok, error=None) -> MailboxAccount` — sets `status="verified"|"failed"`, `last_test_error`, `last_tested_at=utcnow()`.

Add after the `Email` class (after line 117, before `class Blocklist`):

```python
class MailboxAccount(Base):
    """A mailbox the dashboard can poll (replaces hardcoded .env IMAP_* vars).

    Exactly one row has is_active=True at a time — that's the mailbox
    run_pipeline() and gmail_smtp_bridge.py poll next. Every Email row saved
    while a mailbox is active is stamped with that mailbox's address in
    Email.account, so switching which mailbox is active only changes what
    the dashboard *shows* — no email is ever deleted or moved.
    """

    __tablename__ = "mailbox_accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(320), unique=True, nullable=False, index=True)
    provider = Column(String(20), nullable=False, default="custom")  # gmail, outlook, custom
    imap_host = Column(String(255), nullable=False)
    imap_port = Column(Integer, nullable=False, default=993)
    password_encrypted = Column(Text, nullable=False)  # vault.encrypt_field output
    status = Column(String(20), nullable=False, default="untested")  # untested, verified, failed
    last_test_error = Column(Text, nullable=True)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=False, index=True)
    added_by = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
```

Add `account = Column(String(320), nullable=True, index=True)` to the `Email` class, right after `attachment_count` (line 97):

```python
    attachment_count = Column(Integer, default=0)
    account = Column(String(320), nullable=True, index=True)  # mailbox that fetched this email
```

Add a migration function (existing DB already has `emails` without this column) mirroring `_migrate_pending_detonation_manual`, placed after it (~line 449):

```python
def _migrate_email_account_column():
    """One-time: add emails.account for pre-existing rows (NULL = shown under every mailbox)."""
    from sqlalchemy import inspect, text as sa_text
    try:
        inspector = inspect(engine)
        if "emails" not in inspector.get_table_names():
            return
        existing = {c["name"] for c in inspector.get_columns("emails")}
        if "account" not in existing:
            with engine.begin() as conn:
                conn.execute(sa_text('ALTER TABLE emails ADD COLUMN "account" VARCHAR(320)'))
                conn.execute(sa_text('CREATE INDEX IF NOT EXISTS ix_emails_account ON emails ("account")'))
                print("[DB] Added column emails.account")
    except Exception as e:
        print(f"[DB] emails.account migration skipped: {e}")
```

Call it in `init_db()` (~line 509), alongside the other migrations:

```python
    _migrate_users_rbac()
    _migrate_pending_detonation_manual()
    _migrate_encrypt_totp_secrets()
    _migrate_email_account_column()
```

Add the helper functions at the end of the file (after `get_recent_detonation_events`, ~line 943):

```python
# ---------------------------------------------------------------------------
# Mailbox accounts — dashboard-managed IMAP credentials
# ---------------------------------------------------------------------------

def add_mailbox_account(db: Session, email: str, provider: str, imap_host: str,
                        imap_port: int, password_encrypted: str,
                        added_by: Optional[str] = None) -> "MailboxAccount":
    row = MailboxAccount(
        email=email.strip().lower(),
        provider=provider,
        imap_host=imap_host,
        imap_port=imap_port,
        password_encrypted=password_encrypted,
        added_by=added_by,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def list_mailbox_accounts(db: Session) -> list["MailboxAccount"]:
    return db.query(MailboxAccount).order_by(MailboxAccount.created_at.desc()).all()


def get_mailbox_account(db: Session, mailbox_id: int) -> Optional["MailboxAccount"]:
    return db.query(MailboxAccount).filter(MailboxAccount.id == mailbox_id).first()


def get_active_mailbox(db: Session) -> Optional["MailboxAccount"]:
    return db.query(MailboxAccount).filter(MailboxAccount.is_active == True).first()


def set_active_mailbox(db: Session, mailbox_id: int) -> "MailboxAccount":
    target = get_mailbox_account(db, mailbox_id)
    if not target:
        raise ValueError(f"Mailbox {mailbox_id} not found")
    db.query(MailboxAccount).filter(MailboxAccount.is_active == True).update({"is_active": False})
    target.is_active = True
    db.commit()
    db.refresh(target)
    return target


def delete_mailbox_account(db: Session, mailbox_id: int) -> bool:
    target = get_mailbox_account(db, mailbox_id)
    if not target:
        return False
    if target.is_active:
        raise ValueError("Cannot delete the active mailbox — activate a different one first")
    db.delete(target)
    db.commit()
    return True


def mark_mailbox_tested(db: Session, mailbox_id: int, ok: bool,
                        error: Optional[str] = None) -> "MailboxAccount":
    target = get_mailbox_account(db, mailbox_id)
    if not target:
        raise ValueError(f"Mailbox {mailbox_id} not found")
    target.status = "verified" if ok else "failed"
    target.last_test_error = None if ok else (error or "unknown error")[:2000]
    target.last_tested_at = utcnow()
    db.commit()
    db.refresh(target)
    return target
```

- [ ] **Step 1: Write the failing test**

```python
# tests/test_mailbox_accounts_db.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_mailbox_accounts_db.py -v`
Expected: FAIL — `ImportError: cannot import name 'MailboxAccount' from 'database'`

- [ ] **Step 3: Implement** — apply all the `database.py` changes described above (model, `Email.account` column, migration function + call in `init_db()`, six helper functions).

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_mailbox_accounts_db.py -v`
Expected: PASS (5 tests). Requires a reachable `DATABASE_URL` Postgres instance (same requirement as `tests/test_jwt_revocation.py`).

- [ ] **Step 5: Commit**

```bash
git add src/database.py tests/test_mailbox_accounts_db.py
git commit -m "feat: mailbox_accounts table + emails.account column, admin-managed IMAP credentials"
```

---

### Task 3: `mailboxes.manage` RBAC permission

**Files:**
- Modify: `src/database.py:333-353` (`ALL_PERMISSIONS` dict)
- Test: extend `tests/test_mailbox_accounts_db.py` (or a small dedicated test)

**Interfaces:**
- Produces: `"mailboxes.manage"` key in `ALL_PERMISSIONS`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_mailbox_accounts_db.py`:

```python
def test_mailboxes_manage_is_admin_only_by_default():
    from database import ALL_PERMISSIONS, ANALYST_PERMISSIONS, VIEWER_PERMISSIONS
    assert "mailboxes.manage" in ALL_PERMISSIONS
    assert "mailboxes.manage" not in ANALYST_PERMISSIONS
    assert "mailboxes.manage" not in VIEWER_PERMISSIONS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_mailbox_accounts_db.py::test_mailboxes_manage_is_admin_only_by_default -v`
Expected: FAIL — `AssertionError` (key missing)

- [ ] **Step 3: Implement**

In `src/database.py`, add one line to `ALL_PERMISSIONS` (after `"detonation.manual": True,` at line 352):

```python
    "detonation.manual": True,   # upload + detonate an arbitrary file in the sandbox
    "mailboxes.manage": True,    # add/test/activate/delete dashboard-managed mailboxes (admin only)
}
```

Do **not** add it to `ANALYST_PERMISSIONS` or `VIEWER_PERMISSIONS` — admin gets it implicitly via `user_has_permission()`'s role bypass; nobody else does by default (can still be granted per-analyst later through the existing permissions editor with zero code changes).

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_mailbox_accounts_db.py -v`
Expected: PASS (all tests including the new one)

- [ ] **Step 5: Commit**

```bash
git add src/database.py tests/test_mailbox_accounts_db.py
git commit -m "feat: add mailboxes.manage permission (admin-only by default)"
```

---

### Task 4: `src/mailboxes.py` — business logic (connection test, provider presets, add/activate/delete)

**Files:**
- Create: `src/mailboxes.py`
- Test: `tests/test_mailboxes_service.py` (new)

**Interfaces:**
- Consumes: `EmailIngestion(host, user, password, port=993)` (Task 1), `database.add_mailbox_account/list_mailbox_accounts/set_active_mailbox/delete_mailbox_account/mark_mailbox_tested/get_active_mailbox` (Task 2), `vault.encrypt_field/decrypt_field`.
- Produces:
  - `PROVIDER_PRESETS: dict[str, tuple[str, int]]`
  - `resolve_host_port(provider: str, host: str | None, port: int | None) -> tuple[str, int]`
  - `test_connection(host: str, user: str, password: str, port: int = 993) -> tuple[bool, str | None]`
  - `add_and_test_mailbox(db, email, provider, password, host=None, port=None, added_by=None) -> MailboxAccount` — raises `ValueError(error_message)` if the connection test fails; does not persist a row in that case.
  - `retest_mailbox(db, mailbox_id) -> MailboxAccount`
  - `activate_mailbox(db, mailbox_id) -> MailboxAccount`
  - `remove_mailbox(db, mailbox_id) -> bool`
  - `get_active_mailbox_credentials(db) -> dict | None` — `{"host", "user", "port", "password"}` (password decrypted) for the active row, or `None` if no row is active (caller falls back to `.env`).

```python
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
```

- [ ] **Step 1: Write the failing test**

```python
# tests/test_mailboxes_service.py
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
        "port": 993, "password": "super-secret",
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_mailboxes_service.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'mailboxes'`

- [ ] **Step 3: Implement** — create `src/mailboxes.py` exactly as shown above.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_mailboxes_service.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add src/mailboxes.py tests/test_mailboxes_service.py
git commit -m "feat: mailbox service layer — provider presets, test-before-save, active-mailbox credentials"
```

---

### Task 5: `routers/mailboxes.py` — HTTP endpoints

**Files:**
- Create: `src/routers/mailboxes.py`
- Modify: `src/api.py` (register the router)
- Test: `tests/test_mailboxes_router.py` (new)

**Interfaces:**
- Consumes: everything from Task 4 (`mailboxes.py`), `api_core.require_permission`/`AuthenticatedUser` (existing), `database.SessionLocal`/`add_audit_entry` (existing).
- Produces: FastAPI router `mailboxes_router` with:
  - `POST /api/mailboxes/test` — body `{email, provider, password, host?, port?}` → `{ok, error}` (no persistence).
  - `POST /api/mailboxes` — same body → creates + tests atomically (via `add_and_test_mailbox`), returns the row (no password) or 400 with the IMAP error.
  - `GET /api/mailboxes` — list all, no `password_encrypted` field, `is_active` shown.
  - `POST /api/mailboxes/{id}/retest` — re-runs the connection test on stored credentials.
  - `POST /api/mailboxes/{id}/activate` — flips the active row.
  - `DELETE /api/mailboxes/{id}` — 400 if it's the active mailbox.

```python
"""mailboxes.py router — admin-only dashboard mailbox management.

All endpoints require the mailboxes.manage permission (admin by default,
see database.ALL_PERMISSIONS). Passwords are never returned in any response.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from api_core import require_permission, AuthenticatedUser
from database import SessionLocal, add_audit_entry
import mailboxes

mailboxes_router = APIRouter()
_admin_dep = require_permission("mailboxes.manage")


class TestMailboxRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    provider: str = Field(..., pattern=r"^(gmail|outlook|custom)$")
    password: str = Field(..., min_length=1, max_length=512)
    host: Optional[str] = Field(default=None, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)


def _serialize(row) -> dict:
    return {
        "id": row.id,
        "email": row.email,
        "provider": row.provider,
        "imap_host": row.imap_host,
        "imap_port": row.imap_port,
        "status": row.status,
        "last_test_error": row.last_test_error,
        "last_tested_at": row.last_tested_at.isoformat() if row.last_tested_at else None,
        "is_active": row.is_active,
        "added_by": row.added_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@mailboxes_router.post("/api/mailboxes/test")
async def api_test_mailbox(body: TestMailboxRequest, admin: AuthenticatedUser = Depends(_admin_dep)):
    try:
        host, port = mailboxes.resolve_host_port(body.provider, body.host, body.port)
    except ValueError as e:
        raise HTTPException(400, str(e))
    ok, error = mailboxes.test_connection(host, body.email, body.password, port)
    return {"ok": ok, "error": error}


@mailboxes_router.post("/api/mailboxes")
async def api_add_mailbox(body: TestMailboxRequest, admin: AuthenticatedUser = Depends(_admin_dep)):
    db = SessionLocal()
    try:
        try:
            row = mailboxes.add_and_test_mailbox(
                db, email=body.email, provider=body.provider, password=body.password,
                host=body.host, port=body.port, added_by=admin.username,
            )
        except ValueError as e:
            raise HTTPException(400, str(e))

        add_audit_entry(
            db, action="mailbox_add", actor=admin.username,
            details={"email": row.email, "provider": row.provider},
        )
        return {"success": True, "mailbox": _serialize(row)}
    finally:
        db.close()


@mailboxes_router.get("/api/mailboxes")
async def api_list_mailboxes(admin: AuthenticatedUser = Depends(_admin_dep)):
    db = SessionLocal()
    try:
        from database import list_mailbox_accounts
        rows = list_mailbox_accounts(db)
        return {"mailboxes": [_serialize(r) for r in rows]}
    finally:
        db.close()


@mailboxes_router.post("/api/mailboxes/{mailbox_id}/retest")
async def api_retest_mailbox(mailbox_id: int, admin: AuthenticatedUser = Depends(_admin_dep)):
    db = SessionLocal()
    try:
        try:
            row = mailboxes.retest_mailbox(db, mailbox_id)
        except ValueError as e:
            raise HTTPException(404, str(e))
        return {"success": True, "mailbox": _serialize(row)}
    finally:
        db.close()


@mailboxes_router.post("/api/mailboxes/{mailbox_id}/activate")
async def api_activate_mailbox(mailbox_id: int, admin: AuthenticatedUser = Depends(_admin_dep)):
    db = SessionLocal()
    try:
        try:
            row = mailboxes.activate_mailbox(db, mailbox_id)
        except ValueError as e:
            raise HTTPException(404, str(e))

        add_audit_entry(
            db, action="mailbox_activate", actor=admin.username,
            details={"email": row.email, "mailbox_id": mailbox_id},
        )
        return {"success": True, "mailbox": _serialize(row)}
    finally:
        db.close()


@mailboxes_router.delete("/api/mailboxes/{mailbox_id}")
async def api_delete_mailbox(mailbox_id: int, admin: AuthenticatedUser = Depends(_admin_dep)):
    db = SessionLocal()
    try:
        try:
            deleted = mailboxes.remove_mailbox(db, mailbox_id)
        except ValueError as e:
            raise HTTPException(400, str(e))
        if not deleted:
            raise HTTPException(404, "Mailbox not found")

        add_audit_entry(
            db, action="mailbox_delete", actor=admin.username,
            details={"mailbox_id": mailbox_id},
        )
        return {"success": True}
    finally:
        db.close()
```

In `src/api.py`, add the import next to the other router imports (~line 62):

```python
from routers.users import users_router
from routers.mailboxes import mailboxes_router
```

And register it next to `users_router` (~line 226):

```python
app.include_router(users_router, dependencies=[Depends(verify_auth)])
app.include_router(mailboxes_router, dependencies=[Depends(verify_auth)])
```

- [ ] **Step 1: Write the failing test**

```python
# tests/test_mailboxes_router.py
"""Router-level tests: call the endpoint functions directly with a fake
AuthenticatedUser, mirroring the codebase's existing pattern of testing
FastAPI handlers as plain async functions rather than spinning up a TestClient."""
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


def test_add_endpoint_rejects_bad_password(db_cleanup):
    body = mailboxes_router_mod.TestMailboxRequest(
        email="router-fail@gmail.com", provider="gmail", password="wrong",
    )
    with patch.object(mailboxes_service, "test_connection", return_value=(False, "AUTHENTICATIONFAILED")):
        with pytest.raises(Exception) as exc_info:
            asyncio.run(mailboxes_router_mod.api_add_mailbox(body, ADMIN))
    assert "AUTHENTICATIONFAILED" in str(exc_info.value)


def test_add_then_list_then_activate(db_cleanup):
    body = mailboxes_router_mod.TestMailboxRequest(
        email="router-ok@gmail.com", provider="gmail", password="right",
    )
    with patch.object(mailboxes_service, "test_connection", return_value=(True, None)):
        result = asyncio.run(mailboxes_router_mod.api_add_mailbox(body, ADMIN))
    db_cleanup.append(result["mailbox"]["id"])
    assert result["success"] is True
    assert "password" not in result["mailbox"]

    listing = asyncio.run(mailboxes_router_mod.api_list_mailboxes(ADMIN))
    assert any(m["email"] == "router-ok@gmail.com" for m in listing["mailboxes"])

    activated = asyncio.run(mailboxes_router_mod.api_activate_mailbox(result["mailbox"]["id"], ADMIN))
    assert activated["mailbox"]["is_active"] is True


def test_delete_active_mailbox_rejected(db_cleanup):
    body = mailboxes_router_mod.TestMailboxRequest(
        email="router-del@gmail.com", provider="gmail", password="right",
    )
    with patch.object(mailboxes_service, "test_connection", return_value=(True, None)):
        result = asyncio.run(mailboxes_router_mod.api_add_mailbox(body, ADMIN))
    db_cleanup.append(result["mailbox"]["id"])
    asyncio.run(mailboxes_router_mod.api_activate_mailbox(result["mailbox"]["id"], ADMIN))

    with pytest.raises(Exception) as exc_info:
        asyncio.run(mailboxes_router_mod.api_delete_mailbox(result["mailbox"]["id"], ADMIN))
    assert exc_info.value.status_code == 400
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_mailboxes_router.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'routers.mailboxes'`

- [ ] **Step 3: Implement** — create `src/routers/mailboxes.py` (using the corrected `api_list_mailboxes` shown second, not the draft with the dead line) and wire it into `src/api.py` as shown.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_mailboxes_router.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/routers/mailboxes.py src/api.py tests/test_mailboxes_router.py
git commit -m "feat: /api/mailboxes endpoints — add/test/list/retest/activate/delete (admin-only)"
```

---

### Task 6: Pipeline + Gmail bridge read credentials from the active mailbox (`.env` fallback)

**Files:**
- Modify: `src/main.py:143-165` and the two `save_email(...)` call sites (~line 344, ~line 799)
- Modify: `src/gmail_smtp_bridge.py:61-91`
- Test: `tests/test_main_active_mailbox.py` (new)

**Interfaces:**
- Consumes: `mailboxes.get_active_mailbox_credentials(db)` (Task 4).
- Produces: `run_pipeline()` builds `EmailIngestion` from the active mailbox when one exists, else from `.env` (unchanged behavior); every `save_email()` call includes `"account": <mailbox email or None>`.

In `src/main.py`, replace lines 151-155:

```python
    ingestion = EmailIngestion(
        host=os.getenv("IMAP_HOST"),
        user=os.getenv("IMAP_USER"),
        password=os.getenv("IMAP_PASSWORD"),
    )
```

with:

```python
    from mailboxes import get_active_mailbox_credentials
    _active_mailbox = None
    if db:
        try:
            _active_mailbox = get_active_mailbox_credentials(db)
        except Exception as e:
            print(f"[MAILBOX] Failed to load active mailbox, falling back to .env: {e}")

    if _active_mailbox:
        ingestion = EmailIngestion(
            host=_active_mailbox["host"],
            user=_active_mailbox["user"],
            password=_active_mailbox["password"],
            port=_active_mailbox["port"],
        )
        _account_tag = _active_mailbox["user"]
        print(f"[MAILBOX] Using dashboard-configured mailbox: {_account_tag}")
    else:
        ingestion = EmailIngestion(
            host=os.getenv("IMAP_HOST"),
            user=os.getenv("IMAP_USER"),
            password=os.getenv("IMAP_PASSWORD"),
        )
        _account_tag = os.getenv("IMAP_USER")
```

Note this block must run AFTER the existing DB-init block (lines 140-149) since it needs `db`. Move/keep it directly below that block, replacing the old `ingestion = EmailIngestion(...)` at 151-155.

Then add `"account": _account_tag,` to both `save_email(db, {...})` dict literals:
- ~line 344 (auto-quarantine path): add `"account": _account_tag,` alongside the other keys.
- ~line 772 `email_data = {...}` dict: add `"account": _account_tag,` alongside the other keys.

In `src/gmail_smtp_bridge.py`, replace `run_once()` (lines 61-77):

```python
def run_once() -> int:
    """Fetch recent mail from the active mailbox and relay it into the SMTP receiver.
    Returns count relayed."""
    from database import SessionLocal
    from mailboxes import get_active_mailbox_credentials

    db = SessionLocal()
    try:
        active = get_active_mailbox_credentials(db)
    except Exception as e:
        print(f"[MAIL-BRIDGE] Failed to load active mailbox, falling back to .env: {e}")
        active = None
    finally:
        db.close()

    if active:
        host, user, password, port = active["host"], active["user"], active["password"], active["port"]
    else:
        host = os.getenv("IMAP_HOST")
        user = os.getenv("IMAP_USER")
        password = os.getenv("IMAP_PASSWORD")
        port = 993

    rcpt_to = os.getenv("GMAIL_BRIDGE_RCPT_TO") or user or ""
    if not rcpt_to:
        print("[MAIL-BRIDGE] No recipient configured "
              "(set GMAIL_BRIDGE_RCPT_TO, or configure/activate a mailbox in the dashboard) — skipping")
        return 0

    ingestion = EmailIngestion(host=host, user=user, password=password, port=port)
    try:
        ingestion.connect()
    except Exception as e:
        print(f"[MAIL-BRIDGE] IMAP connect failed: {e}")
        return 0

    try:
        raw_emails = ingestion.fetch_recent(since_days=7, limit=50)
    finally:
        try:
            ingestion.disconnect()
        except Exception:
            pass

    relayed = sum(1 for raw in raw_emails if relay_one(raw, rcpt_to))
    if relayed:
        print(f"[MAIL-BRIDGE] Relayed {relayed}/{len(raw_emails)} message(s) into the SMTP receiver")
    return relayed
```

`relay_one` currently reads the module-level `BRIDGE_RCPT_TO` constant, computed once at import time from env — that's now stale the moment a mailbox is added/switched in the dashboard. Change its signature to take the recipient explicitly:

```python
def relay_one(raw: bytes, rcpt_to: str) -> bool:
    """Deliver one raw message to the local inbound SMTP receiver. True on success."""
    try:
        with smtplib.SMTP(SMTP_TARGET_HOST, SMTP_TARGET_PORT, timeout=15) as smtp:
            smtp.sendmail(_extract_from(raw), [rcpt_to], raw)
        return True
    except Exception as e:
        print(f"[MAIL-BRIDGE] Relay failed: {e}")
        return False
```

Remove the now-unused module-level `BRIDGE_RCPT_TO = os.getenv(...)` line (was line 35) — `run_once()` computes it fresh every tick instead. Update `run_forever()`'s log line (was line 94-96) since it referenced the stale constant:

```python
def run_forever() -> None:
    print(f"[MAIL-BRIDGE] Polling every {GMAIL_BRIDGE_INTERVAL}s -> {SMTP_TARGET_HOST}:{SMTP_TARGET_PORT}")
    while True:
        try:
            run_once()
        except Exception as e:
            print(f"[MAIL-BRIDGE] Tick error: {e}")
        time.sleep(GMAIL_BRIDGE_INTERVAL)
```

Also update the module docstring's "Gmail"-specific wording (lines 1-18) to be provider-neutral — e.g. replace "relays real Gmail mail" with "relays real mail from whichever mailbox is configured (dashboard-managed, or .env fallback)" and "polls Mohamed's Gmail over IMAP" with "polls the active mailbox over IMAP". Keep the filename (`gmail_smtp_bridge.py`) unchanged — renaming it would require touching `start.bat`/docs references, which is out of scope; only the docstring/log-prefix wording changes.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_main_active_mailbox.py
"""run_pipeline() must prefer the dashboard-active mailbox and fall back to
.env when none is configured — and must never crash the fallback path if
the mailboxes table/DB lookup itself fails."""
import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import mailboxes


def test_get_active_mailbox_credentials_falls_back_gracefully(monkeypatch):
    # Simulate "no mailbox configured yet" — the exact state on a fresh DB.
    from database import Base, engine, SessionLocal
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        assert mailboxes.get_active_mailbox_credentials(db) is None
    finally:
        db.close()


def test_gmail_bridge_relay_one_uses_explicit_rcpt(monkeypatch):
    import gmail_smtp_bridge as bridge

    captured = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=15):
            captured["host"] = host
            captured["port"] = port
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def sendmail(self, from_addr, to_addrs, raw):
            captured["to_addrs"] = to_addrs

    monkeypatch.setattr(bridge.smtplib, "SMTP", FakeSMTP)
    ok = bridge.relay_one(b"Subject: test\r\n\r\nbody", "explicit@target.com")
    assert ok is True
    assert captured["to_addrs"] == ["explicit@target.com"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_main_active_mailbox.py -v`
Expected: FAIL — `TypeError: relay_one() missing 1 required positional argument: 'rcpt_to'` (bridge test) — confirms the signature hasn't changed yet.

- [ ] **Step 3: Implement** — apply the `main.py` and `gmail_smtp_bridge.py` changes described above.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_main_active_mailbox.py -v`
Expected: PASS (2 tests)

Also run the existing SMTP receiver tests to confirm nothing else regressed:

Run: `python -m pytest tests/test_smtp_receiver.py tests/test_email_extraction_pending.py -v`
Expected: PASS (unchanged — these don't touch the bridge)

- [ ] **Step 5: Commit**

```bash
git add src/main.py src/gmail_smtp_bridge.py tests/test_main_active_mailbox.py
git commit -m "feat: pipeline + mail bridge read the dashboard-active mailbox, fall back to .env"
```

---

### Task 7: Scope dashboard reads (list/detail/stats/export) to the active mailbox

**Files:**
- Modify: `src/routers/emails.py` — `api_list_emails` (~line 127-185), `api_get_email` (~line 189-193), `api_stats` (~line 569-659), `api_export_emails` (~line 698 onward)
- Test: `tests/test_email_account_scoping.py` (new)

**Interfaces:**
- Consumes: `database.get_active_mailbox` (Task 2).
- Produces: `_active_account_filter(db)` in `routers/emails.py` — returns a SQLAlchemy boolean clause (`Email.account == active_email | Email.account.is_(None)`) or `None` if no mailbox is active (meaning: don't filter, matches today's behavior for anyone who hasn't adopted mailboxes yet).

Add this helper near the top of `src/routers/emails.py`, after the existing imports (~line 22, right after `_scan_lock = asyncio.Lock()`):

```python
def _active_account_filter(db):
    """SQLAlchemy filter clause scoping Email queries to the active mailbox,
    or None if no mailbox is configured (no filtering — legacy behavior).
    account IS NULL rows (pre-migration history) are always included so
    nothing that existed before this feature disappears."""
    from database import get_active_mailbox
    from sqlalchemy import or_
    active = get_active_mailbox(db)
    if not active:
        return None
    return or_(Email.account == active.email, Email.account.is_(None))
```

In `api_list_emails` (~line 137), apply it right after the base query is built:

```python
        q = db.query(
            Email.id,
            Email.sender,
            Email.sender_domain,
            Email.subject,
            Email.status,
            Email.attachment_count,
            Email.analyst_action,
            Email.email_date,
            Email.created_at
        ).order_by(Email.email_date.desc().nullslast(), Email.created_at.desc())

        scope = _active_account_filter(db)
        if scope is not None:
            q = q.filter(scope)
```

In `api_get_email` (~line 193), change:

```python
        email = db.query(Email).filter(Email.id == email_id).first()
```

to:

```python
        q = db.query(Email).filter(Email.id == email_id)
        scope = _active_account_filter(db)
        if scope is not None:
            q = q.filter(scope)
        email = q.first()
```

In `api_stats` (~line 577-589), apply the scope to every base query:

```python
        scope = _active_account_filter(db)

        status_q = db.query(Email.status, func.count(Email.id))
        if scope is not None:
            status_q = status_q.filter(scope)
        status_counts = dict(status_q.group_by(Email.status).all())
        total = sum(status_counts.values())

        # Recent activity — last 24 h
        cutoff_24h = utcnow() - timedelta(hours=24)
        recent_q = db.query(Email).filter(Email.created_at >= cutoff_24h)
        if scope is not None:
            recent_q = recent_q.filter(scope)
        recent = recent_q.count()

        # --- Compliance metrics: rolling 30-day window ---
        cutoff_30d = utcnow() - timedelta(days=30)
        base_q = db.query(Email).filter(Email.created_at >= cutoff_30d)
        if scope is not None:
            base_q = base_q.filter(scope)
```

The raw-SQL `avg_conf_row` query (~line 615-624) needs the same scoping. Replace it with:

```python
        from database import get_active_mailbox
        _active = get_active_mailbox(db)
        _account_clause = ""
        _params = {"cutoff": cutoff_30d}
        if _active:
            _account_clause = "AND (account = :active_account OR account IS NULL)"
            _params["active_account"] = _active.email

        avg_conf_row = db.execute(
            text(
                "SELECT AVG((llm_result->>'confiance')::float) "
                "FROM emails "
                "WHERE created_at >= :cutoff "
                "AND llm_result IS NOT NULL "
                "AND llm_result->>'confiance' IS NOT NULL "
                f"{_account_clause}"
            ),
            _params,
        ).scalar()
```

In `api_export_emails` (~line 709), change:

```python
        q = db.query(Email).filter(Email.created_at >= cutoff).order_by(Email.created_at.desc())
```

to:

```python
        q = db.query(Email).filter(Email.created_at >= cutoff).order_by(Email.created_at.desc())
        scope = _active_account_filter(db)
        if scope is not None:
            q = q.filter(scope)
```

- [ ] **Step 1: Write the failing test**

```python
# tests/test_email_account_scoping.py
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
                   sender="a@x.com", subject="From person 1", status="recu",
                   account="p1@gmail.com")
        e2 = Email(idempotency_key="scope-test-e2", raw_sha256="b" * 64,
                   sender="b@x.com", subject="From person 2", status="recu",
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
    result = asyncio.run(emails_router_mod.api_list_emails(user=VIEWER))
    subjects = {e["subject"] for e in result["emails"]}
    assert "From person 1" in subjects
    assert "From person 2" not in subjects


def test_switching_back_restores_the_view(scoped_data):
    set_active_mailbox(scoped_data.db, scoped_data.m1.id)
    set_active_mailbox(scoped_data.db, scoped_data.m2.id)
    result_p2 = asyncio.run(emails_router_mod.api_list_emails(user=VIEWER))
    assert any(e["subject"] == "From person 2" for e in result_p2["emails"])

    set_active_mailbox(scoped_data.db, scoped_data.m1.id)  # switch back
    result_p1 = asyncio.run(emails_router_mod.api_list_emails(user=VIEWER))
    subjects = {e["subject"] for e in result_p1["emails"]}
    assert "From person 1" in subjects
    assert "From person 2" not in subjects  # not deleted, just filtered out


def test_get_email_404s_for_other_mailbox(scoped_data):
    from fastapi import HTTPException
    set_active_mailbox(scoped_data.db, scoped_data.m1.id)
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(emails_router_mod.api_get_email(scoped_data.e2_id, user=VIEWER))
    assert exc_info.value.status_code == 404
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_email_account_scoping.py -v`
Expected: FAIL — emails from both mailboxes show up regardless of active mailbox (no filtering applied yet)

- [ ] **Step 3: Implement** — apply the `routers/emails.py` changes described above (helper + four call sites).

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_email_account_scoping.py -v`
Expected: PASS (3 tests)

Also run the full existing email router test coverage to confirm no regression:

Run: `python -m pytest tests/ -v -k "email or detonation"`
Expected: PASS (all previously-passing tests still pass)

- [ ] **Step 5: Commit**

```bash
git add src/routers/emails.py tests/test_email_account_scoping.py
git commit -m "feat: scope dashboard email list/detail/stats/export to the active mailbox"
```

---

### Task 8: "Mailboxes" section in the dashboard's User Management page

**Files:**
- Modify: `src/dashboard/templates/admin.html`

**Interfaces:**
- Consumes: `/api/mailboxes` (GET/POST/DELETE), `/api/mailboxes/{id}/activate`, `/api/mailboxes/{id}/retest` (Task 5).
- Produces: a new "Mailboxes" card below the existing user table, following the exact same `registerAction`/`data-action`/`modal-overlay` conventions already used in this file for the user CRUD UI (see lines 1-395 of the current file for the pattern this mirrors).

This is UI-only wiring — no new backend contract beyond what Task 5 already returns. Add, right after the closing `</div>` of the existing user table card (after line 28 in the current file) and before the `<!-- Create User Modal -->` comment:

```html
<!-- Mailboxes -->
<div class="page-header" style="margin-top:32px;">
    <h2>Mailboxes</h2>
    <button class="btn btn-primary" data-action="open-add-mailbox-modal">+ Add email</button>
</div>

<div class="card" style="margin-top:20px;">
    <table class="data-table" id="mailboxes-table">
        <thead>
            <tr>
                <th>Email</th>
                <th>Provider</th>
                <th>Status</th>
                <th>Active</th>
                <th>Added by</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody id="mailboxes-body">
            <tr><td colspan="6" style="text-align:center;color:var(--text-muted);">Loading...</td></tr>
        </tbody>
    </table>
</div>

<!-- Add Mailbox Modal -->
<div class="modal-overlay" id="add-mailbox-modal" data-action="backdrop-close" data-close="closeAddMailboxModal">
    <div class="modal" style="max-width:480px;">
        <h3>Add email</h3>
        <div class="form-group">
            <label class="form-label">Email address</label>
            <input class="form-input" id="mailbox-email" type="email" placeholder="person@gmail.com" required>
        </div>
        <div class="form-group">
            <label class="form-label">Provider</label>
            <select class="form-select" id="mailbox-provider" data-change-action="apply-mailbox-provider">
                <option value="gmail">Gmail</option>
                <option value="outlook">Outlook</option>
                <option value="custom">Custom IMAP</option>
            </select>
        </div>
        <div class="form-group" id="mailbox-host-group" style="display:none;">
            <label class="form-label">IMAP host</label>
            <input class="form-input" id="mailbox-host" type="text" placeholder="mail.example.com">
        </div>
        <div class="form-group" id="mailbox-port-group" style="display:none;">
            <label class="form-label">IMAP port</label>
            <input class="form-input" id="mailbox-port" type="number" value="993">
        </div>
        <div class="form-group">
            <label class="form-label">Password (app password)</label>
            <input class="form-input" id="mailbox-password" type="password" required>
        </div>
        <div id="mailbox-test-result" style="margin:8px 0;font-size:0.85rem;"></div>
        <div class="btn-group" style="justify-content:flex-end;margin-top:16px;">
            <button class="btn btn-outline" data-action="close-add-mailbox-modal">Cancel</button>
            <button class="btn btn-outline" data-action="test-mailbox">Test connection</button>
            <button class="btn btn-primary" data-action="save-mailbox">Save</button>
        </div>
    </div>
</div>
```

Add the corresponding JS at the end of the existing `<script>` block, right before the `// Initial load` comment (~line 393 in the current file):

```javascript
// ----- Mailboxes -----
async function loadMailboxes() {
    const res = await fetch('/api/mailboxes');
    if (res.status === 403) { document.getElementById('mailboxes-body').innerHTML =
        '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);">No access</td></tr>'; return; }
    const data = await res.json();
    const tbody = document.getElementById('mailboxes-body');
    if (!data.mailboxes || data.mailboxes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);">No mailboxes added yet — using .env fallback</td></tr>';
        return;
    }
    tbody.innerHTML = data.mailboxes.map(m => {
        const statusBadge = m.status === 'verified'
            ? '<span class="status-badge status-accepted">Verified</span>'
            : m.status === 'failed'
            ? `<span class="status-badge status-quarantined" title="${esc(m.last_test_error || '')}">Failed</span>`
            : '<span class="status-badge" style="background:rgba(149,165,166,0.15);color:#7f8c8d;">Untested</span>';
        const activeBadge = m.is_active
            ? '<span class="status-badge status-accepted">Active</span>'
            : `<button class="btn btn-outline btn-sm" data-action="activate-mailbox" data-id="${m.id}">Select</button>`;
        return `<tr>
            <td><strong>${esc(m.email)}</strong></td>
            <td>${esc(m.provider)}</td>
            <td>${statusBadge}</td>
            <td>${activeBadge}</td>
            <td>${esc(m.added_by || '-')}</td>
            <td>
                <div class="btn-group" style="gap:4px;">
                    <button class="btn btn-outline btn-sm" data-action="retest-mailbox" data-id="${m.id}" title="Re-test">Retest</button>
                    ${!m.is_active ? `<button class="btn btn-outline btn-sm" style="color:#e74c3c;" data-action="delete-mailbox" data-id="${m.id}" data-email="${esc(m.email)}" title="Delete">X</button>` : ''}
                </div>
            </td>
        </tr>`;
    }).join('');
}

function openAddMailboxModal() {
    document.getElementById('mailbox-email').value = '';
    document.getElementById('mailbox-password').value = '';
    document.getElementById('mailbox-provider').value = 'gmail';
    document.getElementById('mailbox-test-result').textContent = '';
    applyMailboxProvider();
    document.getElementById('add-mailbox-modal').classList.add('open');
}
function closeAddMailboxModal() { document.getElementById('add-mailbox-modal').classList.remove('open'); }

function applyMailboxProvider() {
    const provider = document.getElementById('mailbox-provider').value;
    const showCustom = provider === 'custom';
    document.getElementById('mailbox-host-group').style.display = showCustom ? '' : 'none';
    document.getElementById('mailbox-port-group').style.display = showCustom ? '' : 'none';
}

function _mailboxPayload() {
    const provider = document.getElementById('mailbox-provider').value;
    const payload = {
        email: document.getElementById('mailbox-email').value.trim(),
        provider,
        password: document.getElementById('mailbox-password').value,
    };
    if (provider === 'custom') {
        payload.host = document.getElementById('mailbox-host').value.trim();
        payload.port = parseInt(document.getElementById('mailbox-port').value, 10) || 993;
    }
    return payload;
}

async function testMailbox() {
    const payload = _mailboxPayload();
    const resultEl = document.getElementById('mailbox-test-result');
    resultEl.textContent = 'Testing...';
    resultEl.style.color = 'var(--text-muted)';
    const res = await fetch('/api/mailboxes/test', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (data.ok) {
        resultEl.textContent = 'Connection successful';
        resultEl.style.color = '#27ae60';
    } else {
        resultEl.textContent = 'Failed: ' + (data.error || 'unknown error');
        resultEl.style.color = '#e74c3c';
    }
}

async function saveMailbox() {
    const payload = _mailboxPayload();
    if (!payload.email || !payload.password) { alert('Email and password are required'); return; }
    const res = await fetch('/api/mailboxes', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) { alert(data.detail || 'Failed to add mailbox'); return; }
    closeAddMailboxModal();
    loadMailboxes();
}

async function activateMailbox(mailboxId) {
    const res = await fetch(`/api/mailboxes/${mailboxId}/activate`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) { alert(data.detail || 'Failed to activate'); return; }
    loadMailboxes();
}

async function retestMailbox(mailboxId) {
    const res = await fetch(`/api/mailboxes/${mailboxId}/retest`, { method: 'POST' });
    const data = await res.json();
    if (!res.ok) { alert(data.detail || 'Retest failed'); return; }
    loadMailboxes();
}

async function deleteMailbox(mailboxId, email) {
    if (!confirm(`Remove mailbox "${email}"? Its already-fetched emails stay in the system, just no longer selectable as active from this row.`)) return;
    const res = await fetch(`/api/mailboxes/${mailboxId}`, { method: 'DELETE' });
    const data = await res.json();
    if (!res.ok) { alert(data.detail || 'Failed to delete'); return; }
    loadMailboxes();
}

registerAction('open-add-mailbox-modal', () => openAddMailboxModal());
registerAction('close-add-mailbox-modal', () => closeAddMailboxModal());
registerChangeAction('apply-mailbox-provider', () => applyMailboxProvider());
registerAction('test-mailbox', () => testMailbox());
registerAction('save-mailbox', () => saveMailbox());
registerAction('activate-mailbox', (el) => activateMailbox(parseInt(el.dataset.id)));
registerAction('retest-mailbox', (el) => retestMailbox(parseInt(el.dataset.id)));
registerAction('delete-mailbox', (el) => deleteMailbox(parseInt(el.dataset.id), el.dataset.email));

loadMailboxes();
```

- [ ] **Step 1: Manual verification (no automated frontend test harness in this repo — follow existing convention of manual dashboard checks for template changes)**

Start the dashboard (`start.bat` or `python src/main.py --serve`, whichever this project's README/CLAUDE.md documents), log in as admin, navigate to `/admin`, and confirm:
1. A "Mailboxes" card renders below the user table.
2. "+ Add email" opens the modal; selecting "Custom IMAP" reveals host/port fields, Gmail/Outlook hide them.
3. "Test connection" against real or intentionally-wrong credentials shows a pass/fail message inline.
4. Saving a verified mailbox adds a row; "Select" activates it (badge flips to "Active"); adding a second mailbox and selecting it flips the first back to a "Select" button.
5. Deleting a non-active mailbox works; deleting the active one is blocked via the existing `is_active` guard (button is hidden client-side per the template above, and the backend 400s regardless — confirm via a direct DELETE call if you want to double-check the server-side guard, not just the UI hiding).

- [ ] **Step 2: Commit**

```bash
git add src/dashboard/templates/admin.html
git commit -m "feat: Mailboxes section in dashboard User Management — add/test/select/delete"
```

---

### Task 9: `.env.example` documentation update

**Files:**
- Modify: `.env.example:8-14`

**Interfaces:** none (documentation only).

Replace the `--- IMAP ---` block (lines 8-14):

```
# --- IMAP ---
# The pipeline itself no longer reads this directly (see Inbound SMTP below).
# Still used by src/gmail_smtp_bridge.py, which polls this Gmail account and
# relays real mail into the local SMTP receiver — see GMAIL_BRIDGE_* below.
IMAP_HOST=imap.gmail.com
IMAP_USER=your-email@gmail.com
IMAP_PASSWORD=xxxx xxxx xxxx xxxx
```

with:

```
# --- IMAP (fallback only — prefer the dashboard) ---
# As of the mailbox_accounts feature, mailboxes are normally added and
# selected from the dashboard's User Management > Mailboxes section (admin
# only), which tests the connection and stores the password encrypted
# (vault.py). These IMAP_* vars are ONLY used as a fallback when no mailbox
# has been added/activated in the dashboard yet — e.g. right after a fresh
# deploy, before an admin has configured anything. Once a mailbox is active
# in the dashboard, these vars are ignored by both src/main.py and
# src/gmail_smtp_bridge.py.
IMAP_HOST=imap.gmail.com
IMAP_USER=your-email@gmail.com
IMAP_PASSWORD=xxxx xxxx xxxx xxxx
# Outlook: IMAP_HOST=outlook.office365.com (same port, 993). Note Microsoft
# has been retiring basic-auth IMAP for work/school (Exchange Online)
# accounts — app passwords still work for personal outlook.com/hotmail
# accounts with 2FA enabled as of this writing, but verify on the account
# you're using before relying on it.
```

- [ ] **Step 1: Implement** the doc change above.

- [ ] **Step 2: Commit**

```bash
git add .env.example
git commit -m "docs: .env IMAP_* vars are now a fallback — dashboard Mailboxes section is primary"
```

---

## Post-plan verification

Run the full suite once all tasks are committed:

Run: `python -m pytest tests/ -v`
Expected: PASS — all pre-existing tests plus every new test added in Tasks 1–7 (no regressions in the Gmail/SMTP ingestion path, RBAC, or existing email endpoints).
