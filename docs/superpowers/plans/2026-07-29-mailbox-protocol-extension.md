# Mailbox Protocol Extension (POP3 + Outbound SMTP Relay) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add POP3 as a second inbound polling protocol for dashboard-managed mailboxes, and let each mailbox carry its own outbound SMTP relay credentials so scheduled reports can send through a specific mailbox instead of the single global `.env` `SMTP_*` config.

**Architecture:** `MailboxAccount` gains a `protocol` column (`imap`/`pop3`) and four nullable outbound-relay columns. A new `Pop3Ingestion` class mirrors `EmailIngestion`'s interface. A new `pop3_smtp_bridge.py` mirrors `gmail_smtp_bridge.py`, each guarding on `protocol` so exactly one bridge acts on the active mailbox. `reporting.send_smtp_report()` gains an optional `mailbox` override param.

**Tech Stack:** Python 3.12, SQLAlchemy, `poplib` (stdlib), FastAPI, existing `vault.py` (Fernet) for credential encryption.

## Global Constraints

- Follow the existing additive-migration idiom (see `_migrate_email_account_column` in `src/database.py`) — never destructive `ALTER`/backfill-required migrations.
- Passwords are never returned in any API response (existing rule for `password_encrypted`; applies identically to `smtp_out_password_encrypted`).
- Router tests call endpoint functions directly as plain async functions with a fake `AuthenticatedUser` (no `TestClient`) — see `tests/test_mailboxes_router.py`.
- DB tests use the real configured `DATABASE_URL` (via `Base.metadata.create_all`), not sqlite/mocks — see `tests/test_mailbox_accounts_db.py`'s `db_session`/`db_cleanup` fixture pattern; always track created row IDs and delete them in teardown.
- Every test file needs the `VAULT_ENCRYPTION_KEY` bootstrap boilerplate at the top (copy verbatim from `tests/test_mailbox_accounts_db.py:8-10`) and `sys.path.insert(0, str(Path(__file__).parent.parent / "src"))`.

---

### Task 0: Commit existing uncommitted WIP (mailbox deactivate feature)

This is finished, already-tested, unrelated work sitting uncommitted in the working tree — commit it as its own change before starting new work so it doesn't get tangled with the protocol-extension diff.

**Files:** all currently modified files per `git status` (`src/dashboard/templates/admin.html`, `src/database.py`, `src/mailboxes.py`, `src/routers/emails.py`, `src/routers/mailboxes.py`, `tests/test_email_account_scoping.py`, `tests/test_mailbox_accounts_db.py`, `tests/test_mailboxes_router.py`, `tests/test_mailboxes_service.py`).

- [ ] **Step 1: Run the full mailbox-related test suite to confirm the WIP is green**

Run: `python -m pytest tests/test_email_account_scoping.py tests/test_mailbox_accounts_db.py tests/test_mailboxes_router.py tests/test_mailboxes_service.py tests/test_main_active_mailbox.py -q`
Expected: all pass (this was already verified: 22 passed, 1 skipped, plus `test_main_active_mailbox.py`).

- [ ] **Step 2: Commit**

```bash
git add src/dashboard/templates/admin.html src/database.py src/mailboxes.py src/routers/emails.py src/routers/mailboxes.py tests/test_email_account_scoping.py tests/test_mailbox_accounts_db.py tests/test_mailboxes_router.py tests/test_mailboxes_service.py
git commit -m "feat: mailbox deactivate endpoint restores .env fallback"
```

Leave `"Trust_No_Email (1) (1) (1).pdf"`, `docs/presentation/`, and `secflow-report-job-112.html` untouched — they're unrelated untracked files, not part of this work.

---

### Task 1: Schema — `protocol` + outbound-relay columns on `MailboxAccount`

**Files:**
- Modify: `src/database.py` (`MailboxAccount` class ~line 120-144, `add_mailbox_account` ~line 1008, `init_db` ~line 559-568, new migration function, new outbound-smtp setter/getter)
- Test: `tests/test_mailbox_protocol_schema.py` (new)

**Interfaces:**
- Produces: `MailboxAccount.protocol` (str, default `"imap"`), `MailboxAccount.smtp_out_host` (str|None), `MailboxAccount.smtp_out_port` (int, default 465), `MailboxAccount.smtp_out_user` (str|None), `MailboxAccount.smtp_out_password_encrypted` (str|None).
- Produces: `add_mailbox_account(db, email, provider, imap_host, imap_port, password_encrypted, added_by=None, protocol="imap") -> MailboxAccount`.
- Produces: `set_mailbox_outbound_smtp(db, mailbox_id, host, port, user, password_encrypted) -> MailboxAccount` — passing `host=None` clears all four outbound columns to `None`.
- Produces: `_migrate_mailbox_protocol_and_outbound_smtp()` — additive `ALTER TABLE`, called from `init_db()`.

- [ ] **Step 1: Write the failing schema/migration test**

```python
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
    Base.metadata.create_all(bind=engine)
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_mailbox_protocol_schema.py -q`
Expected: FAIL — `add_mailbox_account() got an unexpected keyword argument 'protocol'` (or `ImportError: cannot import name 'set_mailbox_outbound_smtp'`).

- [ ] **Step 3: Add the columns to `MailboxAccount`**

In `src/database.py`, inside the `MailboxAccount` class (after the existing `is_active` line, before `added_by`):

```python
    protocol = Column(String(10), nullable=False, default="imap")  # imap, pop3 — which bridge polls this mailbox
    smtp_out_host = Column(String(255), nullable=True)   # outbound relay; NULL = not configured, falls back to .env SMTP_*
    smtp_out_port = Column(Integer, nullable=True, default=465)
    smtp_out_user = Column(String(320), nullable=True)
    smtp_out_password_encrypted = Column(Text, nullable=True)
```

- [ ] **Step 4: Update `add_mailbox_account` to accept `protocol`**

Replace the existing function:

```python
def add_mailbox_account(db: Session, email: str, provider: str, imap_host: str,
                        imap_port: int, password_encrypted: str,
                        added_by: Optional[str] = None, protocol: str = "imap") -> "MailboxAccount":
    row = MailboxAccount(
        email=email.strip().lower(),
        provider=provider,
        imap_host=imap_host,
        imap_port=imap_port,
        password_encrypted=password_encrypted,
        added_by=added_by,
        protocol=protocol,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row
```

- [ ] **Step 5: Add `set_mailbox_outbound_smtp`**

Add directly below `mark_mailbox_tested` in `src/database.py`:

```python
def set_mailbox_outbound_smtp(db: Session, mailbox_id: int, host: Optional[str],
                              port: Optional[int], user: Optional[str],
                              password_encrypted: Optional[str]) -> "MailboxAccount":
    """host=None clears the whole outbound relay config back to 'not configured'."""
    target = get_mailbox_account(db, mailbox_id)
    if not target:
        raise ValueError(f"Mailbox {mailbox_id} not found")
    target.smtp_out_host = host
    target.smtp_out_port = port if host else None
    target.smtp_out_user = user if host else None
    target.smtp_out_password_encrypted = password_encrypted if host else None
    db.commit()
    db.refresh(target)
    return target
```

- [ ] **Step 6: Add the migration function and register it in `init_db()`**

Add directly below `_migrate_email_account_column` in `src/database.py`:

```python
def _migrate_mailbox_protocol_and_outbound_smtp():
    """One-time: add mailbox_accounts.protocol (default 'imap') and the four
    nullable outbound-SMTP-relay columns. All additive — existing rows get
    protocol='imap' (correct, since IMAP was the only option before this) and
    NULL outbound fields (correct 'not configured' state)."""
    from sqlalchemy import inspect, text as sa_text
    try:
        inspector = inspect(engine)
        if "mailbox_accounts" not in inspector.get_table_names():
            return
        existing = {c["name"] for c in inspector.get_columns("mailbox_accounts")}
        with engine.begin() as conn:
            if "protocol" not in existing:
                conn.execute(sa_text(
                    "ALTER TABLE mailbox_accounts ADD COLUMN protocol VARCHAR(10) NOT NULL DEFAULT 'imap'"
                ))
                print("[DB] Added column mailbox_accounts.protocol")
            if "smtp_out_host" not in existing:
                conn.execute(sa_text('ALTER TABLE mailbox_accounts ADD COLUMN smtp_out_host VARCHAR(255)'))
                conn.execute(sa_text('ALTER TABLE mailbox_accounts ADD COLUMN smtp_out_port INTEGER'))
                conn.execute(sa_text('ALTER TABLE mailbox_accounts ADD COLUMN smtp_out_user VARCHAR(320)'))
                conn.execute(sa_text('ALTER TABLE mailbox_accounts ADD COLUMN smtp_out_password_encrypted TEXT'))
                print("[DB] Added mailbox_accounts outbound SMTP relay columns")
    except Exception as e:
        print(f"[DB] mailbox protocol/outbound-smtp migration skipped: {e}")
```

In `init_db()`, add the call alongside the other migrations:

```python
    _migrate_email_account_column()
    _migrate_mailbox_protocol_and_outbound_smtp()
```

- [ ] **Step 7: Run test to verify it passes**

Run: `python -m pytest tests/test_mailbox_protocol_schema.py -q`
Expected: PASS (5 tests; the migration test may `SKIP` if columns already exist fresh from the model — that's fine, it means `Base.metadata.create_all` already covers it).

- [ ] **Step 8: Run the full existing mailbox suite to check nothing broke**

Run: `python -m pytest tests/test_mailbox_accounts_db.py tests/test_mailboxes_router.py tests/test_mailboxes_service.py tests/test_main_active_mailbox.py -q`
Expected: all still pass (the new `protocol` param has a default, so existing call sites are unaffected).

- [ ] **Step 9: Commit**

```bash
git add src/database.py tests/test_mailbox_protocol_schema.py
git commit -m "feat: add protocol and outbound-SMTP-relay columns to MailboxAccount"
```

---

### Task 2: `Pop3Ingestion` class

**Files:**
- Modify: `src/email_extraction.py` (add `import poplib` near the top with the other stdlib imports, add class after `EmailIngestion`)
- Test: `tests/test_pop3_ingestion.py` (new)

**Interfaces:**
- Consumes: nothing new (stdlib `poplib`, `ssl` — already imported in this file).
- Produces: `Pop3Ingestion(host, user, password, port=995)` with `.connect()`, `.disconnect()`, `.fetch_recent(since_days=7, limit=50) -> list[bytes]`, matching `EmailIngestion`'s call signature exactly so bridge code can use either interchangeably.

- [ ] **Step 1: Write the failing tests**

```python
"""Pop3Ingestion mirrors EmailIngestion's interface (connect/disconnect/fetch_recent)
but over POP3 instead of IMAP — for mailboxes that don't offer IMAP."""
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from email_extraction import Pop3Ingestion


def _raw_message(subject: str, date: datetime) -> bytes:
    date_str = date.strftime("%a, %d %b %Y %H:%M:%S +0000")
    return f"Subject: {subject}\r\nDate: {date_str}\r\n\r\nbody".encode()


def test_connect_uses_pop3_ssl_with_explicit_context():
    ing = Pop3Ingestion(host="pop.example.com", user="a@example.com", password="pw", port=995)
    with patch("email_extraction.poplib.POP3_SSL") as mock_pop3_ssl:
        mock_conn = MagicMock()
        mock_pop3_ssl.return_value = mock_conn
        ing.connect()
        _, kwargs = mock_pop3_ssl.call_args
        assert mock_pop3_ssl.call_args[0][0] == "pop.example.com"
        assert kwargs.get("context") is not None
        mock_conn.user.assert_called_once_with("a@example.com")
        mock_conn.pass_.assert_called_once_with("pw")


def test_disconnect_calls_quit():
    ing = Pop3Ingestion(host="pop.example.com", user="a@example.com", password="pw")
    ing.conn = MagicMock()
    ing.disconnect()
    ing.conn.quit.assert_called_once()


def test_connect_failure_propagates():
    ing = Pop3Ingestion(host="pop.example.com", user="a@example.com", password="wrong")
    with patch("email_extraction.poplib.POP3_SSL") as mock_pop3_ssl:
        mock_conn = MagicMock()
        mock_conn.pass_.side_effect = Exception("-ERR authentication failed")
        mock_pop3_ssl.return_value = mock_conn
        try:
            ing.connect()
            assert False, "expected exception"
        except Exception as e:
            assert "authentication failed" in str(e)


def test_fetch_recent_filters_by_date_and_limit():
    ing = Pop3Ingestion(host="pop.example.com", user="a@example.com", password="pw")
    ing.conn = MagicMock()
    now = datetime.now(timezone.utc)
    messages = {
        1: _raw_message("old", now - timedelta(days=30)),
        2: _raw_message("recent-1", now - timedelta(days=1)),
        3: _raw_message("recent-2", now - timedelta(hours=2)),
    }
    ing.conn.list.return_value = (b"+OK", [f"{i} 100".encode() for i in messages], 0)
    ing.conn.retr.side_effect = lambda i: (b"+OK", [line.encode() for line in messages[i].decode().splitlines()], len(messages[i]))

    result = ing.fetch_recent(since_days=7, limit=50)
    assert len(result) == 2
    assert all(b"recent" in r for r in result)


def test_fetch_recent_respects_limit():
    ing = Pop3Ingestion(host="pop.example.com", user="a@example.com", password="pw")
    ing.conn = MagicMock()
    now = datetime.now(timezone.utc)
    messages = {i: _raw_message(f"msg{i}", now - timedelta(minutes=i)) for i in range(1, 6)}
    ing.conn.list.return_value = (b"+OK", [f"{i} 100".encode() for i in messages], 0)
    ing.conn.retr.side_effect = lambda i: (b"+OK", [line.encode() for line in messages[i].decode().splitlines()], len(messages[i]))

    result = ing.fetch_recent(since_days=7, limit=2)
    assert len(result) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_pop3_ingestion.py -q`
Expected: FAIL with `ImportError: cannot import name 'Pop3Ingestion'`.

- [ ] **Step 3: Implement `Pop3Ingestion`**

Add `import poplib` to the top of `src/email_extraction.py` alongside `import imaplib`. Then add the class after `EmailIngestion` (after its `fetch_pending_smtp` method, before any module-level functions that follow):

```python
class Pop3Ingestion:
    """Mirrors EmailIngestion's public interface (connect/disconnect/fetch_recent)
    for mailboxes that only offer POP3, not IMAP.

    Two behavioral differences from EmailIngestion, both safe:
    - No PEEK equivalent: POP3's RETR has no no-mark-read option. This does
      NOT threaten repeated-poll safety — that guarantee lives entirely in
      the SMTP receiver's SHA-256 content dedup (see gmail_smtp_bridge.py),
      not in the source protocol. Re-relaying an already-seen message via
      POP3 is still a no-op downstream.
    - No server-side date search: POP3's LIST only gives sequence numbers,
      not dates. Filtering by since_days happens client-side after parsing
      each message's Date header.
    """
    def __init__(self, host: str, user: str, password: str, port: int = 995):
        self.host = host
        self.user = user
        self.password = password
        self.port = port
        self.parser = BytesParser(policy=policy.default)

    def connect(self):
        ctx = ssl.create_default_context()
        self.conn = poplib.POP3_SSL(self.host, port=self.port, context=ctx)
        self.conn.user(self.user)
        self.conn.pass_(self.password)

    def disconnect(self):
        self.conn.quit()

    def fetch_recent(self, since_days: int = 7, limit: int = 50) -> list[bytes]:
        cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
        _, listing, _ = self.conn.list()
        msg_nums = [int(line.decode().split()[0]) for line in listing]

        candidates = []
        for num in msg_nums:
            _, lines, _ = self.conn.retr(num)
            raw = b"\r\n".join(lines)
            if len(raw) > MAX_EMAIL_SIZE:
                continue
            msg = self.parser.parsebytes(raw)
            date_header = msg.get("Date")
            try:
                msg_date = email.utils.parsedate_to_datetime(date_header) if date_header else None
                if msg_date and msg_date.tzinfo is None:
                    msg_date = msg_date.replace(tzinfo=timezone.utc)
            except Exception:
                msg_date = None
            if msg_date is None or msg_date >= cutoff:
                candidates.append((msg_date or cutoff, raw))

        candidates.sort(key=lambda pair: pair[0], reverse=True)
        return [raw for _, raw in candidates[:limit]]
```

Add `timezone` to the existing `from datetime import datetime, timedelta` import (change to `from datetime import datetime, timedelta, timezone`), and confirm `import email` is present at the top (it already is, per the module's existing `from email import policy` — add a bare `import email` if not already there, since `email.utils.parsedate_to_datetime` needs the parent package imported).

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_pop3_ingestion.py -q`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/email_extraction.py tests/test_pop3_ingestion.py
git commit -m "feat: add Pop3Ingestion class mirroring EmailIngestion for POP3 mailboxes"
```

---

### Task 3: POP3 bridge + protocol-guard on both bridges

**Files:**
- Create: `src/pop3_smtp_bridge.py`
- Modify: `src/gmail_smtp_bridge.py` (add protocol guard to `run_once()`)
- Modify: `src/mailboxes.py` (`get_active_mailbox_credentials` must include `protocol` in its returned dict)
- Test: `tests/test_pop3_smtp_bridge.py` (new), extend `tests/test_main_active_mailbox.py`

**Interfaces:**
- Consumes: `Pop3Ingestion` (Task 2), `mailboxes.get_active_mailbox_credentials(db)` now returning `{"host", "user", "port", "password", "protocol"}`.
- Produces: `pop3_smtp_bridge.run_once() -> int` (relayed count), `pop3_smtp_bridge.run_forever()`, importing and reusing `gmail_smtp_bridge.relay_one`.

- [ ] **Step 1: Update `get_active_mailbox_credentials` to include `protocol`**

In `src/mailboxes.py`:

```python
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
```

- [ ] **Step 2: Write the failing bridge-guard test (extends `test_main_active_mailbox.py`)**

Add to `tests/test_main_active_mailbox.py`:

```python
def test_gmail_bridge_skips_when_active_mailbox_is_pop3(monkeypatch):
    import gmail_smtp_bridge as bridge
    import database
    import mailboxes

    # gmail_smtp_bridge.run_once() does `from database import SessionLocal` and
    # `from mailboxes import get_active_mailbox_credentials` as LOCAL imports
    # inside the function body, re-resolved from these modules at call time —
    # patch the source modules' attributes, not `bridge.SessionLocal` /
    # `bridge.get_active_mailbox_credentials` (those names are never read).
    monkeypatch.setattr(
        mailboxes, "get_active_mailbox_credentials",
        lambda db: {"host": "pop.example.com", "user": "a@example.com", "port": 995, "password": "pw", "protocol": "pop3"},
    )

    class FakeSessionLocal:
        def __call__(self):
            return self
        def close(self):
            pass
    monkeypatch.setattr(database, "SessionLocal", FakeSessionLocal())

    with patch("email_extraction.EmailIngestion.connect") as mock_connect:
        result = bridge.run_once()
        mock_connect.assert_not_called()
    assert result == 0
```

Note this test imports `patch` — add `from unittest.mock import patch` to the top of `tests/test_main_active_mailbox.py` if not already present (it currently only imports `patch` — check first; the existing file already has `from unittest.mock import patch` at line 7, so no change needed there).

Also write the new bridge's own test file:

```python
"""pop3_smtp_bridge mirrors gmail_smtp_bridge but only acts when the active
mailbox's protocol is 'pop3' — never double-relays a mailbox both bridges
could otherwise see."""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

import database
import mailboxes

# pop3_smtp_bridge.run_once() does `from database import SessionLocal` and
# `from mailboxes import get_active_mailbox_credentials` as LOCAL imports
# inside the function body, re-resolved from these modules at call time —
# every test below patches database.SessionLocal / mailboxes.get_active_mailbox_credentials
# directly, never `bridge.SessionLocal` / `bridge.get_active_mailbox_credentials`
# (those attributes are never read by the function).


class FakeSessionLocal:
    def __call__(self):
        return self
    def close(self):
        pass


def test_skips_when_no_active_mailbox(monkeypatch):
    import pop3_smtp_bridge as bridge

    monkeypatch.setattr(database, "SessionLocal", FakeSessionLocal())
    monkeypatch.setattr(mailboxes, "get_active_mailbox_credentials", lambda db: None)

    assert bridge.run_once() == 0


def test_skips_when_active_mailbox_is_imap(monkeypatch):
    import pop3_smtp_bridge as bridge

    monkeypatch.setattr(database, "SessionLocal", FakeSessionLocal())
    monkeypatch.setattr(
        mailboxes, "get_active_mailbox_credentials",
        lambda db: {"host": "imap.gmail.com", "user": "a@gmail.com", "port": 993, "password": "pw", "protocol": "imap"},
    )

    with patch("pop3_smtp_bridge.Pop3Ingestion") as mock_pop3:
        result = bridge.run_once()
        mock_pop3.assert_not_called()
    assert result == 0


def test_relays_pop3_mailbox_mail(monkeypatch):
    import pop3_smtp_bridge as bridge

    monkeypatch.setattr(database, "SessionLocal", FakeSessionLocal())
    monkeypatch.setattr(
        mailboxes, "get_active_mailbox_credentials",
        lambda db: {"host": "pop.example.com", "user": "a@example.com", "port": 995, "password": "pw", "protocol": "pop3"},
    )

    fake_ingestion = MagicMock()
    fake_ingestion.fetch_recent.return_value = [b"Subject: t\r\n\r\nbody"]
    monkeypatch.setattr(bridge, "Pop3Ingestion", lambda **kwargs: fake_ingestion)

    with patch.object(bridge, "relay_one", return_value=True) as mock_relay:
        relayed = bridge.run_once()
        mock_relay.assert_called_once()
    assert relayed == 1
    fake_ingestion.connect.assert_called_once()
    fake_ingestion.disconnect.assert_called_once()
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/test_pop3_smtp_bridge.py tests/test_main_active_mailbox.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'pop3_smtp_bridge'`.

- [ ] **Step 4: Add the protocol guard to `gmail_smtp_bridge.run_once()`**

In `src/gmail_smtp_bridge.py`, at the top of `run_once()` (right after `active = get_active_mailbox_credentials(db)` resolves, before the `if active:`/`else:` host/user/password block):

```python
    if active and active.get("protocol") == "pop3":
        print("[MAIL-BRIDGE] Active mailbox is POP3 — skipping (handled by pop3_smtp_bridge)")
        return 0
```

- [ ] **Step 5: Create `src/pop3_smtp_bridge.py`**

```python
"""pop3_smtp_bridge.py — relays mail from a POP3-only active mailbox into the
local inbound SMTP receiver. Structural mirror of gmail_smtp_bridge.py, but
guards the opposite way: only acts when the active mailbox's protocol is
'pop3'. gmail_smtp_bridge.py carries the matching guard so exactly one
bridge ever acts on the active mailbox at a time.
"""
from __future__ import annotations

import os
import time

from email_extraction import Pop3Ingestion
from gmail_smtp_bridge import relay_one, SMTP_TARGET_HOST, SMTP_TARGET_PORT

POP3_BRIDGE_INTERVAL = int(os.getenv("POP3_BRIDGE_INTERVAL_SECONDS", "60"))


def run_once() -> int:
    """Fetch recent mail from the active mailbox over POP3 and relay it into
    the SMTP receiver. Returns count relayed. No-op unless the active
    mailbox's protocol is 'pop3'."""
    from database import SessionLocal
    from mailboxes import get_active_mailbox_credentials

    db = SessionLocal()
    try:
        active = get_active_mailbox_credentials(db)
    except Exception as e:
        print(f"[POP3-BRIDGE] Failed to load active mailbox: {e}")
        active = None
    finally:
        db.close()

    if not active or active.get("protocol") != "pop3":
        return 0

    host, user, password, port = active["host"], active["user"], active["password"], active["port"]
    rcpt_to = os.getenv("GMAIL_BRIDGE_RCPT_TO") or user

    ingestion = Pop3Ingestion(host=host, user=user, password=password, port=port)
    try:
        ingestion.connect()
    except Exception as e:
        print(f"[POP3-BRIDGE] POP3 connect failed: {e}")
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
        print(f"[POP3-BRIDGE] Relayed {relayed}/{len(raw_emails)} message(s) into the SMTP receiver")
    return relayed


def run_forever() -> None:
    print(f"[POP3-BRIDGE] Polling every {POP3_BRIDGE_INTERVAL}s -> {SMTP_TARGET_HOST}:{SMTP_TARGET_PORT}")
    while True:
        try:
            run_once()
        except Exception as e:
            print(f"[POP3-BRIDGE] Tick error: {e}")
        time.sleep(POP3_BRIDGE_INTERVAL)


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    run_forever()
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `python -m pytest tests/test_pop3_smtp_bridge.py tests/test_main_active_mailbox.py -q`
Expected: PASS.

- [ ] **Step 7: Run the full mailbox/bridge suite**

Run: `python -m pytest tests/test_mailbox_accounts_db.py tests/test_mailboxes_router.py tests/test_mailboxes_service.py tests/test_main_active_mailbox.py tests/test_pop3_ingestion.py tests/test_pop3_smtp_bridge.py tests/test_mailbox_protocol_schema.py -q`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add src/mailboxes.py src/gmail_smtp_bridge.py src/pop3_smtp_bridge.py tests/test_pop3_smtp_bridge.py tests/test_main_active_mailbox.py
git commit -m "feat: add pop3_smtp_bridge, mutual protocol guard with gmail_smtp_bridge"
```

---

### Task 4: Outbound SMTP relay wiring — `reporting.py` + `mailboxes.get_active_mailbox_outbound_smtp`

**Files:**
- Modify: `src/reporting.py` (`send_smtp_report`)
- Modify: `src/mailboxes.py` (new `get_active_mailbox_outbound_smtp`, new `update_mailbox_outbound_smtp`)
- Test: `tests/test_mailbox_outbound_smtp.py` (new)

**Interfaces:**
- Consumes: `database.set_mailbox_outbound_smtp` (Task 1), `vault.encrypt_field`/`decrypt_field`.
- Produces: `mailboxes.get_active_mailbox_outbound_smtp(db) -> dict | None` (`{"host", "port", "user", "password"}` or `None`).
- Produces: `mailboxes.update_mailbox_outbound_smtp(db, mailbox_id, host, port, user, password) -> MailboxAccount` — `host=None`/empty clears the config.
- Produces: `reporting.send_smtp_report(report, recipients=None, mailbox=None) -> bool` — `mailbox` overrides `.env` `SMTP_*` reads when provided.

- [ ] **Step 1: Write the failing tests**

```python
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
    fake_report = {"period": "daily", "counts": {"total": 1, "accepted": 1, "escalated": 0, "quarantined": 0}}
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
    fake_report = {"period": "daily", "counts": {"total": 1, "accepted": 1, "escalated": 0, "quarantined": 0}}
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_mailbox_outbound_smtp.py -q`
Expected: FAIL — `AttributeError: module 'mailboxes' has no attribute 'get_active_mailbox_outbound_smtp'`.

- [ ] **Step 3: Add `get_active_mailbox_outbound_smtp` and `update_mailbox_outbound_smtp` to `src/mailboxes.py`**

```python
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
    """host=None or empty clears the outbound relay config entirely."""
    from database import set_mailbox_outbound_smtp
    host = host or None
    encrypted = vault.encrypt_field(password) if (host and password) else None
    return set_mailbox_outbound_smtp(db, mailbox_id, host=host, port=port, user=user, password_encrypted=encrypted)
```

- [ ] **Step 4: Update `send_smtp_report` in `src/reporting.py`**

Replace the function signature and the top credential-resolution block:

```python
def send_smtp_report(report: dict, recipients: Optional[list[str]] = None, mailbox: Optional[dict] = None) -> bool:
    """Send the report as an HTML email via SMTP. `mailbox`, if given, is
    {host, port, user, password} for a dashboard-configured mailbox's own
    outbound relay — overrides the .env SMTP_* fallback."""
    if mailbox:
        smtp_host = mailbox["host"]
        smtp_port = mailbox["port"]
        smtp_user = mailbox["user"]
        smtp_pass = mailbox["password"]
    else:
        smtp_host = os.getenv("SMTP_HOST")
        smtp_port = int(os.getenv("SMTP_PORT", "465"))
        smtp_user = os.getenv("SMTP_USER")
        smtp_pass = os.getenv("SMTP_PASSWORD")
```

(The rest of the function body is unchanged — it already just uses `smtp_host`/`smtp_port`/`smtp_user`/`smtp_pass`.)

- [ ] **Step 5: Wire the resolved mailbox into the scheduled-report call site**

The only call site is `src/reporting.py:366`, inside `generate_and_deliver()`:

```python
    # SMTP
    if send_smtp_report(report):
        delivered.append("smtp")
```

Replace it with:

```python
    # SMTP
    from database import SessionLocal
    from mailboxes import get_active_mailbox_outbound_smtp
    _db = SessionLocal()
    try:
        _outbound = get_active_mailbox_outbound_smtp(_db)
    finally:
        _db.close()
    if send_smtp_report(report, mailbox=_outbound):
        delivered.append("smtp")
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `python -m pytest tests/test_mailbox_outbound_smtp.py -q`
Expected: PASS (4 tests).

- [ ] **Step 7: Run the full reporting + mailbox suites**

Run: `python -m pytest tests/test_mailbox_outbound_smtp.py tests/test_mailbox_accounts_db.py tests/test_mailboxes_router.py tests/test_mailboxes_service.py -q`
Expected: all pass. Also run any existing `tests/test_reporting*.py` if present (`ls tests | grep report`) to confirm the unchanged-call-path tests still pass.

- [ ] **Step 8: Commit**

```bash
git add src/mailboxes.py src/reporting.py tests/test_mailbox_outbound_smtp.py
git commit -m "feat: per-mailbox outbound SMTP relay for scheduled reports"
```

---

### Task 5: Router — protocol field on add/test, `PATCH /api/mailboxes/{id}/outbound-smtp`

**Files:**
- Modify: `src/routers/mailboxes.py`
- Modify: `src/mailboxes.py` (`resolve_host_port`, `test_connection`, `add_and_test_mailbox`, `retest_mailbox` need a `protocol` parameter)
- Test: `tests/test_mailboxes_router_protocol.py` (new)

**Interfaces:**
- Consumes: `Pop3Ingestion` (Task 2), `mailboxes.update_mailbox_outbound_smtp`/`get_active_mailbox_outbound_smtp` (Task 4).
- Produces: `TestMailboxRequest.protocol: str` (default `"imap"`, pattern `^(imap|pop3)$`).
- Produces: `POST /api/mailboxes/{id}/outbound-smtp` request body `OutboundSmtpRequest{host, port, user, password}`; response `{"success": True, "mailbox": {...}}`.

- [ ] **Step 1: Update `resolve_host_port`, `test_connection`, `add_and_test_mailbox`, `retest_mailbox` in `src/mailboxes.py`**

```python
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
```

Add `from email_extraction import EmailIngestion, Pop3Ingestion` (update the existing single-class import at the top of `src/mailboxes.py`).

- [ ] **Step 2: Write the failing router tests**

```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/test_mailboxes_router_protocol.py -q`
Expected: FAIL — `TypeError: __init__() got an unexpected keyword argument 'protocol'`.

- [ ] **Step 4: Update `TestMailboxRequest`, `_serialize`, `api_add_mailbox`, add `OutboundSmtpRequest` + endpoint in `src/routers/mailboxes.py`**

```python
class TestMailboxRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    provider: str = Field(..., pattern=r"^(gmail|outlook|custom)$")
    password: str = Field(..., min_length=1, max_length=512)
    host: Optional[str] = Field(default=None, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    protocol: str = Field(default="imap", pattern=r"^(imap|pop3)$")


class OutboundSmtpRequest(BaseModel):
    host: Optional[str] = Field(default=None, max_length=255)
    port: Optional[int] = Field(default=465, ge=1, le=65535)
    user: Optional[str] = Field(default=None, max_length=320)
    password: Optional[str] = Field(default=None, max_length=512)


def _serialize(row) -> dict:
    return {
        "id": row.id,
        "email": row.email,
        "provider": row.provider,
        "protocol": row.protocol,
        "imap_host": row.imap_host,
        "imap_port": row.imap_port,
        "status": row.status,
        "last_test_error": row.last_test_error,
        "last_tested_at": row.last_tested_at.isoformat() if row.last_tested_at else None,
        "is_active": row.is_active,
        "added_by": row.added_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "smtp_out_host": row.smtp_out_host,
        "smtp_out_port": row.smtp_out_port,
        "smtp_out_user": row.smtp_out_user,
    }
```

Update `api_test_mailbox` and `api_add_mailbox` to pass `protocol`:

```python
@mailboxes_router.post("/api/mailboxes/test")
async def api_test_mailbox(body: TestMailboxRequest, admin: AuthenticatedUser = Depends(_admin_dep)):
    try:
        host, port = mailboxes.resolve_host_port(body.provider, body.host, body.port, body.protocol)
    except ValueError as e:
        raise HTTPException(400, str(e))
    ok, error = mailboxes.test_connection(host, body.email, body.password, port, body.protocol)
    return {"ok": ok, "error": error}


@mailboxes_router.post("/api/mailboxes")
async def api_add_mailbox(body: TestMailboxRequest, admin: AuthenticatedUser = Depends(_admin_dep)):
    db = SessionLocal()
    try:
        try:
            row = mailboxes.add_and_test_mailbox(
                db, email=body.email, provider=body.provider, password=body.password,
                host=body.host, port=body.port, added_by=admin.username, protocol=body.protocol,
            )
        except ValueError as e:
            raise HTTPException(400, str(e))

        add_audit_entry(
            db, action="mailbox_add", actor=admin.username,
            details={"email": row.email, "provider": row.provider, "protocol": row.protocol},
        )
        return {"success": True, "mailbox": _serialize(row)}
    finally:
        db.close()
```

Add the new endpoint (near `api_delete_mailbox`):

```python
@mailboxes_router.post("/api/mailboxes/{mailbox_id}/outbound-smtp")
async def api_set_outbound_smtp(mailbox_id: int, body: OutboundSmtpRequest,
                                admin: AuthenticatedUser = Depends(_admin_dep)):
    db = SessionLocal()
    try:
        try:
            row = mailboxes.update_mailbox_outbound_smtp(
                db, mailbox_id, host=body.host, port=body.port, user=body.user, password=body.password,
            )
        except ValueError as e:
            raise HTTPException(404, str(e))

        add_audit_entry(
            db, action="mailbox_outbound_smtp_update", actor=admin.username,
            details={"mailbox_id": mailbox_id, "configured": bool(body.host)},
        )
        return {"success": True, "mailbox": _serialize(row)}
    finally:
        db.close()
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_mailboxes_router_protocol.py -q`
Expected: PASS (3 tests).

- [ ] **Step 6: Run the full router/mailbox/bridge suite**

Run: `python -m pytest tests/test_mailbox_accounts_db.py tests/test_mailboxes_router.py tests/test_mailboxes_router_protocol.py tests/test_mailboxes_service.py tests/test_main_active_mailbox.py tests/test_pop3_ingestion.py tests/test_pop3_smtp_bridge.py tests/test_mailbox_protocol_schema.py tests/test_mailbox_outbound_smtp.py -q`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/mailboxes.py src/routers/mailboxes.py tests/test_mailboxes_router_protocol.py
git commit -m "feat: protocol field on mailbox add/test, outbound-smtp router endpoint"
```

---

### Task 6: Dashboard UI — protocol selector + outbound relay section

**Files:**
- Modify: `src/dashboard/templates/admin.html`

No automated test for this task (it's template/JS markup) — verify manually per the Step below.

- [ ] **Step 1: Add the protocol selector to the add-mailbox modal**

In `src/dashboard/templates/admin.html`, inside `#add-mailbox-modal`, immediately after the existing provider `<select>` block (around line 67-72), add:

```html
<div class="form-group">
    <label>Protocol</label>
    <select class="form-select" id="mailbox-protocol" data-change-action="apply-mailbox-provider">
        <option value="imap" selected>IMAP</option>
        <option value="pop3">POP3</option>
    </select>
</div>
```

- [ ] **Step 2: Update `applyMailboxProvider()` and `_mailboxPayload()` to read/send protocol and adjust the default port**

Replace `applyMailboxProvider()` (around line 506-511):

```javascript
function applyMailboxProvider() {
    const provider = document.getElementById('mailbox-provider').value;
    const protocol = document.getElementById('mailbox-protocol').value;
    const showCustom = provider === 'custom';
    document.getElementById('mailbox-host-group').style.display = showCustom ? '' : 'none';
    document.getElementById('mailbox-port-group').style.display = showCustom ? '' : 'none';
    if (showCustom) {
        document.getElementById('mailbox-port').value = protocol === 'pop3' ? '995' : '993';
    }
}
```

Replace `_mailboxPayload()` (around line 513-523):

```javascript
function _mailboxPayload() {
    const provider = document.getElementById('mailbox-provider').value;
    const payload = {
        email: document.getElementById('mailbox-email').value.trim(),
        provider,
        password: document.getElementById('mailbox-password').value,
        protocol: document.getElementById('mailbox-protocol').value,
    };
    if (provider === 'custom') {
        payload.host = document.getElementById('mailbox-host').value.trim();
        payload.port = parseInt(document.getElementById('mailbox-port').value, 10) || 993;
    }
    return payload;
}
```

Reset the protocol selector in `openAddMailboxModal()` (around line 497-502):

```javascript
document.getElementById('mailbox-protocol').value = 'imap';
```

(Add this line alongside the existing `mailbox-email`/`mailbox-password`/`mailbox-provider` resets.)

- [ ] **Step 3: Add a "Protocol" column to the mailboxes table and an "Outbound relay" action**

In the `#mailboxes-table` header (around line 40-51), add a `<th>Protocol</th>` column. In the `tbody.innerHTML = data.mailboxes.map(...)` row template (around line 471-489), add a `<td>${m.protocol.toUpperCase()}</td>` cell, and add a row action button:

```html
<button class="btn btn-outline btn-sm" data-action="open-outbound-smtp-modal" data-id="${m.id}" title="Configure outbound relay">Relay</button>
```

- [ ] **Step 4: Add the outbound-relay modal + JS**

Add a new modal near `#add-mailbox-modal`:

```html
<div class="modal-overlay" id="outbound-smtp-modal" data-action="backdrop-close" data-close="closeOutboundSmtpModal">
    <div class="modal-box">
        <h3>Outbound relay (optional)</h3>
        <p style="font-size:0.85rem;color:var(--text-muted);">Used to send scheduled reports through this mailbox's own SMTP server instead of the default .env relay. Leave host blank to clear.</p>
        <div class="form-group">
            <label>SMTP host</label>
            <input class="form-input" id="outbound-smtp-host" type="text" placeholder="smtp.example.com">
        </div>
        <div class="form-group">
            <label>SMTP port</label>
            <input class="form-input" id="outbound-smtp-port" type="number" value="465">
        </div>
        <div class="form-group">
            <label>SMTP user</label>
            <input class="form-input" id="outbound-smtp-user" type="text">
        </div>
        <div class="form-group">
            <label>SMTP password</label>
            <input class="form-input" id="outbound-smtp-password" type="password">
        </div>
        <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px;">
            <button class="btn btn-outline" data-action="close-outbound-smtp-modal">Cancel</button>
            <button class="btn btn-primary" data-action="save-outbound-smtp">Save</button>
        </div>
    </div>
</div>
```

Add JS near the other mailbox functions:

```javascript
let _outboundSmtpMailboxId = null;

function openOutboundSmtpModal(mailboxId) {
    _outboundSmtpMailboxId = mailboxId;
    document.getElementById('outbound-smtp-host').value = '';
    document.getElementById('outbound-smtp-port').value = '465';
    document.getElementById('outbound-smtp-user').value = '';
    document.getElementById('outbound-smtp-password').value = '';
    document.getElementById('outbound-smtp-modal').classList.add('open');
}
function closeOutboundSmtpModal() { document.getElementById('outbound-smtp-modal').classList.remove('open'); }

async function saveOutboundSmtp() {
    const payload = {
        host: document.getElementById('outbound-smtp-host').value.trim() || null,
        port: parseInt(document.getElementById('outbound-smtp-port').value, 10) || 465,
        user: document.getElementById('outbound-smtp-user').value.trim() || null,
        password: document.getElementById('outbound-smtp-password').value || null,
    };
    const res = await fetch(`/api/mailboxes/${_outboundSmtpMailboxId}/outbound-smtp`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) { alert(data.detail || 'Failed to save outbound relay'); return; }
    closeOutboundSmtpModal();
    loadMailboxes();
}

registerAction('open-outbound-smtp-modal', (el) => openOutboundSmtpModal(parseInt(el.dataset.id, 10)));
registerAction('close-outbound-smtp-modal', () => closeOutboundSmtpModal());
registerAction('save-outbound-smtp', () => saveOutboundSmtp());
```

(Match the exact `registerAction`/`data-action` dispatch pattern already used for the other mailbox buttons — confirm the helper signature by reading how `data-id` is read for `activate-mailbox`/`delete-mailbox` in the existing code, and mirror it exactly.)

- [ ] **Step 5: Manually verify in the browser**

Start the app (`start.bat` or equivalent), open `/admin`, go to Mailboxes:
- Add a mailbox with Protocol=POP3, provider=custom — confirm the port field defaults to 995 when switching protocol.
- Confirm the table shows a Protocol column.
- Click "Relay" on an existing mailbox, fill in outbound fields, Save — confirm no error and the modal closes.
- Reopen "Relay" on the same mailbox — confirm previously-saved non-secret fields are reflected if you choose to prefill them (optional; the plan above resets fields to blank on open, which is acceptable since passwords are never returned).

- [ ] **Step 6: Commit**

```bash
git add src/dashboard/templates/admin.html
git commit -m "feat: dashboard UI for mailbox protocol selection and outbound relay config"
```

---

### Task 7: Start `pop3_smtp_bridge` alongside `gmail_smtp_bridge` in `src/api.py`

**Files:**
- Modify: `src/api.py`

- [ ] **Step 1: Add the POP3 bridge background task**

In `src/api.py`, alongside the existing `_gmail_bridge_task`/`_gmail_bridge_poll` block (around line 142-166):

```python
_pop3_bridge_task = None
POP3_BRIDGE_ENABLED = os.getenv("POP3_BRIDGE_ENABLED", "1") != "0"
POP3_BRIDGE_INTERVAL = int(os.getenv("POP3_BRIDGE_INTERVAL_SECONDS", "60"))

async def _pop3_bridge_poll():
    await asyncio.sleep(5)
    from pop3_smtp_bridge import run_once as _pop3_bridge_run_once
    while True:
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _pop3_bridge_run_once)
        except Exception as e:
            print(f"[POP3-BRIDGE] Tick error: {e}")
        await asyncio.sleep(POP3_BRIDGE_INTERVAL)
```

In `startup()` (around line 190-207), add alongside the existing `if GMAIL_BRIDGE_ENABLED:` block:

```python
    global _pop3_bridge_task
    if POP3_BRIDGE_ENABLED:
        _pop3_bridge_task = asyncio.create_task(_pop3_bridge_poll())
        print(f"[POP3-BRIDGE] Started (every {POP3_BRIDGE_INTERVAL}s)")
```

(Add `_pop3_bridge_task` to the existing `global` statement at the top of `startup()` rather than a second `global` line, and add the corresponding cancellation in `shutdown()` alongside `_gmail_bridge_task`.)

- [ ] **Step 2: Verify the app starts cleanly**

Run: `python -m pytest tests/ -q -k "not slow"` (full suite) to confirm nothing broke from the `api.py` import-time changes.
Expected: same pass count as Task 6's final baseline, no new failures.

Also manually confirm the app boots (`start.bat` or `python src/main.py --serve`) and the console shows both `[GMAIL-BRIDGE] Started` and `[POP3-BRIDGE] Started` lines.

- [ ] **Step 3: Commit**

```bash
git add src/api.py
git commit -m "feat: start pop3_smtp_bridge background task alongside gmail_smtp_bridge"
```

---

## Final verification

- [ ] Run the complete test suite: `python -m pytest tests/ -q`
- [ ] Confirm the previously-noted baseline (126 passed per the CLAUDE.md build log, plus all new tests from this plan) — no regressions, no unexplained skips beyond the pre-existing one in `test_mailboxes_service.py`.
- [ ] Update CLAUDE.md's Build Log with a dated entry summarizing what shipped (per this project's own convention of logging builds/fixes there).
