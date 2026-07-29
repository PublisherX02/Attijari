# Dashboard-managed mailbox accounts

**Date:** 2026-07-29
**Status:** approved for planning

## Problem

Today the single mailbox the pipeline polls is hardcoded in `.env`
(`IMAP_HOST`/`IMAP_USER`/`IMAP_PASSWORD`), read by `EmailIngestion` in
`src/main.py` and by `src/gmail_smtp_bridge.py`. Switching to a different
person's mailbox means editing `.env` and restarting — not something an
analyst can do from the dashboard, and no per-mailbox history separation:
every stored `Email` row looks the same regardless of which mailbox it came
from.

Two things are needed:

1. Add and test mailbox credentials (Gmail, Outlook, or custom IMAP) from
   the dashboard instead of `.env`.
2. Every stored email is attributed to the mailbox that fetched it, and the
   dashboard only shows the currently-selected mailbox's emails — switching
   never deletes another mailbox's history, switching back restores the view.

## Non-goals

- OAuth2 login flow (Exchange Online / work-tenant accounts requiring it are
  out of scope; provider dropdown covers Gmail/Outlook/Custom IMAP with a
  password or app password).
- Polling multiple mailboxes concurrently. Exactly one mailbox is "active"
  at a time; the pipeline only ever polls that one (confirmed with the
  user — simpler background worker, matches "operator chooses which boîte
  d'email he wants to see").
- Non-admin access. Managing mailboxes is admin-only for now.
- Rewriting `reporting.py`'s outbound SMTP (unrelated — that's for sending
  reports, not receiving mail).

## Data model

New table `mailbox_accounts` in `src/database.py`, following the existing
model conventions in that file:

```python
class MailboxAccount(Base):
    __tablename__ = "mailbox_accounts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(320), unique=True, nullable=False, index=True)
    provider = Column(String(20), nullable=False)  # gmail, outlook, custom
    imap_host = Column(String(255), nullable=False)
    imap_port = Column(Integer, nullable=False, default=993)
    password_encrypted = Column(Text, nullable=False)  # vault.encrypt_field
    status = Column(String(20), nullable=False, default="untested")
    # untested, verified, failed
    last_test_error = Column(Text, nullable=True)
    last_tested_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=False)
    added_by = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
```

Invariant: at most one row has `is_active = True`. Enforced in the
`set_active_mailbox()` helper (clear all, then set the target in the same
transaction) rather than a DB constraint, to keep "zero active mailboxes"
representable (falls back to `.env`, see below).

`emails.account` (String, nullable, indexed) — added to the existing
`Email` model. Stores the **email address** of the mailbox active at fetch
time (not an FK to `mailbox_accounts.id`), because a mailbox row can be
deleted later while its historical emails must remain viewable. Existing
rows get `account = NULL` on migration and are treated as visible under
every mailbox filter (see Filtering below), so history that predates this
feature never "disappears."

Password encryption reuses `vault.encrypt_field` / `vault.decrypt_field`
(`src/vault.py`), the same Fernet-based helper already used for TOTP
secrets — no new crypto code.

## Connection testing

`POST /api/mailboxes/test` accepts `{email, provider, imap_host, imap_port,
password}` (not yet saved) and attempts:

```python
EmailIngestion(host=imap_host, user=email, password=password).connect()
```
then immediately disconnects. Reuses `src/email_extraction.py`'s existing
`EmailIngestion.connect()` unchanged — same TLS/timeout behavior as the
production fetch path, so "test passed" means "the real pipeline can log in
too." Returns `{ok: true}` or `{ok: false, error: "..."}` (IMAP error
message, truncated — never leak the password back).

Saving a mailbox (`POST /api/mailboxes`) runs the same test server-side
before persisting; a mailbox can only be saved with `status="verified"`.
Re-testing an existing mailbox is `POST /api/mailboxes/{id}/test`, which
updates `status`/`last_test_error`/`last_tested_at` in place.

## Provider presets (dashboard form)

| Provider | imap_host             | imap_port |
|----------|------------------------|-----------|
| Gmail    | imap.gmail.com          | 993       |
| Outlook  | outlook.office365.com   | 993       |
| Custom   | (user-entered)          | (user-entered, default 993) |

Selecting Gmail/Outlook fills and locks `imap_host`/`imap_port`; Custom
exposes both fields for editing. This is what makes Outlook "supported" —
no provider-specific code path, just a preset plus the existing
provider-agnostic `EmailIngestion`.

## RBAC

New permission `mailboxes.manage` added to `ALL_PERMISSIONS` in
`src/database.py`, **not** added to `ANALYST_PERMISSIONS` or
`VIEWER_PERMISSIONS` — admin has it implicitly (same bypass rule as
`users.manage`), nobody else does by default. All `/api/mailboxes/*`
endpoints gate on `require_permission("mailboxes.manage")`, mirroring
`src/routers/users.py`'s `_admin_dep` pattern.

## Pipeline integration

`run_pipeline()` (`src/main.py`) and `src/gmail_smtp_bridge.py` both
currently build `EmailIngestion(host=IMAP_HOST, user=IMAP_USER,
password=IMAP_PASSWORD)` straight from env. Both switch to a shared helper,
e.g. `get_active_mailbox_credentials(db)` in `src/database.py`:

- If a `mailbox_accounts` row has `is_active = True`: return its
  `email`/`imap_host`/`imap_port`/decrypted password.
- Else: fall back to `.env` `IMAP_HOST`/`IMAP_USER`/`IMAP_PASSWORD` (so
  today's Gmail setup keeps working unmodified until it's "adopted" into
  the new table — nothing breaks on deploy day).

Every email saved via `save_email()` in this run gets `account=<that
mailbox's email address>` stamped on it (both call sites in `main.py`,
~line 344 and ~line 799).

## Filtering (dashboard read paths)

A helper `_active_account_filter(db)` in `src/routers/emails.py` resolves
the same way (`mailbox_accounts.is_active` row's email, or `None` if
none set / falls back to env). Applied to every `Email` query used for
display: `api_list_emails`, `api_get_email`, `api_stats`,
`api_export_emails`. Filter logic: `Email.account == active_email OR
Email.account IS NULL` when an active mailbox is set; unfiltered when none
is (matches current behavior for anyone who hasn't adopted this feature
yet).

Switching the active mailbox in the dashboard (`POST
/api/mailboxes/{id}/activate`) is instant — it only flips a boolean row,
so the very next dashboard read reflects the new filter. No email data is
ever deleted or moved by switching.

## Out of scope for this pass, explicitly deferred

- Polling multiple mailboxes at once.
- OAuth2 (Exchange Online / modern-auth-only tenants).
- Non-admin mailbox management permissions (the `mailboxes.manage`
  permission exists and *can* be granted to an analyst later via the
  existing permissions editor, but isn't part of any default role besides
  admin).
- Migrating `reporting.py` outbound SMTP off Gmail-only assumptions.

## Testing plan

- `MailboxAccount` model + `set_active_mailbox()` invariant (only one
  active) — unit test in `tests/test_database.py` style.
- `get_active_mailbox_credentials()` fallback-to-env behavior when no row
  is active / table is empty.
- `POST /api/mailboxes/test` — mock `EmailIngestion.connect()` for both
  success and IMAP auth failure paths; assert password never appears in
  the response.
- Email list/stats/export endpoints respect the active-mailbox filter,
  and that `account IS NULL` rows remain visible regardless of which
  mailbox is active (pre-migration history never hidden).
- Regression: existing Gmail bridge / `run_pipeline()` behavior is
  unchanged when `mailbox_accounts` is empty (fallback path).
