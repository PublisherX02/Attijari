# Mailbox protocol extension: POP3 inbound + custom outbound SMTP relay

Date: 2026-07-29
Status: Approved
Builds on: `2026-07-29-dashboard-mailbox-accounts-design.md`

## Problem

`MailboxAccount` today only supports IMAP polling (`provider` in
`gmail`/`outlook`/`custom`, always fetched via `EmailIngestion` + IMAP). Two
gaps:

1. Some real-world mailboxes only offer POP3, not IMAP.
2. Outbound scheduled-report delivery (`reporting.send_smtp_report`) is
   hardcoded to a single `.env` `SMTP_*` config — it can't send through a
   specific dashboard-configured mailbox's own SMTP relay.

## Non-goals

- No "direct-push SMTP mailbox" type (a mailbox whose only inbound path is
  mail delivered straight to the local SMTP receiver). Considered and
  dropped — out of scope for this spec.
- No changes to `src/smtp_receiver.py` (inbound receiver) or the pipeline's
  `fetch_pending_smtp` read path — those are unaffected.

## Schema changes — `MailboxAccount` (`src/database.py`)

New columns, all additive/nullable except `protocol`:

| Column | Type | Default | Purpose |
|---|---|---|---|
| `protocol` | `String(10)` | `"imap"` | `imap` or `pop3` — which bridge/class polls this mailbox |
| `smtp_out_host` | `String(255)` | `NULL` | Outbound relay host |
| `smtp_out_port` | `Integer` | `465` | Outbound relay port |
| `smtp_out_user` | `String(320)` | `NULL` | Outbound relay username |
| `smtp_out_password_encrypted` | `Text` | `NULL` | `vault.encrypt_field` output |

`smtp_out_host` being `NULL` means "no outbound relay configured for this
mailbox" — reporting falls back to `.env` `SMTP_*`, unchanged from today.

Migration: new `_migrate_mailbox_protocol_and_outbound_smtp()` function
following the existing additive-`ALTER TABLE` idiom (see
`_migrate_email_account_column`). No backfill needed — existing rows get
`protocol='imap'` via the column default, and null outbound fields are the
correct "not configured" state.

## Inbound: `Pop3Ingestion` (new class, `src/email_extraction.py`)

Mirrors `EmailIngestion`'s public interface exactly so callers can use
either interchangeably:

```python
class Pop3Ingestion:
    def __init__(self, host, user, password, port=995): ...
    def connect(self): ...      # poplib.POP3_SSL with explicit ssl.create_default_context()
    def disconnect(self): ...
    def fetch_recent(self, since_days=7, limit=50) -> list[bytes]: ...
```

Key differences from `EmailIngestion`, documented in the class docstring:

- **No PEEK equivalent.** POP3's `RETR` doesn't have an IMAP-style
  peek/no-mark-read option, but this doesn't threaten the existing
  re-poll-safety guarantee — that guarantee already lives entirely in the
  SMTP receiver's SHA-256 content dedup (see `gmail_smtp_bridge.py`'s
  docstring), not in the source protocol. Re-relaying an already-seen
  message via POP3 is still a no-op downstream.
- **No server-side date search.** `since_days` filtering happens
  client-side: fetch message list via `LIST`/`RETR`, parse each message's
  `Date` header, filter, then cap at `limit` (newest first by parsed date).

## Bridges — mutual exclusion by protocol

- `gmail_smtp_bridge.py`'s `run_once()` gains a guard: if the active
  mailbox's `protocol == "pop3"`, skip (return 0) — don't attempt IMAP.
- New `src/pop3_smtp_bridge.py`, structural mirror of
  `gmail_smtp_bridge.py`: same `run_once()`/`run_forever()` shape, guards
  the opposite way (skip unless `protocol == "pop3"`), builds
  `Pop3Ingestion` instead of `EmailIngestion`. Imports and reuses
  `gmail_smtp_bridge.relay_one()` rather than duplicating the relay logic.
- Both bridges are started as asyncio background tasks from `src/api.py`
  startup (matching how `gmail_smtp_bridge` is started today).
- Net effect: exactly one bridge acts on the active mailbox at a time,
  selected by its `protocol` column. No mailbox is ever polled by both.

## Outbound: per-mailbox SMTP relay (`src/reporting.py`, `src/mailboxes.py`)

- New `mailboxes.get_active_mailbox_outbound_smtp(db) -> dict | None`:
  returns `{host, port, user, password}` (password decrypted via
  `vault.decrypt_field`) if the active mailbox has `smtp_out_host` set,
  else `None`. Mirrors `get_active_mailbox_credentials`'s shape/fallback
  convention.
- `reporting.send_smtp_report(report, recipients=None, mailbox=None)`
  gains the optional `mailbox` param. When provided, its host/port/user/
  password replace the `os.getenv("SMTP_*")` reads; when `None`
  (unchanged callers), behavior is identical to today.
- The scheduled-report caller resolves `get_active_mailbox_outbound_smtp`
  and passes it through; if it returns `None`, the call site passes
  `mailbox=None` and `.env` fallback applies exactly as it does now.

## Dashboard UI (`admin.html` + `routers/mailboxes.py`)

- Add a **Protocol** selector (IMAP / POP3) next to the existing provider
  dropdown in the add-mailbox form. Defaults to IMAP. Selecting POP3
  changes the default port shown from 993 to 995 but reuses the same
  host/user/password fields — no new required fields for inbound.
- Add a collapsible **"Outbound relay (optional)"** sub-section per
  mailbox row: host/port/user/password fields, saved independently via a
  new `PATCH /api/mailboxes/{id}/outbound-smtp` endpoint (admin-only, same
  auth dependency as existing mailbox routes). Clearing the host field
  clears the whole outbound config (sets all four columns back to NULL).
- A lightweight **"Test relay"** action does an `SMTP`/`EHLO` + `login`
  check against the outbound fields — separate from the existing IMAP
  "Test" button, since they test different servers/protocols entirely.

## Testing

- `Pop3Ingestion`: unit tests with mocked `poplib.POP3_SSL` — connect,
  disconnect, fetch with date filtering, connection failure path.
- `pop3_smtp_bridge.run_once()`: mirrors existing `gmail_smtp_bridge`
  tests — mocked active-mailbox lookup, mocked `Pop3Ingestion`, asserts
  relay calls and the protocol-guard skip behavior.
- `gmail_smtp_bridge.run_once()`: new test asserting it skips (returns 0,
  no IMAP connect attempted) when the active mailbox's protocol is
  `pop3`.
- Migration test for the five new columns (protocol default, outbound
  fields nullable) — same pattern as `test_mailbox_accounts_db.py`'s
  existing migration tests.
- Router tests for `PATCH /api/mailboxes/{id}/outbound-smtp` — set,
  clear, and auth-required cases.
- `reporting.send_smtp_report()` test: confirms a passed `mailbox` dict
  overrides `.env` reads, and `mailbox=None` preserves current behavior
  unchanged.

## Out of scope / deferred

- Direct-push SMTP mailbox type (mail delivered straight to the receiver,
  no polling) — explicitly dropped, see Non-goals.
- No changes to the rules engine, extraction, enrichment, or LLM stages —
  this is purely ingestion-source and outbound-delivery plumbing.
