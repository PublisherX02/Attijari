# SMTP Ingestion — Design Spec

**Date:** 2026-07-24
**Status:** Approved for implementation

## Purpose

Replace the current Gmail IMAP-polling ingestion with an SMTP-based inbound
path, per the tutor's final task requirement. The bank owns its mail domain
and runs its own SMTP server; conceptually, mail from the internet should
arrive at our pipeline via SMTP instead of us polling an inbox. For this PoC,
"the internet" is simulated locally: a test client (`swaks` or a small
`smtplib` script) delivers mail to our SMTP receiver instead of real DNS/MX
records pointing at it. The receiver must be configured the way a real one
would be (domain acceptance, size limits, TLS hook), so moving to production
later is a configuration change, not a redesign.

## Non-goals

- Outbound SMTP is unchanged. `reporting.py`'s `send_smtp_report()` keeps
  sending reports through the existing SMTP relay (e.g. Gmail). The tutor
  has not yet specified outbound requirements; that will be revisited in a
  later conversation.
- No real-world internet exposure. Running on a real public IP with a real
  MX record is explicitly out of scope for this PoC.
- No changes to rules engine, extraction, enrichment, or LLM analysis
  logic — only how a message enters the pipeline changes.

## Architecture

### 1. SMTP receiver (`src/smtp_receiver.py`, new)

An `aiosmtpd` `Controller` started as a background task in `api.py`'s
`startup` event handler, alongside the existing `_poll_task` /
`_retention_task` pattern.

Configuration (new `.env` variables, following the existing `IMAP_HOST`-style
convention):

- `SMTP_LISTEN_HOST` (default `0.0.0.0` for real deployment, `127.0.0.1` fine
  for the local demo)
- `SMTP_LISTEN_PORT` (default `2525` for the demo — unprivileged; `25`/`587`
  in a real deployment)
- `SMTP_ACCEPTED_DOMAINS` — comma-separated list of domains we accept mail
  for (e.g. `attijaribank.com`); RCPT TO addresses outside this list are
  rejected with a 550, so the server is never an open relay.
- `SMTP_MAX_MESSAGE_SIZE` — byte limit enforced at the protocol level
  (reject oversized DATA with a 552).
- `SMTP_TLS_CERT_PATH` / `SMTP_TLS_KEY_PATH` — optional; if both are set the
  controller offers STARTTLS. Left empty for the local demo.

### 2. Accept-fast handler

The `aiosmtpd` message handler's `handle_DATA` does only cheap, fast checks
before responding:

1. Enforce `SMTP_MAX_MESSAGE_SIZE` (reject if exceeded).
2. Enforce `SMTP_ACCEPTED_DOMAINS` against RCPT TO (reject if no match).
3. Write the raw message bytes to the same durable "pending" store the IMAP
   path already relies on for idempotency (composite key: Message-ID +
   SHA-256 of raw content, per existing project rule).
4. Return `250 OK`.

No rules evaluation, extraction, enrichment, or LLM analysis happens inside
the SMTP transaction. This matches how real MTAs behave (accept into a
queue, process asynchronously) and avoids holding SMTP connections open for
however long full analysis takes.

### 3. Shared per-message processing function (refactor of `src/main.py`)

`run_pipeline()` currently fetches a batch from IMAP and, inside a
`for raw in raw_emails:` loop, does: archive raw → idempotency check → parse
→ DMARC/DKIM/SPF auth → rules engine → extraction → enrichment → LLM
analysis → save verdict. This per-message body will be extracted into a
standalone function:

```python
def process_one_email(raw: bytes, ingestion: EmailIngestion, engine: RuleEngine, db) -> None:
    ...
```

Both the legacy IMAP code path (kept only as historical reference during
transition, see "Removal of IMAP polling" below) and the new SMTP-sourced
path call this same function, so rules/extraction/enrichment/LLM behavior is
identical regardless of how the message arrived.

### 4. Background consumer

Replaces the fixed-interval IMAP poll (`_background_poll` in `api.py`,
currently ticking every `POLL_INTERVAL_SECONDS`). The new consumer wakes on
a short interval (reusing `POLL_INTERVAL_SECONDS` as the polling cadence for
the pending store, since we're not doing real push/event wiring for the
PoC) and calls `process_one_email()` for every unprocessed message sitting
in the pending store. This preserves the existing Ollama-availability gate
and detonation-window gate (a pipeline run is skipped/deferred under the
same conditions as today).

### 5. Removal of IMAP polling

Per the tutor's explicit instruction ("SMTP should replace the IMAP polling
method"), `run_pipeline()` stops connecting to IMAP and fetching messages.
The `EmailIngestion` IMAP-connect/fetch code remains in the codebase (it's
generic parsing/archival logic reused by the SMTP path too) but is no longer
invoked to *source* new mail.

## Data flow

```
Test client (swaks/smtplib)
    |  SMTP DATA
    v
aiosmtpd Controller (src/smtp_receiver.py)
    |  size + domain checks -> 250/45x/55x
    v
Pending store (raw bytes, keyed by idempotency key)
    |
    v
Background consumer (was: _background_poll)
    |
    v
process_one_email()  [same logic as before: rules -> extraction ->
                       enrichment -> LLM -> verdict -> DB]
    |
    v
Dashboard (unchanged)
```

## Error handling (fail-safe, matches existing project rules)

- Oversized message or wrong recipient domain: rejected at the SMTP
  protocol level (4xx/5xx), never stored.
- Message accepted but fails to parse downstream: still escalated to a
  human for review, exactly like an unparseable IMAP-sourced email today —
  never silently dropped, never auto-accepted.
- SMTP receiver crash/restart: any message already returned `250 OK` is
  durably stored before that response is sent, so a receiver restart does
  not lose accepted mail.

## Testing / demo plan

1. Start the app as usual (`start.bat` / `start_all.ps1`).
2. Send a test message with `swaks --to test@attijaribank.com --from
   attacker@example.com --server localhost:2525 --data sample.eml` (or an
   equivalent `smtplib` script).
3. Confirm the message appears in the dashboard inbox, goes through rules →
   extraction → enrichment → LLM analysis, and produces a verdict — same
   as an IMAP-sourced email does today.
4. Confirm a message to an unaccepted recipient domain is rejected by the
   server (no dashboard entry created).
5. Confirm an oversized message is rejected.

## Open items (deferred, not part of this task)

- Outbound SMTP redesign — tutor has not specified requirements yet.
- Real TLS certificates / real MX record configuration — production
  concern, not needed for the demo.
