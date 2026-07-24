# SMTP Ingestion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Gmail IMAP polling with a locally-demoable SMTP receiver, without changing any rules/extraction/enrichment/LLM behavior, and without breaking the working demo at any point.

**Architecture:** An `aiosmtpd`-based SMTP server accepts mail fast (size + recipient-domain checks only) and writes each raw message to a durable `data/smtp_pending/` folder, returning `250 OK` immediately. `main.py`'s existing per-email processing loop (rules -> extraction -> enrichment -> LLM -> save) is untouched — the ONLY change is where `raw_emails: list[bytes]` comes from: instead of `ingestion.connect()` + `ingestion.fetch_recent()` (IMAP), it's read from the pending folder. The existing background poll (`_background_poll` in `api.py`, every `POLL_INTERVAL_SECONDS`) keeps calling `run_pipeline()` exactly as it does today — it doesn't know or care that the source changed.

**Tech Stack:** Python 3.12, `aiosmtpd==1.4.6` (new dependency, confirmed installable), FastAPI (existing), pytest (existing).

## Global Constraints

- All email content stays strictly local — the SMTP receiver only ever runs on a local/demo listener; no real internet exposure in this task.
- Fail-safe, never fail-open — an oversized or wrong-domain message is rejected at the SMTP protocol level; a message that's accepted but fails to parse downstream is escalated to a human, never dropped silently.
- Idempotency — composite key of Message-ID + SHA-256 of raw content (existing `EmailIngestion.idempotency_key`) must still be the thing that prevents reprocessing, exactly as it is for IMAP-sourced mail today.
- Do not rename or remove `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` in `.env.example` — those are the existing **outbound** reporting SMTP relay config (`src/reporting.py`), unrelated to this **inbound** receiver. New inbound config uses a distinct `SMTP_INBOUND_*` prefix to avoid collision.
- Priority above all: at every task boundary, the app must still start, the dashboard must still load, and `run_pipeline()` must still complete without raising. Verify this before moving to the next task.

---

### Task 1: Add `aiosmtpd` dependency and inbound SMTP config

**Files:**
- Modify: `requirements.txt`
- Modify: `.env.example`

**Interfaces:**
- Produces: env vars `SMTP_INBOUND_LISTEN_HOST`, `SMTP_INBOUND_LISTEN_PORT`, `SMTP_INBOUND_ACCEPTED_DOMAINS`, `SMTP_INBOUND_MAX_MESSAGE_SIZE`, `SMTP_INBOUND_TLS_CERT_PATH`, `SMTP_INBOUND_TLS_KEY_PATH` — consumed by Task 2's `src/smtp_receiver.py`.

- [ ] **Step 1: Add the dependency**

In `requirements.txt`, find the `# Email parsing & auth` section:

```
# Email parsing & auth
dkimpy==1.1.8
checkdmarc==5.17.1
dnspython==2.6.1
```

Add `aiosmtpd` right after it:

```
# Email parsing & auth
dkimpy==1.1.8
checkdmarc==5.17.1
dnspython==2.6.1

# Inbound SMTP server (replaces IMAP polling)
aiosmtpd==1.4.6
```

- [ ] **Step 2: Install it**

Run: `pip install aiosmtpd==1.4.6`
Expected: `Successfully installed aiosmtpd-1.4.6 atpublic-... attrs-...`

- [ ] **Step 3: Add inbound SMTP config to `.env.example`**

In `.env.example`, find the `# --- IMAP (email ingestion) ---` block:

```
# --- IMAP (email ingestion) ---
IMAP_HOST=imap.gmail.com
IMAP_USER=your-email@gmail.com
IMAP_PASSWORD=xxxx xxxx xxxx xxxx
```

Replace it with (IMAP is no longer the ingestion source, so mark it deprecated rather than deleting the block outright — a real deployment may still want the values documented):

```
# --- IMAP (deprecated — replaced by inbound SMTP below) ---
# No longer used to source new mail. Left here only in case a future
# fallback path needs it.
IMAP_HOST=imap.gmail.com
IMAP_USER=your-email@gmail.com
IMAP_PASSWORD=xxxx xxxx xxxx xxxx

# --- Inbound SMTP (email ingestion — replaces IMAP polling) ---
# Local demo: leave host/port as-is, send test mail with swaks or smtplib
# to localhost:2525. Real deployment: point the domain's MX record here,
# set SMTP_INBOUND_LISTEN_HOST=0.0.0.0, SMTP_INBOUND_LISTEN_PORT=25 (or 587),
# and set SMTP_INBOUND_ACCEPTED_DOMAINS to the real domain(s) so the server
# is never an open relay.
SMTP_INBOUND_LISTEN_HOST=127.0.0.1
SMTP_INBOUND_LISTEN_PORT=2525
# Comma-separated. Empty = accept mail for any recipient domain (demo only).
SMTP_INBOUND_ACCEPTED_DOMAINS=
SMTP_INBOUND_MAX_MESSAGE_SIZE=26214400
# Optional STARTTLS — leave both empty to run without TLS (fine for local demo).
SMTP_INBOUND_TLS_CERT_PATH=
SMTP_INBOUND_TLS_KEY_PATH=
```

- [ ] **Step 4: Verify nothing else references the old IMAP block position**

Run: `grep -rn "IMAP_HOST\|IMAP_USER\|IMAP_PASSWORD" src/`
Expected: only `src/main.py` (the `EmailIngestion(...)` construction) — confirms no other file assumes `.env.example`'s layout.

- [ ] **Step 5: Commit**

```bash
git add requirements.txt .env.example
git commit -m "chore: add aiosmtpd dependency and inbound SMTP config"
```

---

### Task 2: SMTP receiver module

**Files:**
- Create: `src/smtp_receiver.py`
- Test: `tests/test_smtp_receiver.py`

**Interfaces:**
- Consumes: nothing from earlier tasks (only env vars from Task 1 and stdlib/`aiosmtpd`).
- Produces:
  - `class PendingMailHandler` with `__init__(self, pending_dir: Path, accepted_domains: set[str], max_size: int)`, and aiosmtpd hooks `handle_RCPT`, `handle_DATA`.
  - `def build_controller() -> aiosmtpd.controller.Controller` — reads env vars, constructs `PendingMailHandler`, returns a `Controller` instance (not yet started). Consumed by Task 5 (`api.py` startup/shutdown).
  - Module constant `PENDING_DIR: Path` (`data/smtp_pending/`, following the existing `SAFE_DATA_DIR` convention from `src/email_extraction.py`). Consumed by Task 3 (`fetch_pending_smtp`).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_smtp_receiver.py`:

```python
import asyncio
import smtplib
import sys
from email.message import EmailMessage
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.smtp_receiver import PendingMailHandler


class _FakeSession:
    pass


class _FakeEnvelope:
    def __init__(self):
        self.rcpt_tos = []
        self.content = b""


@pytest.mark.asyncio
async def test_handle_rcpt_accepts_matching_domain(tmp_path):
    handler = PendingMailHandler(
        pending_dir=tmp_path, accepted_domains={"attijaribank.com"}, max_size=1000
    )
    envelope = _FakeEnvelope()
    status = await handler.handle_RCPT(
        None, _FakeSession(), envelope, "analyst@attijaribank.com", []
    )
    assert status == "250 OK"
    assert envelope.rcpt_tos == ["analyst@attijaribank.com"]


@pytest.mark.asyncio
async def test_handle_rcpt_rejects_other_domain(tmp_path):
    handler = PendingMailHandler(
        pending_dir=tmp_path, accepted_domains={"attijaribank.com"}, max_size=1000
    )
    envelope = _FakeEnvelope()
    status = await handler.handle_RCPT(
        None, _FakeSession(), envelope, "someone@gmail.com", []
    )
    assert status.startswith("550")
    assert envelope.rcpt_tos == []


@pytest.mark.asyncio
async def test_handle_rcpt_accepts_any_domain_when_unrestricted(tmp_path):
    handler = PendingMailHandler(pending_dir=tmp_path, accepted_domains=set(), max_size=1000)
    envelope = _FakeEnvelope()
    status = await handler.handle_RCPT(None, _FakeSession(), envelope, "x@anything.test", [])
    assert status == "250 OK"


@pytest.mark.asyncio
async def test_handle_data_writes_pending_file(tmp_path):
    handler = PendingMailHandler(pending_dir=tmp_path, accepted_domains=set(), max_size=1000)
    envelope = _FakeEnvelope()
    envelope.content = b"Subject: test\r\n\r\nbody\r\n"
    status = await handler.handle_DATA(None, _FakeSession(), envelope)
    assert status == "250 Message accepted for delivery"
    files = list(tmp_path.glob("*.eml"))
    assert len(files) == 1
    assert files[0].read_bytes() == envelope.content


@pytest.mark.asyncio
async def test_handle_data_rejects_oversized_message(tmp_path):
    handler = PendingMailHandler(pending_dir=tmp_path, accepted_domains=set(), max_size=10)
    envelope = _FakeEnvelope()
    envelope.content = b"x" * 100
    status = await handler.handle_DATA(None, _FakeSession(), envelope)
    assert status.startswith("552")
    assert list(tmp_path.glob("*.eml")) == []


def test_end_to_end_delivery_via_real_controller(tmp_path):
    """Integration test: real Controller on an ephemeral port, real smtplib client."""
    from src.smtp_receiver import PendingMailHandler
    from aiosmtpd.controller import Controller

    handler = PendingMailHandler(pending_dir=tmp_path, accepted_domains=set(), max_size=1_000_000)
    controller = Controller(handler, hostname="127.0.0.1", port=0)
    controller.start()
    try:
        port = controller.server.sockets[0].getsockname()[1]
        msg = EmailMessage()
        msg["From"] = "attacker@example.com"
        msg["To"] = "analyst@attijaribank.com"
        msg["Subject"] = "test delivery"
        msg.set_content("hello from the integration test")

        with smtplib.SMTP("127.0.0.1", port, timeout=5) as client:
            client.send_message(msg)
    finally:
        controller.stop()

    files = list(tmp_path.glob("*.eml"))
    assert len(files) == 1
    assert b"hello from the integration test" in files[0].read_bytes()
```

- [ ] **Step 2: Add `pytest-asyncio` if not already present**

Run: `grep -n pytest-asyncio requirements.txt`
If it prints nothing, add it to `requirements.txt` right after `pytest` (check `grep -n "^pytest" requirements.txt` for the exact existing line first), then run `pip install pytest-asyncio`.

Add to the top of `tests/test_smtp_receiver.py` (already included above) — no `pytest.ini`/`pyproject.toml` marker registration needed if the project doesn't have strict-mode asyncio config; if `pytest --collect-only tests/test_smtp_receiver.py` in Step 3 complains about unknown `asyncio` marker, add this to `tests/test_smtp_receiver.py` right below the imports:

```python
pytestmark = pytest.mark.asyncio
```

(only add this line if Step 3 shows the marker warning — try without it first, since some pytest-asyncio versions auto-detect `async def test_*` without a marker when `asyncio_mode = auto` is configured; if it's not configured, the explicit marker above is the fallback.)

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_smtp_receiver.py -v`
Expected: `ModuleNotFoundError: No module named 'src.smtp_receiver'` (or import error) — the module doesn't exist yet.

- [ ] **Step 4: Write the implementation**

Create `src/smtp_receiver.py`:

```python
"""Inbound SMTP receiver — accepts mail fast, hands off to the pipeline later.

Replaces Gmail IMAP polling as the source of new mail (see
docs/superpowers/specs/2026-07-24-smtp-ingestion-design.md). Accepts a
message (size + recipient-domain checks only) and writes it to
data/smtp_pending/ for main.py's existing pipeline to pick up on its next
tick — no rules/extraction/enrichment/LLM work happens inside the SMTP
transaction itself.
"""
import hashlib
import os
from pathlib import Path

from aiosmtpd.controller import Controller

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
PENDING_DIR = _PROJECT_ROOT / "data" / "smtp_pending"


class PendingMailHandler:
    """aiosmtpd message handler: validate fast, persist, return."""

    def __init__(self, pending_dir: Path, accepted_domains: set[str], max_size: int):
        self.pending_dir = pending_dir
        self.accepted_domains = accepted_domains
        self.max_size = max_size

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if self.accepted_domains:
            domain = address.split("@")[-1].lower() if "@" in address else ""
            if domain not in self.accepted_domains:
                return f"550 not accepting mail for {address!r}"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        data = envelope.content
        if len(data) > self.max_size:
            return f"552 Message exceeds size limit of {self.max_size} bytes"

        self.pending_dir.mkdir(parents=True, exist_ok=True)
        sha = hashlib.sha256(data).hexdigest()
        path = self.pending_dir / f"{sha}.eml"
        if not path.exists():
            path.write_bytes(data)
        return "250 Message accepted for delivery"


def _accepted_domains_from_env() -> set[str]:
    raw = os.getenv("SMTP_INBOUND_ACCEPTED_DOMAINS", "")
    return {d.strip().lower() for d in raw.split(",") if d.strip()}


def build_controller() -> Controller:
    """Construct (but do not start) the inbound SMTP Controller from env config."""
    host = os.getenv("SMTP_INBOUND_LISTEN_HOST", "127.0.0.1")
    port = int(os.getenv("SMTP_INBOUND_LISTEN_PORT", "2525"))
    max_size = int(os.getenv("SMTP_INBOUND_MAX_MESSAGE_SIZE", str(25 * 1024 * 1024)))
    handler = PendingMailHandler(
        pending_dir=PENDING_DIR,
        accepted_domains=_accepted_domains_from_env(),
        max_size=max_size,
    )
    return Controller(handler, hostname=host, port=port, data_size_limit=max_size)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_smtp_receiver.py -v`
Expected: all 6 tests `PASS`.

- [ ] **Step 6: Commit**

```bash
git add src/smtp_receiver.py tests/test_smtp_receiver.py requirements.txt
git commit -m "feat: add inbound SMTP receiver (accept-fast, write-to-pending)"
```

---

### Task 3: `EmailIngestion.fetch_pending_smtp()` — read the pending folder

**Files:**
- Modify: `src/email_extraction.py`
- Test: `tests/test_email_extraction_pending.py`

**Interfaces:**
- Consumes: `PENDING_DIR` from `src/smtp_receiver.py` (Task 2) — actually, to avoid a two-way import between `email_extraction.py` and `smtp_receiver.py`, this task defines its own `SAFE_DATA_DIR / "smtp_pending"` path directly (same literal path `smtp_receiver.py` uses), matching the existing convention in `email_extraction.py` of resolving paths under `SAFE_DATA_DIR`.
- Produces: `EmailIngestion.fetch_pending_smtp(self, limit: int = 50) -> list[bytes]` — consumed by Task 4 (`main.py`).

- [ ] **Step 1: Write the failing test**

Create `tests/test_email_extraction_pending.py`:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.email_extraction import EmailIngestion


def test_fetch_pending_smtp_reads_eml_files(tmp_path, monkeypatch):
    ingestion = EmailIngestion(host="unused", user="unused", password="unused")
    monkeypatch.setattr(ingestion, "PENDING_SMTP_DIR", tmp_path)

    (tmp_path / "aaa.eml").write_bytes(b"message one")
    (tmp_path / "bbb.eml").write_bytes(b"message two")
    (tmp_path / "not-an-eml.txt").write_bytes(b"ignore me")

    result = ingestion.fetch_pending_smtp()

    assert len(result) == 2
    assert b"message one" in result
    assert b"message two" in result


def test_fetch_pending_smtp_empty_dir_returns_empty_list(tmp_path, monkeypatch):
    ingestion = EmailIngestion(host="unused", user="unused", password="unused")
    monkeypatch.setattr(ingestion, "PENDING_SMTP_DIR", tmp_path / "does_not_exist")

    result = ingestion.fetch_pending_smtp()

    assert result == []


def test_fetch_pending_smtp_respects_limit(tmp_path, monkeypatch):
    ingestion = EmailIngestion(host="unused", user="unused", password="unused")
    monkeypatch.setattr(ingestion, "PENDING_SMTP_DIR", tmp_path)

    for i in range(5):
        (tmp_path / f"{i}.eml").write_bytes(f"message {i}".encode())

    result = ingestion.fetch_pending_smtp(limit=3)

    assert len(result) == 3
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_email_extraction_pending.py -v`
Expected: `AttributeError: 'EmailIngestion' object has no attribute 'fetch_pending_smtp'`

- [ ] **Step 3: Implement it**

In `src/email_extraction.py`, the class already defines `SAFE_DATA_DIR` at module level (line 34: `SAFE_DATA_DIR = _PROJECT_ROOT / "data"`). Add a new method right after `fetch_unread` (currently at line ~131-132):

```python
    # Backward compat alias
    def fetch_unread(self, limit: int = 50) -> list[bytes]:
        return self.fetch_recent(since_days=7, limit=limit)

    # Directory the inbound SMTP receiver (src/smtp_receiver.py) writes
    # accepted messages into. Kept as an instance attribute (not a
    # classmethod constant) so tests can monkeypatch it per-instance.
    PENDING_SMTP_DIR = SAFE_DATA_DIR / "smtp_pending"

    def fetch_pending_smtp(self, limit: int = 50) -> list[bytes]:
        """Read raw messages the SMTP receiver has accepted and queued.

        Mirrors fetch_recent()'s contract (returns a list[bytes], newest
        files first, capped at `limit`) so main.py's run_pipeline() can
        swap sources without changing anything downstream. Unlike IMAP,
        there's no "already fetched" concept here — every call re-reads
        whatever is currently on disk, and the existing idempotency cache
        (idempotency_key / get_cached_result) is what prevents reprocessing,
        exactly as it already does for IMAP-sourced mail.
        """
        pending_dir = self.PENDING_SMTP_DIR
        if not pending_dir.exists():
            return []
        files = sorted(pending_dir.glob("*.eml"), key=lambda p: p.stat().st_mtime, reverse=True)
        files = files[:limit]
        raw_emails = []
        for path in files:
            try:
                raw_emails.append(path.read_bytes())
            except OSError as e:
                print(f"[SMTP-PENDING] Failed to read {path.name}: {e}")
        return raw_emails
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_email_extraction_pending.py -v`
Expected: all 3 tests `PASS`.

- [ ] **Step 5: Commit**

```bash
git add src/email_extraction.py tests/test_email_extraction_pending.py
git commit -m "feat: add EmailIngestion.fetch_pending_smtp for SMTP-sourced mail"
```

---

### Task 4: Wire `run_pipeline()` to the SMTP pending source instead of IMAP

**Files:**
- Modify: `src/main.py:151-160` and `src/main.py:842` (the `ingestion.disconnect()` call)

**Interfaces:**
- Consumes: `EmailIngestion.fetch_pending_smtp()` (Task 3).
- Produces: nothing new — `raw_emails: list[bytes]` still flows into the exact same `for i, raw in enumerate(raw_emails, 1):` loop that already exists (unchanged).

This is the highest-risk task because it touches the live pipeline entry point, so it gets extra manual verification steps instead of only unit tests (the loop body itself is ~700 lines of pre-existing, already-working logic that this task does not touch).

- [ ] **Step 1: Read the current code to confirm line numbers before editing**

Run: `grep -n "ingestion = EmailIngestion\|ingestion.connect()\|raw_emails = ingestion.fetch_recent\|ingestion.disconnect()" src/main.py`
Expected output includes these four lines (line numbers may have shifted slightly since this plan was written — use the surrounding context below to find them, not the exact numbers):

```
151:    ingestion = EmailIngestion(
159:        ingestion.connect()
160:        raw_emails = ingestion.fetch_recent(since_days=7, limit=50)
842:        ingestion.disconnect()
```

- [ ] **Step 2: Replace the IMAP fetch with the pending-folder read**

Find this block in `src/main.py`:

```python
    try:
        ingestion.connect()
        raw_emails = ingestion.fetch_recent(since_days=7, limit=50)
```

Replace with:

```python
    try:
        # SMTP replaces IMAP as the ingestion source (2026-07-24). The
        # inbound SMTP receiver (src/smtp_receiver.py) already accepted and
        # durably wrote these messages; nothing below this line changes —
        # the per-email loop doesn't know or care where raw_emails came from.
        raw_emails = ingestion.fetch_pending_smtp(limit=50)
```

- [ ] **Step 3: Remove the now-unreachable `ingestion.disconnect()` call**

Find:

```python
        if cached:
            print(f"\n[INFO] {cached} email(s) loaded from cache")

        ingestion.disconnect()
```

Replace with:

```python
        if cached:
            print(f"\n[INFO] {cached} email(s) loaded from cache")
```

(`ingestion.disconnect()` calls `self.conn.close()`, but `self.conn` is only ever set by `connect()`, which we no longer call — leaving the old call in would raise `AttributeError: 'EmailIngestion' object has no attribute 'conn'` on every pipeline run.)

- [ ] **Step 4: Syntax-check the file**

Run: `python -m py_compile src/main.py`
Expected: no output, exit code 0.

- [ ] **Step 5: Verify the existing pipeline e2e test still passes**

Run: `cd src && python ../tests/test_pipeline_e2e.py`
Expected: same pass/fail behavior as before this change (this script builds its own synthetic `.eml` bytes and calls pipeline internals directly, not through `run_pipeline()`'s IMAP/SMTP fetch step — confirm by reading its output that it completes without a new error that mentions `fetch_pending_smtp`, `conn`, or `AttributeError`).

- [ ] **Step 6: Manually verify `run_pipeline()` runs end-to-end with an empty pending folder**

Run:
```bash
cd src && python -c "from main import run_pipeline; run_pipeline()"
```
Expected: pipeline starts, logs `[FETCH]`-equivalent activity or simply finds 0 pending messages, and finishes with `=== Pipeline Finished in ...s ===` — no traceback. If Ollama isn't running, expect the existing `[PIPELINE] Ollama unreachable — deferring this run` message instead, which is also a clean, non-error exit (that gate runs before the fetch change, so it's unaffected either way).

- [ ] **Step 7: Commit**

```bash
git add src/main.py
git commit -m "feat: source run_pipeline() emails from SMTP pending folder instead of IMAP"
```

---

### Task 5: Start the SMTP receiver with the app; end-to-end demo verification

**Files:**
- Modify: `src/api.py` (startup/shutdown events, near `_poll_task` / `_retention_task`)

**Interfaces:**
- Consumes: `build_controller()` from `src/smtp_receiver.py` (Task 2).

- [ ] **Step 1: Add the SMTP controller as module-level state, alongside `_poll_task`**

Find (`src/api.py:140-143`):

```python
# Background polling
_poll_task = None
_retention_task = None
_scan_lock = asyncio.Lock()
```

Replace with:

```python
# Background polling
_poll_task = None
_retention_task = None
_scan_lock = asyncio.Lock()
_smtp_controller = None
```

- [ ] **Step 2: Start it in `startup()`**

Find:

```python
@app.on_event("startup")
async def startup():
    global _poll_task, _retention_task
    init_db()
    _update_gauge_metrics()
    _poll_task = asyncio.create_task(_background_poll())
    _retention_task = asyncio.create_task(data_retention_and_backup_task())
    print(f"[POLL] Background IMAP polling started (every {POLL_INTERVAL}s)")
```

Replace with:

```python
@app.on_event("startup")
async def startup():
    global _poll_task, _retention_task, _smtp_controller
    init_db()
    _update_gauge_metrics()
    _poll_task = asyncio.create_task(_background_poll())
    _retention_task = asyncio.create_task(data_retention_and_backup_task())
    print(f"[POLL] Background pipeline tick started (every {POLL_INTERVAL}s)")

    from smtp_receiver import build_controller
    _smtp_controller = build_controller()
    _smtp_controller.start()
    print(f"[SMTP] Inbound receiver listening on "
          f"{_smtp_controller.hostname}:{_smtp_controller.port}")
```

- [ ] **Step 3: Stop it in `shutdown()`**

Find (`src/api.py:177-183`):

```python
@app.on_event("shutdown")
async def shutdown():
    global _poll_task, _retention_task
    if _poll_task:
        _poll_task.cancel()
    if _retention_task:
        _retention_task.cancel()
```

Replace with:

```python
@app.on_event("shutdown")
async def shutdown():
    global _poll_task, _retention_task, _smtp_controller
    if _poll_task:
        _poll_task.cancel()
    if _retention_task:
        _retention_task.cancel()
    if _smtp_controller:
        _smtp_controller.stop()
        print("[SMTP] Inbound receiver stopped")
```

- [ ] **Step 4: Syntax-check**

Run: `python -m py_compile src/api.py`
Expected: no output, exit code 0.

- [ ] **Step 5: Start the full app and confirm it comes up clean**

Run (however the project normally starts locally, e.g. `start.bat` or `start_all.ps1`, or directly):
```bash
cd src && python -m uvicorn api:app --host 127.0.0.1 --port 8000
```
Expected in the logs, in order: `[POLL] Background pipeline tick started...`, `[SMTP] Inbound receiver listening on 127.0.0.1:2525`, then normal FastAPI startup log lines. No traceback.

- [ ] **Step 6: Confirm the dashboard still works (regression check)**

Open `http://localhost:8000/login` in a browser, log in, and confirm the inbox loads with existing data — this must look exactly as it did before this task, since nothing about the dashboard changed.

- [ ] **Step 7: Send a test message through the new SMTP path**

With the app still running, from a second terminal:

```bash
python -c "
import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg['From'] = 'attacker@example.com'
msg['To'] = 'analyst@attijaribank.com'
msg['Subject'] = 'SMTP ingestion demo test'
msg.set_content('This is a test message delivered via the new inbound SMTP receiver.')

with smtplib.SMTP('127.0.0.1', 2525, timeout=5) as client:
    client.send_message(msg)
print('sent')
"
```
Expected: prints `sent`, no exception. Confirm a new `.eml` file appears in `data/smtp_pending/`.

- [ ] **Step 8: Confirm it reaches the dashboard**

Wait up to `POLL_INTERVAL_SECONDS` (default 60s) for the background tick to pick it up, or trigger it immediately via the existing manual-scan endpoint (log in as a user with `emails.scan` permission and hit `POST /api/scan`, or use the dashboard's existing "scan" UI control if there is one). Refresh the inbox — the test message should appear with a verdict, exactly like an IMAP-sourced email does today.

- [ ] **Step 9: Confirm the rejection paths work**

```bash
python -c "
import smtplib
from email.message import EmailMessage

msg = EmailMessage()
msg['From'] = 'attacker@example.com'
msg['To'] = 'someone@not-our-domain.example'
msg['Subject'] = 'should be rejected'
msg.set_content('recipient domain not in SMTP_INBOUND_ACCEPTED_DOMAINS')

with smtplib.SMTP('127.0.0.1', 2525, timeout=5) as client:
    try:
        client.send_message(msg)
        print('ERROR: was accepted, should have been rejected')
    except smtplib.SMTPRecipientsRefused as e:
        print('correctly rejected:', e)
"
```
Expected: `correctly rejected: ...` — **only meaningful if `SMTP_INBOUND_ACCEPTED_DOMAINS` in your `.env` is non-empty**; with the demo default (empty = accept any domain) this will print the `ERROR:` line instead, which is expected for the permissive demo config, not a bug. To actually exercise this path, temporarily set `SMTP_INBOUND_ACCEPTED_DOMAINS=attijaribank.com` in `.env`, restart the app, and rerun this step.

- [ ] **Step 10: Commit**

```bash
git add src/api.py
git commit -m "feat: start/stop inbound SMTP receiver with the app lifecycle"
```

---

### Task 6: Update the project build log

**Files:**
- Modify: `CLAUDE.md` (Build Log section)

- [ ] **Step 1: Add an entry**

At the end of the `## Build Log` section in `CLAUDE.md`, add:

```markdown
- **2026-07-24** — Replaced Gmail IMAP polling with an inbound SMTP receiver
  (`src/smtp_receiver.py`, `aiosmtpd`), per the tutor's final task. Mail
  arrives via SMTP (`SMTP_INBOUND_*` env vars — demo listens on
  `localhost:2525`, accept-domain-restricted and size-limited) instead of
  being fetched from Gmail. `run_pipeline()` in `src/main.py` now reads
  from `data/smtp_pending/` via `EmailIngestion.fetch_pending_smtp()`
  instead of `fetch_recent()`; the rules/extraction/enrichment/LLM logic
  itself is unchanged. Outbound SMTP (`src/reporting.py`) is untouched —
  outbound redesign was explicitly deferred pending further tutor input.
  Spec: `docs/superpowers/specs/2026-07-24-smtp-ingestion-design.md`.
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: log SMTP ingestion change in CLAUDE.md build log"
```
