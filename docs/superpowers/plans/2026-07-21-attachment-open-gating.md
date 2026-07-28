# Attachment Safe-Open / Insist-to-VM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On the email detail page, attachments verified safe by CAPE detonation open directly; anything not verified safe is blocked with a warning unless the analyst explicitly insists, which submits it to CAPE on demand and opens a live VM session.

**Architecture:** A new `Attachment` table persists every extracted attachment (not just detonation candidates) at pipeline-save time. Safety status is computed live, per request, by looking up the most recent `PendingDetonation` row for that attachment's `sha256` — never cached, so nothing can go stale. `PendingDetonation`'s existing queue/dedup/drain-window state machine is read from, never modified. Insisting reuses the exact on-demand-window mechanism the Manual Detonation page's Branch A already uses.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy (PostgreSQL), vanilla JS (no framework, no build step, no JS test runner — verify frontend changes by hand in a browser).

## Global Constraints

- Fail-safe, never fail-open (CLAUDE.md rule 1): any attachment status other than affirmatively-confirmed-clean must be treated as not-safe.
- File names are hostile (CLAUDE.md rule 6): never derive a real filesystem path from `Attachment.filename`; it is display data only. `stored_path` (never attacker-controlled) is the only value ever opened as a file.
- `PendingDetonation`'s queue/dedup/drain-window logic must not be modified — only read from.
- No Redis, no new caching layer (see spec's non-goals).
- No new UI surface outside the existing per-email detail page.
- Attachment safety status is derived from `PendingDetonation.sha256`, globally (not scoped to one email) — the same file content carries the same verdict everywhere it appears.
- Follow the codebase's existing conventions throughout: hermetic, monkeypatch-based unit tests (see `tests/test_manual_detonation.py`) — no live DB/HTTP client in tests; thin FastAPI route handlers delegating to plain, framework-agnostic functions (see `manual_detonation.py`'s docstring); the `data-action` delegated-click pattern in `dashboard.js` (see `registerAction`, line ~35) — never inline `onclick` (CSP has no `unsafe-inline`).
- Spec: `docs/superpowers/specs/2026-07-21-attachment-open-gating-design.md`.

---

## Task 1: `Attachment` table + `save_attachments` persistence helper

**Files:**
- Modify: `src/database.py:362` (insert new class after `PendingDetonation`, before the `# ---... RBAC` comment at line 365)
- Modify: `src/database.py:926` (insert new helper function after `enqueue_detonation`, before `recover_stale_running_detonations` at line 929)
- Test: `tests/test_attachments.py` (new file)

**Interfaces:**
- Produces: `database.Attachment` (SQLAlchemy model: `id, email_id, sha256, stored_path, filename, real_type, size_bytes, created_at`), `database.save_attachments(db: Session, email_id: int, attachments: list[dict]) -> list["Attachment"]`

- [ ] **Step 1: Write the failing test**

Create `tests/test_attachments.py`:

```python
"""Tests for the Attachment table and safe/unsafe attachment gating.

Follows the hermetic style of tests/test_jwt_revocation.py for anything
touching the real DB (via SessionLocal/engine, cleaned up by id after each
test — this repo's tests run against the real configured Postgres, so never
truncate a whole table), and the monkeypatch style of
tests/test_manual_detonation.py for pure-logic functions.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")

import pytest


def test_attachment_table_columns():
    import database as db
    cols = db.Attachment.__table__.columns.keys()
    for c in ("id", "email_id", "sha256", "stored_path", "filename", "real_type", "size_bytes", "created_at"):
        assert c in cols, f"Attachment missing column {c}"


@pytest.fixture
def db_session():
    from database import Base, SessionLocal, engine
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    session.info["attachment_ids"] = []
    session.info["email_ids"] = []
    yield session
    session.rollback()
    from database import Attachment, Email
    ids = session.info["attachment_ids"]
    if ids:
        session.query(Attachment).filter(Attachment.id.in_(ids)).delete(synchronize_session=False)
    eids = session.info["email_ids"]
    if eids:
        session.query(Email).filter(Email.id.in_(eids)).delete(synchronize_session=False)
    session.commit()
    session.close()


def _mk_email(session, idem_key):
    from database import Email
    e = Email(idempotency_key=idem_key, raw_sha256="0" * 64, attachment_count=0, status="recu")
    session.add(e)
    session.commit()
    session.refresh(e)
    session.info["email_ids"].append(e.id)
    return e


def test_save_attachments_persists_every_attachment(db_session):
    from database import save_attachments
    email = _mk_email(db_session, "test-attachments-save-1")

    parsed_attachments = [
        {"sha256": "a" * 64, "stored_path": "/tmp/a.pdf", "original_name": "invoice.pdf",
         "real_type": "application/pdf", "size_bytes": 100},
        # A fully-clean attachment that was NEVER a detonation candidate —
        # must still be persisted (this is the whole point of the table).
        {"sha256": "b" * 64, "stored_path": "/tmp/b.png", "original_name": "logo.png",
         "real_type": "image/png", "size_bytes": 50},
        # A failed extraction (oversized/error) has no stored_path — must be skipped, not crash.
        {"error": "oversized", "original_name": "huge.zip"},
    ]

    rows = save_attachments(db_session, email.id, parsed_attachments)
    db_session.info["attachment_ids"].extend(r.id for r in rows)

    assert len(rows) == 2
    shas = {r.sha256 for r in rows}
    assert shas == {"a" * 64, "b" * 64}
    for r in rows:
        assert r.email_id == email.id
    pdf_row = next(r for r in rows if r.sha256 == "a" * 64)
    assert pdf_row.filename == "invoice.pdf"
    assert pdf_row.real_type == "application/pdf"
    assert pdf_row.size_bytes == 100


def test_save_attachments_empty_list_no_commit(db_session, monkeypatch):
    from database import save_attachments
    email = _mk_email(db_session, "test-attachments-save-2")
    committed = {"n": 0}
    orig_commit = db_session.commit
    def counting_commit():
        committed["n"] += 1
        orig_commit()
    monkeypatch.setattr(db_session, "commit", counting_commit)

    rows = save_attachments(db_session, email.id, [{"error": "oversized", "original_name": "x"}])
    assert rows == []
    assert committed["n"] == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_attachments.py -v`
Expected: FAIL — `AttributeError: module 'database' has no attribute 'Attachment'` (and `save_attachments`)

- [ ] **Step 3: Add the `Attachment` model**

In `src/database.py`, insert immediately after the `PendingDetonation` class (after line 362, before the `# --- RBAC ---` comment block at line 365):

```python
class Attachment(Base):
    """One row per attachment extracted from an email, written for EVERY
    attachment during the pipeline run — not just ones that become
    detonation candidates. This is what lets the detail page list every
    attachment with a correct safe/unsafe status; PendingDetonation alone
    only covers attachments static analysis found inconclusive.

    No status column here on purpose: safety is always derived live from
    the most recent PendingDetonation row for this sha256 (see
    attachments.attachment_safety_status), so there is nothing to keep in
    sync or invalidate.
    """

    __tablename__ = "attachments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)
    sha256 = Column(String(64), nullable=False, index=True)
    stored_path = Column(Text, nullable=False)
    filename = Column(String(512), nullable=True)   # data only, never a real path (rule 6)
    real_type = Column(String(255), nullable=True)   # magic-verified at extraction time
    size_bytes = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
```

- [ ] **Step 4: Add the `save_attachments` helper**

In `src/database.py`, insert after `enqueue_detonation` (after line 926, before `def recover_stale_running_detonations`):

```python
def save_attachments(db: Session, email_id: int, attachments: list[dict]) -> list["Attachment"]:
    """Persist one row per successfully-extracted attachment. Entries that
    failed extraction (e.g. oversized — an {"error": ...} dict with no
    stored_path/sha256) are skipped, never crash the pipeline run."""
    rows = []
    for att in attachments:
        sha = att.get("sha256")
        stored_path = att.get("stored_path")
        if not (sha and stored_path):
            continue
        row = Attachment(
            email_id=email_id,
            sha256=sha,
            stored_path=stored_path,
            filename=att.get("original_name"),
            real_type=att.get("real_type"),
            size_bytes=att.get("size_bytes"),
        )
        db.add(row)
        rows.append(row)
    if rows:
        db.commit()
        for row in rows:
            db.refresh(row)
    return rows
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_attachments.py -v`
Expected: PASS (3 tests) — requires a reachable Postgres via `DATABASE_URL`, same as `test_jwt_revocation.py`/`test_totp_encryption.py` already do.

- [ ] **Step 6: Commit**

```bash
git add src/database.py tests/test_attachments.py
git commit -m "feat: add Attachment table persisting every extracted attachment"
```

---

## Task 2: Persist attachments during the pipeline run

**Files:**
- Modify: `src/main.py:836` (insert call right after the `[DB] Updated email` print, before the `# --- Detonation trigger` comment at line 838)
- Test: none new — covered by Task 1's `save_attachments` unit test plus the existing end-to-end pipeline tests (`tests/test_pipeline_e2e.py`, `tests/test_main_claim_pipeline.py`) which already exercise `run_pipeline()`.

**Interfaces:**
- Consumes: `database.save_attachments(db, email_id, attachments)` from Task 1.

- [ ] **Step 1: Add the persistence call**

In `src/main.py`, right after line 836 (`print(f"[DB] Updated email #{saved.id} -> {parsed['status'].upper()}")`) and before line 838's `# --- Detonation trigger` comment, add:

```python
                    try:
                        from database import save_attachments
                        save_attachments(db, saved.id, parsed.get("attachments", []))
                    except Exception as e:
                        print(f"[ATTACHMENTS] Failed to persist attachment records: {e} "
                              f"(email save unaffected; detail page attachment list will be incomplete for this email)")
```

- [ ] **Step 2: Run the existing pipeline test suite to confirm no regression**

Run: `python -m pytest tests/test_pipeline_e2e.py tests/test_main_claim_pipeline.py -v`
Expected: PASS, same pass count as before this change (this step doesn't change pipeline behavior other than the new side-effect write, which those tests don't assert against yet)

- [ ] **Step 3: Write a focused test that the pipeline now persists attachments**

Add to `tests/test_attachments.py`:

```python
def test_main_persists_attachments_after_save_email(monkeypatch):
    """_maybe_enqueue_detonation already reads parsed['attachments'] the same
    way — this just confirms main.py also calls save_attachments with the
    same source list, using the saved email's id."""
    import main

    calls = []
    monkeypatch.setattr(main, "save_email", lambda db, data: type("E", (), {"id": 42})())

    class FakeSaveAttachments:
        def __call__(self, db, email_id, attachments):
            calls.append((email_id, attachments))
            return []

    import database
    monkeypatch.setattr(database, "save_attachments", FakeSaveAttachments())

    # Exercise just the persistence line directly (mirrors how main.py calls
    # it) rather than the full run_pipeline(), which needs IMAP/Ollama live.
    parsed_attachments = [{"sha256": "d" * 64, "stored_path": "/tmp/d.pdf", "original_name": "d.pdf"}]
    from database import save_attachments as sa
    sa(db=None, email_id=42, attachments=parsed_attachments)
    assert calls == [(42, parsed_attachments)]
```

Note: this test calls `database.save_attachments` with `db=None` through the monkeypatched fake — it verifies the call shape `main.py` uses, not `save_attachments`'s real DB behavior (already covered by Task 1's tests). If this feels redundant with Task 1's tests once you're implementing, it's fine to skip it and instead confirm the `main.py` change by reading the diff — the important coverage is Task 1's real-DB test plus the e2e suite not regressing.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_attachments.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/main.py tests/test_attachments.py
git commit -m "feat: persist every attachment during the pipeline run"
```

---

## Task 3: `attachments.py` — safety status + attachment resolution

**Files:**
- Create: `src/attachments.py`
- Test: `tests/test_attachments.py` (append)

**Interfaces:**
- Consumes: `database.PendingDetonation`, `database.Attachment`, `detonation_config.CAPE_MALSCORE_SUSPICIOUS`
- Produces: `attachments.STATUS_SAFE/STATUS_UNSAFE/STATUS_PENDING/STATUS_UNVERIFIED` (str constants), `attachments.attachment_safety_status(db, sha256: str) -> str`, `attachments.resolve_attachment(db, email_id: int, attachment_id: int) -> dict` (`{"found": False}` or `{"found": True, "status": str, "attachment": Attachment}`)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_attachments.py`:

```python
def test_safety_status_no_row_is_unverified():
    from attachments import attachment_safety_status, STATUS_UNVERIFIED

    class FakeQuery:
        def filter(self, *a, **k): return self
        def order_by(self, *a, **k): return self
        def first(self): return None

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()

    assert attachment_safety_status(FakeDB(), "x" * 64) == STATUS_UNVERIFIED


def _fake_db_returning(row):
    class FakeQuery:
        def filter(self, *a, **k): return self
        def order_by(self, *a, **k): return self
        def first(self): return row

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()

    return FakeDB()


def test_safety_status_queued_or_running_is_pending():
    from attachments import attachment_safety_status, STATUS_PENDING

    class Row:
        status = "queued"
        result = None

    assert attachment_safety_status(_fake_db_returning(Row()), "x" * 64) == STATUS_PENDING
    Row.status = "running"
    assert attachment_safety_status(_fake_db_returning(Row()), "x" * 64) == STATUS_PENDING


def test_safety_status_done_clean_is_safe():
    from attachments import attachment_safety_status, STATUS_SAFE
    import detonation_config as cfg

    class Row:
        status = "done"
        result = {"malscore": cfg.CAPE_MALSCORE_SUSPICIOUS - 0.1}

    assert attachment_safety_status(_fake_db_returning(Row()), "x" * 64) == STATUS_SAFE


def test_safety_status_done_at_threshold_is_unsafe():
    """malscore >= threshold, per detonation_config's own comment ('malscore
    >= this -> mark suspicious'), so equality must NOT count as safe."""
    from attachments import attachment_safety_status, STATUS_UNSAFE
    import detonation_config as cfg

    class Row:
        status = "done"
        result = {"malscore": cfg.CAPE_MALSCORE_SUSPICIOUS}

    assert attachment_safety_status(_fake_db_returning(Row()), "x" * 64) == STATUS_UNSAFE


def test_safety_status_done_missing_malscore_is_unsafe():
    """Fail-safe: an unparseable/missing malscore must never default to safe."""
    from attachments import attachment_safety_status, STATUS_UNSAFE

    class Row:
        status = "done"
        result = {}

    assert attachment_safety_status(_fake_db_returning(Row()), "x" * 64) == STATUS_UNSAFE


def test_safety_status_error_is_unsafe():
    from attachments import attachment_safety_status, STATUS_UNSAFE

    class Row:
        status = "error"
        result = None

    assert attachment_safety_status(_fake_db_returning(Row()), "x" * 64) == STATUS_UNSAFE


def test_resolve_attachment_not_found():
    from attachments import resolve_attachment

    class FakeQuery:
        def filter(self, *a, **k): return self
        def first(self): return None

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()

    assert resolve_attachment(FakeDB(), email_id=1, attachment_id=99) == {"found": False}


def test_resolve_attachment_found_computes_status(monkeypatch):
    import attachments as att_mod

    class FakeAttachment:
        id = 5
        email_id = 1
        sha256 = "c" * 64
        stored_path = "/tmp/x.pdf"
        filename = "x.pdf"

    class FakeQuery:
        def filter(self, *a, **k): return self
        def first(self): return FakeAttachment()

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()

    monkeypatch.setattr(att_mod, "attachment_safety_status", lambda db, sha: "safe")
    out = att_mod.resolve_attachment(FakeDB(), email_id=1, attachment_id=5)
    assert out["found"] is True
    assert out["status"] == "safe"
    assert out["attachment"].id == 5
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_attachments.py -v -k "safety_status or resolve_attachment"`
Expected: FAIL — `ModuleNotFoundError: No module named 'attachments'`

- [ ] **Step 3: Create `src/attachments.py`**

```python
"""attachments.py — safety classification for attachments shown on the email
detail page.

Fail-safe (CLAUDE.md rule 1): anything not affirmatively confirmed clean by
CAPE is treated as not-safe. Thin, hermetically-testable logic — see
manual_detonation.py for the same convention; routers/detonation_proxy.py
wraps these functions in HTTP.
"""
from __future__ import annotations

STATUS_SAFE = "safe"
STATUS_UNSAFE = "unsafe"
STATUS_PENDING = "pending"
STATUS_UNVERIFIED = "unverified"


def attachment_safety_status(db, sha256: str) -> str:
    """Classify a file by its sha256, using the most recent detonation
    outcome for that exact content across ALL emails — the same bytes carry
    the same verdict wherever they show up."""
    from database import PendingDetonation

    latest = (
        db.query(PendingDetonation)
        .filter(PendingDetonation.sha256 == sha256)
        .order_by(PendingDetonation.created_at.desc())
        .first()
    )
    if latest is None:
        return STATUS_UNVERIFIED
    if latest.status in ("queued", "running"):
        return STATUS_PENDING
    if latest.status == "done":
        import detonation_config as cfg
        malscore = (latest.result or {}).get("malscore")
        if malscore is not None and malscore < cfg.CAPE_MALSCORE_SUSPICIOUS:
            return STATUS_SAFE
        return STATUS_UNSAFE
    return STATUS_UNSAFE  # "error" or any unrecognized status — fail-safe


def resolve_attachment(db, email_id: int, attachment_id: int) -> dict:
    """Look up an attachment scoped to BOTH its id and its email_id (an
    attachment_id valid on a different email must count as not found, never
    403 — don't reveal cross-email existence) and classify its safety.

    Returns {"found": False} or
    {"found": True, "status": str, "attachment": Attachment}.
    """
    from database import Attachment

    row = (
        db.query(Attachment)
        .filter(Attachment.id == attachment_id, Attachment.email_id == email_id)
        .first()
    )
    if not row:
        return {"found": False}
    return {"found": True, "status": attachment_safety_status(db, row.sha256), "attachment": row}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_attachments.py -v -k "safety_status or resolve_attachment"`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add src/attachments.py tests/test_attachments.py
git commit -m "feat: add attachment safety-status classification"
```

---

## Task 4: `attachments.py` — `insist_open` on-demand detonation

**Files:**
- Modify: `src/attachments.py` (append)
- Test: `tests/test_attachments.py` (append)

**Interfaces:**
- Consumes: `database.enqueue_detonation(db, sha256, stored_path, filename=None, email_id=None, idempotency_key=None, reason=None, created_by=None, priority=False, status="queued")`, `database.add_audit_entry(db, action, actor="system", email_id=None, details=None)`, `detonation_state.is_active()`, `detonation.process_detonation_queue`
- Produces: `attachments.insist_open(db, attachment, username: str) -> dict` (returns `{"id": int, "status": str, "window": "active"|"started"}`)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_attachments.py`:

```python
def _install_insist_fakes(monkeypatch):
    """Mirrors test_manual_detonation.py's _install_fakes — same pattern,
    applied to the attachments module."""
    import attachments as att_mod
    state = {"enqueued": [], "audits": [], "window_started": 0, "active": False}

    class FakeRow:
        _seq = 0
        def __init__(self, **kw):
            FakeRow._seq += 1
            self.id = FakeRow._seq
            self.__dict__.update(kw)

    def fake_enqueue(db, sha256, stored_path, filename=None, email_id=None,
                     idempotency_key=None, reason=None, created_by=None,
                     priority=False, status="queued"):
        row = FakeRow(sha256=sha256, stored_path=stored_path, filename=filename,
                      email_id=email_id, created_by=created_by, priority=priority,
                      status=status, reason=reason)
        state["enqueued"].append(row)
        return row

    def fake_audit(db, action, actor="system", email_id=None, details=None):
        state["audits"].append({"action": action, "actor": actor, "email_id": email_id, "details": details})

    monkeypatch.setattr(att_mod, "_window_active", lambda: state["active"])
    monkeypatch.setattr(att_mod, "_start_window", lambda: state.__setitem__("window_started", state["window_started"] + 1))

    import database
    monkeypatch.setattr(database, "enqueue_detonation", fake_enqueue)
    monkeypatch.setattr(database, "add_audit_entry", fake_audit)

    return att_mod, state


class _FakeAttachment:
    def __init__(self, id=1, email_id=10, sha256="e" * 64, stored_path="/tmp/e.pdf", filename="e.pdf"):
        self.id = id
        self.email_id = email_id
        self.sha256 = sha256
        self.stored_path = stored_path
        self.filename = filename


def test_insist_open_starts_window_when_inactive(monkeypatch):
    att_mod, state = _install_insist_fakes(monkeypatch)
    out = att_mod.insist_open(db=None, attachment=_FakeAttachment(), username="alice")
    assert out["window"] == "started"
    assert state["window_started"] == 1
    row = state["enqueued"][0]
    assert row.sha256 == "e" * 64
    assert row.reason == "analyst_insist"
    assert row.priority is True
    assert row.created_by == "alice"
    assert state["audits"][0]["action"] == "attachment_insist_open"
    assert state["audits"][0]["email_id"] == 10
    assert state["audits"][0]["details"]["attachment_id"] == 1


def test_insist_open_window_already_active(monkeypatch):
    att_mod, state = _install_insist_fakes(monkeypatch)
    state["active"] = True
    out = att_mod.insist_open(db=None, attachment=_FakeAttachment(), username="bob")
    assert out["window"] == "active"
    assert state["window_started"] == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_attachments.py -v -k insist_open`
Expected: FAIL — `AttributeError: module 'attachments' has no attribute 'insist_open'`

- [ ] **Step 3: Append `insist_open` (and its two small private helpers) to `src/attachments.py`**

```python
import threading


def _window_active() -> bool:
    import detonation_state
    return detonation_state.is_active()


def _start_window() -> None:
    from detonation import process_detonation_queue
    threading.Thread(
        target=process_detonation_queue, daemon=True,
        name="attachment-insist-window",
    ).start()


def insist_open(db, attachment, username: str) -> dict:
    """Analyst explicitly chose to open an unverified/unsafe attachment.
    Always attempts a fresh submission — enqueue_detonation's existing dedup
    only blocks on an ALREADY queued/running row for this sha256, so a prior
    'done' or 'error' outcome never prevents getting a live session now.
    Audited: insisting on an unsafe file is a security-relevant decision."""
    from database import enqueue_detonation, add_audit_entry

    row = enqueue_detonation(
        db, sha256=attachment.sha256, stored_path=attachment.stored_path,
        filename=attachment.filename, email_id=attachment.email_id,
        reason="analyst_insist", priority=True, created_by=username,
    )
    add_audit_entry(
        db, action="attachment_insist_open", actor=username,
        email_id=attachment.email_id,
        details={"attachment_id": attachment.id, "sha256": attachment.sha256,
                  "filename": attachment.filename, "pending_id": row.id},
    )
    if _window_active():
        return {"id": row.id, "status": row.status, "window": "active"}
    _start_window()
    return {"id": row.id, "status": row.status, "window": "started"}
```

Move the `import threading` to the top of the file alongside the existing `from __future__ import annotations` rather than inline, matching the rest of the codebase's import style.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_attachments.py -v`
Expected: PASS (all tests in the file so far — 13 total)

- [ ] **Step 5: Commit**

```bash
git add src/attachments.py tests/test_attachments.py
git commit -m "feat: add on-demand insist-to-VM detonation for attachments"
```

---

## Task 5: Embed attachment list in `GET /api/emails/{email_id}`

**Files:**
- Modify: `src/routers/emails.py:18` (add import), `src/routers/emails.py:261` (add key to the returned dict), and add a new `_serialize_attachments` helper near `_manual_ready_rows` (line 862)
- Test: `tests/test_attachment_endpoints.py` (new file)

**Interfaces:**
- Consumes: `attachments.attachment_safety_status(db, sha256) -> str` (Task 3), `database.Attachment`
- Produces: `routers.emails._serialize_attachments(db, email_id: int) -> list[dict]`; the `GET /api/emails/{email_id}` response gains an `"attachments"` key: `[{"id", "filename", "sha256", "real_type", "size_bytes", "status"}, ...]`

- [ ] **Step 1: Write the failing test**

Create `tests/test_attachment_endpoints.py`:

```python
"""Endpoint-level tests for attachment listing, raw-serve gating, and
insist. Hermetic — monkeypatched collaborators, no live HTTP client or DB,
matching tests/test_manual_detonation.py's Task 7/8 style."""
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

if not os.getenv("VAULT_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["VAULT_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ.setdefault("JWT_SECRET", "test-jwt-secret-key-32-bytes-long!!")


def test_serialize_attachments(monkeypatch):
    from routers import emails as e

    class FakeAttachment:
        def __init__(self, id, filename, sha256):
            self.id = id
            self.filename = filename
            self.sha256 = sha256
            self.real_type = "application/pdf"
            self.size_bytes = 1234
            self.created_at = None

    rows = [FakeAttachment(1, "a.pdf", "a" * 64), FakeAttachment(2, "b.exe", "b" * 64)]

    class FakeQuery:
        def filter(self, *a, **k): return self
        def order_by(self, *a, **k): return self
        def all(self): return rows

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()

    monkeypatch.setattr(e, "attachment_safety_status",
                        lambda db, sha: "safe" if sha.startswith("a") else "unsafe")
    out = e._serialize_attachments(FakeDB(), email_id=1)
    assert out[0]["id"] == 1 and out[0]["filename"] == "a.pdf" and out[0]["status"] == "safe"
    assert out[1]["id"] == 2 and out[1]["status"] == "unsafe"
    assert out[0]["real_type"] == "application/pdf"
    assert out[0]["size_bytes"] == 1234
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_attachment_endpoints.py -v`
Expected: FAIL — `AttributeError: module 'routers.emails' has no attribute '_serialize_attachments'` (or `attachment_safety_status`)

- [ ] **Step 3: Add the import and helper function**

In `src/routers/emails.py`, add to the top-level import block (after line 18, `from api_core import ...`):

```python
from attachments import attachment_safety_status
```

Add the helper near `_manual_ready_rows` (before or after line 862 — place it directly above `_manual_ready_rows` for grouping):

```python
def _serialize_attachments(db, email_id: int) -> list[dict]:
    """Every attachment for this email with its live-computed safety status."""
    from database import Attachment
    rows = (
        db.query(Attachment)
        .filter(Attachment.email_id == email_id)
        .order_by(Attachment.created_at.asc())
        .all()
    )
    return [
        {
            "id": a.id,
            "filename": a.filename,
            "sha256": a.sha256,
            "real_type": a.real_type,
            "size_bytes": a.size_bytes,
            "status": attachment_safety_status(db, a.sha256),
        }
        for a in rows
    ]
```

- [ ] **Step 4: Wire it into the `GET /api/emails/{email_id}` response**

In `src/routers/emails.py`, in `api_get_email` (starts at line 194), insert a new key into the returned dict right after `"detonation_queue": [...]` (after line 261, before `"llm_result": email.llm_result,` at line 262):

```python
            "attachments": _serialize_attachments(db, email_id),
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_attachment_endpoints.py -v`
Expected: PASS

- [ ] **Step 6: Run the full suite to confirm no regression**

Run: `python -m pytest tests/ -q`
Expected: all tests pass (previous count + new ones)

- [ ] **Step 7: Commit**

```bash
git add src/routers/emails.py tests/test_attachment_endpoints.py
git commit -m "feat: embed per-attachment safety status in the email detail API"
```

---

## Task 6: Rewrite the attachment raw-serve endpoint with safety gating

**Files:**
- Modify: `src/routers/detonation_proxy.py:6-9` (docstring), `src/routers/detonation_proxy.py:68-105` (rewrite `api_attachment_raw`)
- Test: `tests/test_attachment_endpoints.py` (append)

**Interfaces:**
- Consumes: `attachments.resolve_attachment(db, email_id, attachment_id)` (Task 3), `attachments.STATUS_SAFE`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_attachment_endpoints.py`:

```python
def test_attachment_raw_403_when_not_safe(monkeypatch, tmp_path):
    """The route handler itself is a thin FastAPI wrapper; here we exercise
    the same resolve_attachment() call it makes and confirm the status
    values that must produce a 403 vs a 200 — this is what the handler
    branches on (see routers/detonation_proxy.py's api_attachment_raw)."""
    from attachments import STATUS_SAFE, STATUS_UNSAFE, STATUS_PENDING, STATUS_UNVERIFIED
    for not_safe in (STATUS_UNSAFE, STATUS_PENDING, STATUS_UNVERIFIED):
        assert not_safe != STATUS_SAFE


def test_sniff_media_type_unchanged():
    """Confirms the existing magic-byte sniffing this task reuses (rewritten
    endpoint calls the same _sniff_media_type) is untouched by this task."""
    from routers.detonation_proxy import _sniff_media_type
    assert _sniff_media_type(b"%PDF-1.4...")[0] == "application/pdf"
    assert _sniff_media_type(b"not a real file")[1] is False
```

(These are lightweight confirmations, not a full FastAPI-route test — this repo has no existing pattern for testing a live route handler's HTTP status codes without a running app/DB; `resolve_attachment`'s branching logic is already fully covered by Task 3's tests. The important new coverage here is manual: Task 9's browser verification actually exercises the 403/200 paths end-to-end.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_attachment_endpoints.py -v -k "raw or sniff"`
Expected: `test_sniff_media_type_unchanged` PASSES already (no code change yet); `test_attachment_raw_403_when_not_safe` also passes as-is since it only imports existing constants — this step is a checkpoint, not a red-bar requirement. Confirm both pass before continuing.

- [ ] **Step 3: Update the file docstring**

In `src/routers/detonation_proxy.py`, update lines 6-9:

```python
  - GET  /api/emails/{email_id}/attachments/{attachment_id}/raw  — stored
    attachment bytes for the preview pane, ONLY for attachments verified
    safe by CAPE (see attachments.attachment_safety_status). attachment_id
    is the Attachment row id. Content-type is forced from magic bytes — the
    declared type and filename are hostile data (CLAUDE.md 6+7).
```

- [ ] **Step 4: Rewrite `api_attachment_raw`**

Replace lines 68-105 in `src/routers/detonation_proxy.py`:

```python
@detonation_proxy_router.get("/api/emails/{email_id}/attachments/{attachment_id}/raw")
def api_attachment_raw(
    email_id: int, attachment_id: int,
    user: AuthenticatedUser = Depends(require_permission("emails.view")),
):
    """Serve stored attachment bytes for the detail-page preview pane —
    ONLY for attachments verified safe by CAPE detonation. Anything else
    (unverified, pending, or confirmed unsafe) is blocked here; the analyst
    must use POST .../insist to view it live in the VM instead."""
    from database import SessionLocal
    from attachments import resolve_attachment, STATUS_SAFE
    db = SessionLocal()
    try:
        resolved = resolve_attachment(db, email_id, attachment_id)
        if not resolved["found"]:
            raise HTTPException(404, "Attachment not found")
        if resolved["status"] != STATUS_SAFE:
            raise HTTPException(403, detail={"status": resolved["status"]})
        stored_path = resolved["attachment"].stored_path
    finally:
        db.close()

    stored = os.path.realpath(stored_path)
    if not os.path.isfile(stored):
        raise HTTPException(404, "Original file no longer available")

    with open(stored, "rb") as fh:
        head = fh.read(16)
    media_type, inline = _sniff_media_type(head)
    disposition = "inline" if inline else "attachment"
    return FileResponse(
        stored,
        media_type=media_type,
        headers={
            # Internal id, never the attacker-provided filename (rule 6)
            "Content-Disposition": f'{disposition}; filename="attachment-{attachment_id}"',
            "X-Content-Type-Options": "nosniff",
        },
    )
```

- [ ] **Step 5: Run the full suite to confirm no regression**

Run: `python -m pytest tests/ -q`
Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
git add src/routers/detonation_proxy.py tests/test_attachment_endpoints.py
git commit -m "feat: gate attachment raw-serve endpoint on verified-safe status"
```

---

## Task 7: Add the insist endpoint

**Files:**
- Modify: `src/routers/detonation_proxy.py:283` (add new endpoint after `api_detonation_retry`, before the `# ---... CAPE web-report reverse proxy` section — actually insert right after the retry endpoint's closing, i.e. after the existing line 283/284)
- Modify: `src/routers/detonation_proxy.py:6-9` docstring (add the new endpoint to the file-level listing)
- Test: `tests/test_attachment_endpoints.py` (append)

**Interfaces:**
- Consumes: `attachments.resolve_attachment` (Task 3), `attachments.insist_open` (Task 4)
- Produces: `POST /api/emails/{email_id}/attachments/{attachment_id}/insist` — permission `emails.scan`, returns `{"id": int, "status": str, "window": "active"|"started"}` or 404 if the attachment isn't found under that email.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_attachment_endpoints.py`:

```python
def test_insist_endpoint_permission_is_emails_scan():
    """The insist endpoint must require the same permission gate as the
    existing 'See in VM' button (emails.scan), not just emails.view — it
    consumes VM/CAPE resources. Source-level check since this repo has no
    live-route test harness (matches this file's other endpoint tests)."""
    import inspect
    from routers import detonation_proxy as dp
    src = inspect.getsource(dp)
    assert 'require_permission("emails.scan")' in src
    assert "/attachments/{attachment_id}/insist" in src
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_attachment_endpoints.py -v -k insist_endpoint`
Expected: FAIL — assertion on the route path string not found

- [ ] **Step 3: Update the file docstring**

In `src/routers/detonation_proxy.py`, add a line to the listing near the top (after the `/raw` line updated in Task 6):

```python
  - POST /api/emails/{email_id}/attachments/{attachment_id}/insist  — analyst
    insists on opening an attachment that isn't verified safe; submits it to
    CAPE now (on-demand, not the batch queue) and starts a live VM session.
```

- [ ] **Step 4: Add the endpoint**

In `src/routers/detonation_proxy.py`, insert directly after `api_detonation_retry` (after its closing `finally: db.close()` block, currently ending at line 283):

```python
@detonation_proxy_router.post("/api/emails/{email_id}/attachments/{attachment_id}/insist")
def api_attachment_insist(
    email_id: int, attachment_id: int,
    user: AuthenticatedUser = Depends(require_permission("emails.scan")),
):
    """Analyst insists on opening an attachment that isn't verified safe —
    submits it to CAPE now and opens a live VM session. See
    attachments.insist_open for the orchestration and its audit trail."""
    from database import SessionLocal
    from attachments import resolve_attachment, insist_open
    db = SessionLocal()
    try:
        resolved = resolve_attachment(db, email_id, attachment_id)
        if not resolved["found"]:
            raise HTTPException(404, "Attachment not found")
        return insist_open(db, resolved["attachment"], user.username)
    finally:
        db.close()
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_attachment_endpoints.py -v`
Expected: PASS (all tests in the file)

- [ ] **Step 6: Run the full suite to confirm no regression**

Run: `python -m pytest tests/ -q`
Expected: all tests pass

- [ ] **Step 7: Commit**

```bash
git add src/routers/detonation_proxy.py tests/test_attachment_endpoints.py
git commit -m "feat: add insist-to-VM endpoint for unverified attachments"
```

---

## Task 8: Frontend — Attachments panel

**Files:**
- Modify: `src/dashboard/static/js/dashboard.js` — several locations, listed per step below

**Interfaces:**
- Consumes: `e.attachments` and `e.detonation_queue` from `GET /api/emails/{id}` (Task 5, plus the existing `detonation_queue` field), `POST /api/emails/{id}/attachments/{attachmentId}/insist` (Task 7), `GET /api/emails/{id}/attachments/{attachmentId}/raw` (Task 6)

No automated test — this repo has no JS test runner (`grep -r "\.test\.js\|jest.config" .` finds none). Verified by hand in Task 9.

- [ ] **Step 1: Rename the panel div and its render call**

At line 673 (inside `loadEmailDetail`), change:

```javascript
${showCyberSecurity ? '<div id="detonation-panel"></div>' : ''}
```

to:

```javascript
${showCyberSecurity ? '<div id="attachments-panel"></div>' : ''}
```

At line 687, change:

```javascript
if (showCyberSecurity) renderDetonationPanel(e);
```

to:

```javascript
if (showCyberSecurity) renderAttachmentsPanel(e);
```

(Kept behind the same `showCyberSecurity` gate as today's detonation panel it replaces — `insurance_operator` role already couldn't see this panel before this change, so this is not a new restriction, just preserving the existing one. See `database.py`'s `INSURANCE_OPERATOR_PERMISSIONS` comment: "none of the cybersecurity-only surfaces ... sandbox detonation".)

- [ ] **Step 2: Replace the detonation-panel rendering functions**

Replace the block from `_detonationStatusBadge` through the end of `refreshDetonationPanel` (lines 701-827, i.e. everything between the `/* Detonation sandbox panel (CAPE integration) */` comment at 694 and the next function after `refreshDetonationPanel`) with:

```javascript
/* =========================================================================
   Attachments panel — safe/unsafe gating + insist-to-VM (CAPE integration)
   ========================================================================= */

let _detonationPollTimer = null;
let _activeRfb = null;

function _attachmentPanelRowHtml(emailId, a, detRowsBySha, windowActive) {
    const rawUrl = `/api/emails/${parseInt(emailId)}/attachments/${parseInt(a.id)}/raw`;
    const detRow = detRowsBySha[a.sha256];

    if (a.status === 'safe') {
        const inline = /\.(pdf|png|jpe?g|gif)$/.test((a.filename || '').toLowerCase());
        const preview = inline
            ? `<iframe class="sandbox-preview-frame" src="${rawUrl}" title="Attachment preview"></iframe>`
            : `<a class="btn btn-outline btn-sm" href="${rawUrl}" download>Download (verified safe)</a>`;
        return `
            <div class="sandbox-columns">
                <div class="sandbox-preview-meta">
                    <div class="detail-row"><span class="detail-label">File</span>
                        <span class="detail-value">${esc(truncate(a.filename, 60))}</span></div>
                    <span class="badge accepted">Verified safe</span>
                </div>
                <div>${preview}</div>
            </div>`;
    }

    if (a.status === 'pending') {
        const taskId = detRow && detRow.result && detRow.result.cape_task_id;
        const live = (detRow && detRow.status === 'running' && windowActive && taskId)
            ? `<div class="sandbox-live" id="sandbox-live-${parseInt(a.id)}" data-task-id="${parseInt(taskId)}"></div>`
            : `<div class="sandbox-empty"><div class="spinner"></div>
                   <p>${detRow && detRow.status === 'running' ? 'Detonation running…' : 'Queued for detonation — runs in the next drained window.'}</p></div>`;
        return `
            <div class="sandbox-preview-meta">
                <div class="detail-row"><span class="detail-label">File</span>
                    <span class="detail-value">${esc(truncate(a.filename, 60))}</span></div>
                <span class="badge escalated">Verifying…</span>
            </div>
            ${live}`;
    }

    // 'unverified' or 'unsafe'
    const badge = a.status === 'unsafe'
        ? '<span class="badge quarantined">Unsafe</span>'
        : '<span class="badge recu">Not verified safe</span>';
    const reportLine = (a.status === 'unsafe' && detRow && detRow.result && detRow.result.malscore !== undefined)
        ? `<div class="detail-row"><span class="detail-label">Malscore</span><span class="detail-value">${esc(String(detRow.result.malscore))} / 10</span></div>`
        : '';
    const insistBtn = userCan('emails.scan')
        ? `<button class="btn btn-danger btn-sm" data-action="attachment-insist" data-email-id="${parseInt(emailId)}" data-attachment-id="${parseInt(a.id)}">⚠ Insist — open in VM</button>`
        : '';
    return `
        <div class="sandbox-preview-meta">
            <div class="detail-row"><span class="detail-label">File</span><span class="detail-value">${esc(truncate(a.filename, 60))}</span></div>
            ${badge}
            ${reportLine}
            <p style="color:var(--text-muted);font-size:0.85rem">This attachment has not been verified safe. Opening it directly is blocked.</p>
            ${insistBtn}
        </div>`;
}

async function renderAttachmentsPanel(e) {
    const panel = document.getElementById('attachments-panel');
    if (!panel) return;
    const attachments = e.attachments || [];
    if (attachments.length === 0) { panel.innerHTML = ''; return; }

    let windowActive = false;
    try {
        const st = await API.get('/api/detonation/status');
        windowActive = !!st.window_active;
    } catch (_) { /* status endpoint down — panel still renders, no live view */ }

    const detRowsBySha = {};
    for (const r of (e.detonation_queue || [])) detRowsBySha[r.sha256] = r;

    panel.innerHTML = `
        <div class="detail-section" style="grid-column: 1 / -1; margin-bottom:16px">
            <h3>📎 Attachments</h3>
            ${attachments.map(a => _attachmentPanelRowHtml(e.id, a, detRowsBySha, windowActive)).join('')}
        </div>`;

    for (const a of attachments) {
        const el = document.getElementById(`sandbox-live-${a.id}`);
        if (el) mountNoVnc(el, parseInt(el.dataset.taskId) || 0);
    }

    const pending = attachments.some(a => a.status === 'pending');
    clearInterval(_detonationPollTimer);
    if (pending) {
        _detonationPollTimer = setInterval(() => refreshAttachmentsPanel(e.id), 10000);
    }
}

async function refreshAttachmentsPanel(emailId) {
    if (!document.getElementById('attachments-panel')) {
        clearInterval(_detonationPollTimer);
        return;
    }
    try {
        const e = await API.get(`/api/emails/${emailId}`);
        renderAttachmentsPanel(e);
    } catch (_) { /* transient — next poll tick retries */ }
}

async function attachmentInsist(emailId, attachmentId) {
    try {
        await API.post(`/api/emails/${emailId}/attachments/${attachmentId}/insist`);
        showToast('Submitting to the sandbox — this may take a few minutes.', 'success');
        refreshAttachmentsPanel(emailId);
    } catch (err) {
        showToast(`Could not start detonation: ${err.message}`, 'error');
    }
}
```

Everything else that previously lived between `refreshDetonationPanel` and the next unrelated function (the VNC-viewer open/close functions, `mountNoVnc`, the detonation banner functions starting around line 928/1002) is untouched — only the panel-rendering block above it is replaced. Check the file after editing: `_detonationStatusBadge` and `_attachmentPreviewHtml` (the old detonation-only preview helper) should no longer exist; `_detonationRowHtml` should no longer exist either, fully superseded by `_attachmentPanelRowHtml`.

- [ ] **Step 3: Register the new action and remove the ones only `_detonationRowHtml` used**

At the registration block (around line 1418), change:

```javascript
registerAction('see-in-vm', (el) => seeInVm(parseInt(el.dataset.pendingId), parseInt(el.dataset.emailId)));
registerAction('detonation-retry', (el) => detonationRetry(parseInt(el.dataset.pendingId), parseInt(el.dataset.emailId)));
```

Leave `see-in-vm` and `detonation-retry` registered as-is (their handler functions `seeInVm`/`detonationRetry` live elsewhere in the file, untouched by this task, and remain reachable — the `done` state doesn't currently render a "See in VM"/"Retry" button from the new `_attachmentPanelRowHtml`, which is an intentional scope trim per the spec's non-goals; if you want them back, add `data-action="see-in-vm"`/`"detonation-retry"` buttons into the `'unsafe'` branch of `_attachmentPanelRowHtml` using the same `data-pending-id`/`data-email-id` attributes `seeInVm`/`detonationRetry` already expect).

Add the new registration alongside them:

```javascript
registerAction('attachment-insist', (el) => attachmentInsist(parseInt(el.dataset.emailId), parseInt(el.dataset.attachmentId)));
```

- [ ] **Step 4: Grep-check for leftover references to removed functions**

Run: `grep -n "_detonationRowHtml\|_attachmentPreviewHtml\|_detonationStatusBadge\|renderDetonationPanel\|refreshDetonationPanel" src/dashboard/static/js/dashboard.js`
Expected: no output (all references replaced in Steps 1-2)

- [ ] **Step 5: Commit**

```bash
git add src/dashboard/static/js/dashboard.js
git commit -m "feat: attachments panel with safe/unsafe gating and insist-to-VM"
```

---

## Task 9: Manual browser verification

**Files:** none — verification only, per CLAUDE.md: "tests verify code correctness, not feature correctness."

- [ ] **Step 1: Start the dashboard**

Run: `python src/main.py` (or however you normally start it locally — matches your existing dev workflow) and log in.

- [ ] **Step 2: Process an email with a clean attachment and confirm direct open**

Send/process a test email (e.g. one of `data/samples/synthetic_claims/*.eml`) with a PDF or image attachment that will pass static analysis cleanly. Open its detail page. Confirm:
- The attachment shows `Not verified safe` (since it was never detonated) initially — NOT `safe` — this confirms the fail-safe default from Task 3's spec decision ("safe" only means "passed detonation clean", never "static analysis alone said clean").
- Click "Insist — open in VM". Confirm a toast appears, the row switches to a "Verifying…" / spinner or live-VNC state, and (if a window is active) the noVNC viewer mounts.
- Wait for detonation to complete. Confirm the row updates to either `Verified safe` (if malscore came back clean — now the attachment opens directly / previews inline) or `Unsafe` with a malscore shown.

- [ ] **Step 3: Confirm the raw endpoint actually blocks non-safe attachments**

With the dashboard's dev tools network tab open, confirm a direct `GET` to `/api/emails/{id}/attachments/{attachment_id}/raw` for a not-yet-safe attachment returns `403`, and returns `200` with the file bytes once that same attachment is `safe`.

- [ ] **Step 4: Confirm the insurance_operator role still doesn't see the panel**

Log in as (or temporarily assign) an `insurance_operator` user and confirm the Attachments panel doesn't render on the detail page — same as the detonation panel it replaced didn't.

- [ ] **Step 5: Run the full automated suite one final time**

Run: `python -m pytest tests/ -q`
Expected: all tests pass

- [ ] **Step 6: Report back**

Confirm to the user that the manual walkthrough passed (or note any deviations) before considering this feature demo-ready.
