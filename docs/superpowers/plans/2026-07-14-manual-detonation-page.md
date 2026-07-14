# Manual Detonation Page Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dashboard page where an authorized operator uploads an arbitrary file, watches it detonate live in the CAPE sandbox, and sees the result recorded in a history table.

**Architecture:** ~90% reuse of the existing detonation subsystem. A new thin logic module (`src/manual_detonation.py`) holds hermetically-testable helpers; new endpoints in `routers/detonation_proxy.py` are thin wrappers over it. Uploads become `PendingDetonation` rows with `email_id=NULL`, run through the existing drain-window/VNC/report machinery. Two-branch consent modal: **Branch A** = detonate now (existing `run-window` flow); **Branch B** = deferred priority run after the email backlog clears, then a desktop-notification + sound + banner prompt before the window starts.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy (PostgreSQL), Jinja2 templates, vanilla JS, pytest.

## Global Constraints

- **Fail-safe, never fail-open.** Any failure defaults to `error`/escalate, never accept. (CLAUDE.md rule 1)
- **File names are hostile.** Never use the attacker-provided filename as a path; store under an internal id, keep original name as data only. (rule 6)
- **Declared type lies.** Verify real type via magic bytes; extension is data to analyze. (rule 7)
- **Content stays local.** Files go only to the local CAPE VM, never to any external API.
- **CSP discipline.** No new inline `onclick=`/`onchange=` handlers; wire events via `addEventListener`. Script/style CSP is `'self' 'unsafe-inline'` (do not add a nonce alongside it). (build log 2026-07-13)
- **Tests are hermetic.** No live DB, network, or CAPE. Pure-logic functions + `monkeypatch`, matching `tests/test_detonation.py` and `tests/test_cape_dashboard.py`. Add tests to `tests/test_manual_detonation.py`; each test file starts with `sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))`.
- **Run tests with:** `python -m pytest tests/test_manual_detonation.py -v` from the repo root.
- **Permission:** the new capability is `detonation.manual`; admins grant it per-user, analyst/viewer get it only when granted.
- **Accepted file types:** `CAPE_DETONABLE_EXTENSIONS` (CAPEv2's real package set — see spec §12).

---

## File Structure

- **Create** `src/manual_detonation.py` — validation, storage, upload orchestration, confirm/promote helpers (all hermetically testable).
- **Create** `tests/test_manual_detonation.py` — all tests for this feature.
- **Create** `src/dashboard/templates/manual_detonation.html` — the page.
- **Create** `src/dashboard/static/js/manual_detonation.js` — page-specific upload/modal/table JS.
- **Modify** `src/detonation_config.py` — add `CAPE_DETONABLE_EXTENSIONS`.
- **Modify** `src/database.py` — `PendingDetonation` columns + migration; `enqueue_detonation`/`get_queued_detonations` changes; `promote_deferred_detonations`, `list_manual_detonations`, `get_pending_detonation` helpers; `detonation.manual` permission.
- **Modify** `src/routers/detonation_proxy.py` — `POST /api/detonation/manual`, `GET /api/detonation/manual`, `POST /api/detonation/manual/{id}/confirm`.
- **Modify** `src/routers/emails.py` — add `manual_ready` to `/api/detonation/status`.
- **Modify** `src/main.py` — promote deferred detonations at end of `run_pipeline()`.
- **Modify** `src/routers/dashboard.py` — `/manual-detonation` page route.
- **Modify** `src/dashboard/templates/base.html` — nav link + add `detonation.manual` to the admin JS permission list.
- **Modify** `src/dashboard/static/js/dashboard.js` — global poller fires the 3-channel "ready" alert.

---

## Task 1: Accepted-extension config

**Files:**
- Modify: `src/detonation_config.py` (append after `SUPPORTED_EXTENSIONS`, ~line 63)
- Test: `tests/test_manual_detonation.py`

**Interfaces:**
- Produces: `detonation_config.CAPE_DETONABLE_EXTENSIONS: set[str]` (lowercase, dot-prefixed).

- [ ] **Step 1: Write the failing test**

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def test_cape_detonable_extensions_present():
    import detonation_config as cfg
    ext = cfg.CAPE_DETONABLE_EXTENSIONS
    # CAPE-supported types are accepted
    for e in (".exe", ".dll", ".docx", ".xlsx", ".pdf", ".js", ".msg", ".eml", ".iso", ".vhd", ".one", ".hwp"):
        assert e in ext, f"{e} should be detonable"
    # Non-detonable types are absent
    for e in (".txt", ".png", ".mp3", ".csv"):
        assert e not in ext
    # All entries are lowercase and dot-prefixed
    assert all(x.startswith(".") and x == x.lower() for x in ext)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_manual_detonation.py::test_cape_detonable_extensions_present -v`
Expected: FAIL with `AttributeError: module 'detonation_config' has no attribute 'CAPE_DETONABLE_EXTENSIONS'`

- [ ] **Step 3: Add the config**

Append to `src/detonation_config.py` after the `SUPPORTED_EXTENSIONS` block:

```python
# --------------------------------------------------------------------------
# Manual-detonation page: the FULL set CAPEv2 can detonate (broader than the
# curated auto-detonate SUPPORTED_EXTENSIONS above). Derived from CAPEv2's
# analysis-package extension map (docs usage/packages.html). Operators may
# submit any of these; CAPE aborts anything it can't handle, so we reject
# unsupported types up front. Override via env (comma-separated) to match the
# specific CAPE guest's installed packages.
# --------------------------------------------------------------------------
_DEFAULT_CAPE_DETONABLE = {
    ".mdb", ".accdb", ".class", ".iso", ".vhd", ".chm", ".url", ".cpl", ".dll",
    ".doc", ".docm", ".docx", ".eml", ".exe", ".hta", ".hwp", ".jar",
    ".js", ".jse", ".lnk", ".mht", ".build", ".msg", ".msi", ".nsis", ".one",
    ".pdf", ".ppt", ".pptm", ".pptx", ".ps1", ".pub", ".pubx", ".py", ".rar",
    ".reg", ".scr", ".sct", ".swf", ".vbs", ".vbe", ".wsf",
    ".xls", ".xlsm", ".xlsx", ".xslt", ".xps", ".zip",
}
_env_ext = os.getenv("CAPE_DETONABLE_EXTENSIONS", "").strip()
CAPE_DETONABLE_EXTENSIONS = (
    {e if e.startswith(".") else "." + e for e in
     (x.strip().lower() for x in _env_ext.split(",")) if e}
    if _env_ext else _DEFAULT_CAPE_DETONABLE
)
```

(`import os` is already present at the top of `detonation_config.py`.)

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_manual_detonation.py::test_cape_detonable_extensions_present -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/detonation_config.py tests/test_manual_detonation.py
git commit -m "feat: CAPE_DETONABLE_EXTENSIONS for manual detonation page"
```

---

## Task 2: `detonation.manual` permission

**Files:**
- Modify: `src/database.py:289-308` (`ALL_PERMISSIONS`)
- Test: `tests/test_manual_detonation.py`

**Interfaces:**
- Produces: `"detonation.manual"` key in `database.ALL_PERMISSIONS`; absent from `ANALYST_PERMISSIONS`/`VIEWER_PERMISSIONS` (default off). Enforcement reuses existing `user_has_permission(user, "detonation.manual")` and `require_permission("detonation.manual")`.

Note: no user-row migration is needed — `api_list_users` returns `permission_catalog = list(ALL_PERMISSIONS.keys())`, so the editor shows the new toggle automatically, and `user_has_permission` returns `False` via `.get(perm, False)` for users whose stored JSON lacks the key.

- [ ] **Step 1: Write the failing test**

```python
def test_detonation_manual_permission_registered():
    import database as db
    assert "detonation.manual" in db.ALL_PERMISSIONS
    # Off by default for non-admin roles — admin must grant it explicitly
    assert "detonation.manual" not in db.ANALYST_PERMISSIONS
    assert "detonation.manual" not in db.VIEWER_PERMISSIONS


def test_detonation_manual_permission_enforced():
    import database as db

    class U:
        def __init__(self, role, perms):
            self.role = role
            self.permissions = perms

    assert db.user_has_permission(U("admin", {}), "detonation.manual") is True
    assert db.user_has_permission(U("analyst", {}), "detonation.manual") is False
    assert db.user_has_permission(U("analyst", {"detonation.manual": True}), "detonation.manual") is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_manual_detonation.py -k permission -v`
Expected: FAIL on `assert "detonation.manual" in db.ALL_PERMISSIONS`

- [ ] **Step 3: Add the permission**

In `src/database.py`, add to the `ALL_PERMISSIONS` dict (after the `"users.manage": True,` line, before the closing brace):

```python
    "detonation.manual": True,   # upload + detonate an arbitrary file in the sandbox
```

Do **not** add it to `ANALYST_PERMISSIONS` or `VIEWER_PERMISSIONS`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_manual_detonation.py -k permission -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add src/database.py tests/test_manual_detonation.py
git commit -m "feat: detonation.manual permission (grantable, off by default)"
```

---

## Task 3: `PendingDetonation` columns + migration + queue changes

**Files:**
- Modify: `src/database.py:254-279` (model), migration section near `_migrate_users_rbac`, and `src/database.py:642-676` (`enqueue_detonation`, `get_queued_detonations`)
- Test: `tests/test_manual_detonation.py`

**Interfaces:**
- Produces:
  - `PendingDetonation.created_by` (nullable str), `PendingDetonation.priority` (bool, default False).
  - `enqueue_detonation(db, sha256, stored_path, filename=None, email_id=None, idempotency_key=None, reason=None, created_by=None, priority=False, status="queued")`.
  - `get_queued_detonations` orders `priority DESC, created_at ASC`.
  - `_migrate_pending_detonation_manual()` — idempotent ALTER TABLE, called at startup.

Testing note: the model/migration/query touch PostgreSQL + JSONB, which the hermetic suite cannot spin up. This task's automated test asserts the **signature and defaults** via `inspect.signature` (no DB); ordering/migration are checked in the final live-verification task (Task 11).

- [ ] **Step 1: Write the failing test**

```python
def test_enqueue_detonation_signature():
    import inspect, database as db
    sig = inspect.signature(db.enqueue_detonation)
    for p in ("created_by", "priority", "status"):
        assert p in sig.parameters, f"enqueue_detonation missing {p}"
    assert sig.parameters["priority"].default is False
    assert sig.parameters["status"].default == "queued"


def test_pending_detonation_has_manual_columns():
    import database as db
    cols = db.PendingDetonation.__table__.columns.keys()
    assert "created_by" in cols
    assert "priority" in cols
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_manual_detonation.py -k "signature or manual_columns" -v`
Expected: FAIL (`created_by` not in signature / columns)

- [ ] **Step 3a: Add model columns**

In `src/database.py`, inside `class PendingDetonation`, after the `attempts` column (~line 273):

```python
    created_by = Column(String(255), nullable=True)   # operator username (manual uploads)
    priority = Column(Boolean, nullable=False, default=False)  # manual rows jump the queue
```

Ensure `Boolean` is imported from sqlalchemy at the top of the file (add to the existing `from sqlalchemy import ...` line if missing).

- [ ] **Step 3b: Add the migration function**

After `_migrate_users_rbac()` in `src/database.py`, add:

```python
def _migrate_pending_detonation_manual():
    """One-time: add manual-detonation columns to an existing pending_detonation table."""
    from sqlalchemy import inspect, text as sa_text
    try:
        inspector = inspect(engine)
        if "pending_detonation" not in inspector.get_table_names():
            return  # create_all will make it with the columns already
        existing = {c["name"] for c in inspector.get_columns("pending_detonation")}
        new_cols = {
            "created_by": "VARCHAR(255)",
            "priority": "BOOLEAN NOT NULL DEFAULT FALSE",
        }
        with engine.begin() as conn:
            for name, ddl in new_cols.items():
                if name not in existing:
                    conn.execute(sa_text(f'ALTER TABLE pending_detonation ADD COLUMN "{name}" {ddl}'))
                    print(f"[DB] Added column pending_detonation.{name}")
    except Exception as e:
        print(f"[DB] pending_detonation manual migration skipped: {e}")
```

Call it where `_migrate_users_rbac()` is called at startup (find the call site and add `_migrate_pending_detonation_manual()` immediately after it).

- [ ] **Step 3c: Update `enqueue_detonation`**

Replace the signature and body of `enqueue_detonation` (lines ~642-665):

```python
def enqueue_detonation(db: Session, sha256: str, stored_path: str,
                       filename: Optional[str] = None, email_id: Optional[int] = None,
                       idempotency_key: Optional[str] = None,
                       reason: Optional[str] = None,
                       created_by: Optional[str] = None,
                       priority: bool = False,
                       status: str = "queued") -> Optional["PendingDetonation"]:
    """Queue an attachment for detonation. De-dupes on (sha256) while queued/running."""
    existing = db.query(PendingDetonation).filter(
        PendingDetonation.sha256 == sha256,
        PendingDetonation.status.in_(["queued", "running"]),
    ).first()
    if existing:
        return existing
    row = PendingDetonation(
        email_id=email_id,
        idempotency_key=idempotency_key,
        sha256=sha256,
        filename=filename,
        stored_path=stored_path,
        reason=reason,
        status=status,
        created_by=created_by,
        priority=priority,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row
```

- [ ] **Step 3d: Update `get_queued_detonations` ordering**

Replace its `.order_by(...)` line so priority rows come first:

```python
        .order_by(PendingDetonation.priority.desc(), PendingDetonation.created_at.asc())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_manual_detonation.py -k "signature or manual_columns" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/database.py tests/test_manual_detonation.py
git commit -m "feat: PendingDetonation created_by/priority columns + migration + priority ordering"
```

---

## Task 4: DB helpers — list, promote, get-by-id

**Files:**
- Modify: `src/database.py` (after `count_queued_detonations`, ~line 681)
- Test: `tests/test_manual_detonation.py`

**Interfaces:**
- Produces:
  - `list_manual_detonations(db, limit=100) -> list[PendingDetonation]` — rows where `email_id IS NULL`, newest first.
  - `promote_deferred_detonations(db) -> int` — flips every `status=="deferred"` row to `"ready"`; returns count promoted.
  - `get_pending_detonation(db, pending_id) -> Optional[PendingDetonation]`.

These are thin query wrappers. They are exercised against a **fake db** in tests (record-and-assert), matching the repo's monkeypatch style.

- [ ] **Step 1: Write the failing test**

```python
def test_promote_deferred_detonations_flips_status():
    import database as db

    class Row:
        def __init__(self, status):
            self.status = status

    rows = [Row("deferred"), Row("deferred")]

    class FakeQuery:
        def filter(self, *a, **k): return self
        def all(self): return rows

    class FakeDB:
        def __init__(self): self.committed = False
        def query(self, *a, **k): return FakeQuery()
        def commit(self): self.committed = True

    fake = FakeDB()
    n = db.promote_deferred_detonations(fake)
    assert n == 2
    assert all(r.status == "ready" for r in rows)
    assert fake.committed is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_manual_detonation.py -k promote -v`
Expected: FAIL (`module 'database' has no attribute 'promote_deferred_detonations'`)

- [ ] **Step 3: Add the helpers**

Append to `src/database.py` after `count_queued_detonations`:

```python
def list_manual_detonations(db: Session, limit: int = 100) -> list["PendingDetonation"]:
    """Manual (non-email) detonations, newest first, for the manual-detonation page."""
    return (
        db.query(PendingDetonation)
        .filter(PendingDetonation.email_id.is_(None))
        .order_by(PendingDetonation.created_at.desc())
        .limit(limit)
        .all()
    )


def promote_deferred_detonations(db: Session) -> int:
    """Flip Branch-B 'deferred' rows to 'ready' once the email backlog is clear.
    Called at the end of a pipeline tick. Returns the number promoted."""
    rows = db.query(PendingDetonation).filter(PendingDetonation.status == "deferred").all()
    for r in rows:
        r.status = "ready"
    if rows:
        db.commit()
    return len(rows)


def get_pending_detonation(db: Session, pending_id: int) -> Optional["PendingDetonation"]:
    return db.query(PendingDetonation).filter(PendingDetonation.id == pending_id).first()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_manual_detonation.py -k promote -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/database.py tests/test_manual_detonation.py
git commit -m "feat: list_manual_detonations, promote_deferred_detonations, get_pending_detonation"
```

---

## Task 5: Upload validation + storage (pure/filesystem logic)

**Files:**
- Create: `src/manual_detonation.py`
- Test: `tests/test_manual_detonation.py`

**Interfaces:**
- Produces:
  - `MANUAL_UPLOAD_DIR: str` — storage directory (created on import).
  - `MAX_UPLOAD_BYTES = 50 * 1024 * 1024`.
  - `validate_upload(size: int, original_filename: str) -> Optional[str]` — returns an error message, or `None` if OK.
  - `store_upload(content: bytes, original_filename: str) -> tuple[str, str]` — returns `(stored_path, sha256)`. Path uses an internal id, never the original name.

- [ ] **Step 1: Write the failing test**

```python
def test_validate_upload():
    import manual_detonation as m
    assert m.validate_upload(1000, "invoice.pdf") is None
    assert m.validate_upload(1000, "malware.exe") is None
    # unsupported extension
    assert "cannot detonate" in (m.validate_upload(1000, "notes.txt") or "").lower()
    assert "cannot detonate" in (m.validate_upload(1000, "photo.png") or "").lower()
    # oversized
    assert "too large" in (m.validate_upload(m.MAX_UPLOAD_BYTES + 1, "big.exe") or "").lower()
    # empty
    assert m.validate_upload(0, "x.exe") is not None
    # double extension resolves to the REAL last extension (.exe → supported)
    assert m.validate_upload(1000, "invoice.pdf.exe") is None


def test_store_upload_uses_internal_id(tmp_path, monkeypatch):
    import manual_detonation as m
    import hashlib
    monkeypatch.setattr(m, "MANUAL_UPLOAD_DIR", str(tmp_path))
    content = b"MZ fake exe bytes"
    path, sha = store_and_check = m.store_upload(content, "../../evil name.exe")
    assert sha == hashlib.sha256(content).hexdigest()
    # stored under the sandbox dir, filename does NOT contain attacker path
    assert str(tmp_path) in os.path.realpath(path)
    assert "evil name" not in os.path.basename(path)
    assert ".." not in os.path.basename(path)
    with open(path, "rb") as fh:
        assert fh.read() == content
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_manual_detonation.py -k "validate_upload or store_upload" -v`
Expected: FAIL (`No module named 'manual_detonation'`)

- [ ] **Step 3: Create the module**

Create `src/manual_detonation.py`:

```python
"""manual_detonation.py — operator-driven, arbitrary-file detonation.

Thin, hermetically-testable logic behind the Manual Detonation page. The
FastAPI endpoints in routers/detonation_proxy.py are thin wrappers over this.

Security (CLAUDE.md): the uploaded file is stored under an internal id (never
the attacker filename, rule 6), typed by magic bytes downstream (rule 7), and
only ever submitted to the LOCAL CAPE VM — never to any external service.
"""
from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import Optional

import detonation_config as cfg

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
MANUAL_UPLOAD_DIR = str(_PROJECT_ROOT / "data" / "manual_detonations")
os.makedirs(MANUAL_UPLOAD_DIR, exist_ok=True)


def _real_ext(original_filename: str) -> str:
    return os.path.splitext(original_filename or "")[1].lower()


def validate_upload(size: int, original_filename: str) -> Optional[str]:
    """Return an operator-facing error string, or None if the upload is allowed."""
    if size <= 0:
        return "The uploaded file is empty."
    if size > MAX_UPLOAD_BYTES:
        return f"File is too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)."
    ext = _real_ext(original_filename)
    if ext not in cfg.CAPE_DETONABLE_EXTENSIONS:
        return (f"CAPEv2 cannot detonate '{ext or 'this'}' files. "
                f"Supported types include .exe, .dll, .pdf, Office docs, scripts, archives.")
    return None


def store_upload(content: bytes, original_filename: str) -> tuple[str, str]:
    """Persist bytes under an internal id. Returns (stored_path, sha256).

    The on-disk name is an internal UUID + the real extension only; the
    attacker-supplied filename never touches the path."""
    sha = hashlib.sha256(content).hexdigest()
    ext = _real_ext(original_filename)
    internal_name = f"{uuid.uuid4().hex}{ext}"
    stored_path = os.path.join(MANUAL_UPLOAD_DIR, internal_name)
    with open(stored_path, "wb") as fh:
        fh.write(content)
    return stored_path, sha
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_manual_detonation.py -k "validate_upload or store_upload" -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/manual_detonation.py tests/test_manual_detonation.py
git commit -m "feat: manual detonation upload validation + safe storage"
```

---

## Task 6: Upload orchestration (branch A/B) + confirm

**Files:**
- Modify: `src/manual_detonation.py`
- Test: `tests/test_manual_detonation.py`

**Interfaces:**
- Consumes: `store_upload`, `validate_upload`, `database.enqueue_detonation`, `database.add_audit_entry`, `database.SessionLocal`, `detonation_state.is_active`, and `detonation.process_detonation_queue` (started on a daemon thread).
- Produces:
  - `handle_upload(content: bytes, original_filename: str, branch: str, username: str) -> dict`
    - `branch == "now"` → enqueue `status="queued"`, then trigger the drain window unless one is active. Returns `{"id", "status": "queued", "window": "started"|"active"}`.
    - `branch == "queue"` → enqueue `status="deferred", priority=True`, no window. Returns `{"id", "status": "deferred"}`.
    - On validation failure → returns `{"error": "<message>"}` (caller maps to HTTP 400).
  - `confirm_ready(pending_id: int, username: str) -> dict` — flips a `ready` row to `queued`, triggers the window. Returns `{"id", "status": "queued", "window": ...}` or `{"error": ...}`.
  - `_start_window()` — spawns `process_detonation_queue` on a daemon thread (extracted so tests monkeypatch it).

- [ ] **Step 1: Write the failing test**

```python
def _install_fakes(monkeypatch):
    """Wire manual_detonation to in-memory fakes; return a state dict."""
    import manual_detonation as m
    state = {"enqueued": [], "audits": [], "window_started": 0, "active": False, "rows": {}}

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
                      status=status)
        state["enqueued"].append(row)
        state["rows"][row.id] = row
        return row

    def fake_audit(db, action, actor, email_id=None, details=None):
        state["audits"].append({"action": action, "actor": actor, "details": details})

    class FakeDB:
        def close(self): pass
    monkeypatch.setattr(m, "SessionLocal", lambda: FakeDB())
    monkeypatch.setattr(m, "enqueue_detonation", fake_enqueue)
    monkeypatch.setattr(m, "add_audit_entry", fake_audit)
    monkeypatch.setattr(m, "get_pending_detonation", lambda db, pid: state["rows"].get(pid))
    monkeypatch.setattr(m, "_start_window", lambda: state.__setitem__("window_started", state["window_started"] + 1))
    monkeypatch.setattr(m, "_window_active", lambda: state["active"])
    monkeypatch.setattr(m, "store_upload", lambda content, name: ("/tmp/x.exe", "a" * 64))
    return m, state


def test_handle_upload_branch_now(monkeypatch):
    m, state = _install_fakes(monkeypatch)
    out = m.handle_upload(b"MZ...", "sample.exe", "now", "alice")
    assert out["status"] == "queued"
    assert out["window"] == "started"
    row = state["enqueued"][0]
    assert row.email_id is None and row.priority is False and row.status == "queued"
    assert row.created_by == "alice"
    assert state["window_started"] == 1
    assert state["audits"][0]["action"] == "detonation_manual_upload"
    assert state["audits"][0]["details"]["branch"] == "now"


def test_handle_upload_branch_now_window_active(monkeypatch):
    m, state = _install_fakes(monkeypatch)
    state["active"] = True
    out = m.handle_upload(b"MZ...", "sample.exe", "now", "alice")
    assert out["status"] == "queued"
    assert out["window"] == "active"
    assert state["window_started"] == 0  # not started again


def test_handle_upload_branch_queue(monkeypatch):
    m, state = _install_fakes(monkeypatch)
    out = m.handle_upload(b"MZ...", "sample.exe", "queue", "bob")
    assert out["status"] == "deferred"
    row = state["enqueued"][0]
    assert row.status == "deferred" and row.priority is True
    assert state["window_started"] == 0


def test_handle_upload_rejects_bad_type(monkeypatch):
    m, state = _install_fakes(monkeypatch)
    out = m.handle_upload(b"hi", "notes.txt", "now", "alice")
    assert "error" in out and "cannot detonate" in out["error"].lower()
    assert state["enqueued"] == []


def test_confirm_ready_promotes_and_starts(monkeypatch):
    m, state = _install_fakes(monkeypatch)
    # seed a ready row
    m.handle_upload(b"MZ...", "sample.exe", "queue", "bob")
    row = state["enqueued"][0]
    row.status = "ready"
    out = m.confirm_ready(row.id, "bob")
    assert out["status"] == "queued"
    assert row.status == "queued"
    assert state["window_started"] == 1


def test_confirm_ready_rejects_non_ready(monkeypatch):
    m, state = _install_fakes(monkeypatch)
    m.handle_upload(b"MZ...", "sample.exe", "now", "alice")
    row = state["enqueued"][0]  # status "queued", not "ready"
    out = m.confirm_ready(row.id, "alice")
    assert "error" in out
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_manual_detonation.py -k "handle_upload or confirm_ready" -v`
Expected: FAIL (`handle_upload` not defined)

- [ ] **Step 3: Implement orchestration**

Append to `src/manual_detonation.py`:

```python
import threading

from database import (
    SessionLocal, enqueue_detonation, add_audit_entry,
    get_pending_detonation, promote_deferred_detonations,  # noqa: F401 (promote used by main.py)
)


def _window_active() -> bool:
    import detonation_state
    return detonation_state.is_active()


def _start_window() -> None:
    from detonation import process_detonation_queue
    threading.Thread(
        target=process_detonation_queue, daemon=True,
        name="manual-detonation-window",
    ).start()


def handle_upload(content: bytes, original_filename: str, branch: str, username: str) -> dict:
    """Validate, store, enqueue, audit. branch is 'now' (Branch A) or 'queue' (Branch B)."""
    err = validate_upload(len(content or b""), original_filename)
    if err:
        return {"error": err}
    if branch not in ("now", "queue"):
        return {"error": "Unknown branch."}

    stored_path, sha = store_upload(content, original_filename)
    status = "queued" if branch == "now" else "deferred"
    priority = branch == "queue"

    db = SessionLocal()
    try:
        row = enqueue_detonation(
            db, sha256=sha, stored_path=stored_path, filename=original_filename,
            email_id=None, reason="manual upload", created_by=username,
            priority=priority, status=status,
        )
        add_audit_entry(
            db, action="detonation_manual_upload", actor=username,
            details={"pending_id": row.id, "sha256": sha,
                     "filename": original_filename, "branch": branch},
        )
    finally:
        db.close()

    if branch == "queue":
        return {"id": row.id, "status": "deferred"}

    if _window_active():
        return {"id": row.id, "status": "queued", "window": "active"}
    _start_window()
    return {"id": row.id, "status": "queued", "window": "started"}


def confirm_ready(pending_id: int, username: str) -> dict:
    """Operator pressed OK on a Branch-B 'ready' row: promote to queued + start window."""
    db = SessionLocal()
    try:
        row = get_pending_detonation(db, pending_id)
        if not row:
            return {"error": "Detonation not found."}
        if row.status != "ready":
            return {"error": f"Not awaiting confirmation (status: {row.status})."}
        row.status = "queued"
        db.commit()
        add_audit_entry(
            db, action="detonation_manual_confirm", actor=username,
            details={"pending_id": row.id, "sha256": row.sha256},
        )
    finally:
        db.close()

    if _window_active():
        return {"id": pending_id, "status": "queued", "window": "active"}
    _start_window()
    return {"id": pending_id, "status": "queued", "window": "started"}
```

Note: the test monkeypatches `m.SessionLocal`, `m.enqueue_detonation`, `m.add_audit_entry`, `m.get_pending_detonation`, `m._start_window`, `m._window_active`, `m.store_upload` — all module-level names, so the `from database import ...` binding is what gets replaced. This is why they are imported at module top (not inside functions).

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_manual_detonation.py -k "handle_upload or confirm_ready" -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add src/manual_detonation.py tests/test_manual_detonation.py
git commit -m "feat: manual detonation upload orchestration + Branch B confirm"
```

---

## Task 7: API endpoints (upload, list, confirm)

**Files:**
- Modify: `src/routers/detonation_proxy.py` (append endpoints)
- Test: `tests/test_manual_detonation.py`

**Interfaces:**
- Consumes: `manual_detonation.handle_upload/confirm_ready`, `database.list_manual_detonations`, `require_permission("detonation.manual")`.
- Produces:
  - `POST /api/detonation/manual` — `UploadFile` + `branch` form field. 400 on `{"error": ...}`.
  - `GET /api/detonation/manual` — list rows (`email_id IS NULL`) as JSON with `Cache-Control: private, max-age=5`.
  - `POST /api/detonation/manual/{pending_id}/confirm`.
- The list-serialization helper `_serialize_manual(row) -> dict` is unit-tested directly (no HTTP).

- [ ] **Step 1: Write the failing test**

```python
def test_serialize_manual_row():
    from routers import detonation_proxy as dp

    class Row:
        id = 7
        filename = "sample.exe"
        sha256 = "a" * 64
        status = "done"
        created_by = "alice"
        reason = "manual upload"
        result = {"malscore": 8.5, "escalate": True, "cape_task_id": 42}
        created_at = None
        updated_at = None

    out = dp._serialize_manual(Row())
    assert out["id"] == 7
    assert out["filename"] == "sample.exe"
    assert out["malscore"] == 8.5
    assert out["escalate"] is True
    assert out["cape_task_id"] == 42
    assert out["created_by"] == "alice"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_manual_detonation.py -k serialize_manual -v`
Expected: FAIL (`_serialize_manual` not defined)

- [ ] **Step 3: Add the endpoints**

Append to `src/routers/detonation_proxy.py`:

```python
# ---------------------------------------------------------------------------
# Manual detonation page — upload an arbitrary file and watch it run
# ---------------------------------------------------------------------------

from fastapi import UploadFile, File, Form
from fastapi.responses import JSONResponse


def _serialize_manual(row) -> dict:
    result = row.result or {}
    return {
        "id": row.id,
        "filename": row.filename,
        "sha256": row.sha256,
        "status": row.status,
        "created_by": row.created_by,
        "reason": row.reason,
        "malscore": result.get("malscore"),
        "escalate": result.get("escalate"),
        "cape_task_id": result.get("cape_task_id"),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@detonation_proxy_router.post("/api/detonation/manual")
async def api_detonation_manual_upload(
    file: UploadFile = File(...),
    branch: str = Form(...),
    user: AuthenticatedUser = Depends(require_permission("detonation.manual")),
):
    """Upload a file to detonate. branch='now' (drain immediately) or 'queue'
    (priority-defer until the email backlog clears, then operator confirms)."""
    import manual_detonation as md
    content = await file.read()
    out = md.handle_upload(content, file.filename or "sample.bin", branch, user.username)
    if "error" in out:
        return JSONResponse({"success": False, "error": out["error"]}, status_code=400)
    return {"success": True, **out}


@detonation_proxy_router.get("/api/detonation/manual")
def api_detonation_manual_list(
    user: AuthenticatedUser = Depends(require_permission("detonation.manual")),
):
    """History of manual (non-email) detonations for the page table."""
    from database import SessionLocal, list_manual_detonations
    db = SessionLocal()
    try:
        rows = [_serialize_manual(r) for r in list_manual_detonations(db)]
    finally:
        db.close()
    return JSONResponse(
        {"detonations": rows},
        headers={"Cache-Control": "private, max-age=5"},
    )


@detonation_proxy_router.post("/api/detonation/manual/{pending_id}/confirm")
def api_detonation_manual_confirm(
    pending_id: int,
    user: AuthenticatedUser = Depends(require_permission("detonation.manual")),
):
    """Branch B: operator confirms a 'ready' file — promote + start the window."""
    import manual_detonation as md
    out = md.confirm_ready(pending_id, user.username)
    if "error" in out:
        return JSONResponse({"success": False, "error": out["error"]}, status_code=409)
    return {"success": True, **out}
```

Confirm `require_permission` and `AuthenticatedUser` are already imported at the top of `detonation_proxy.py` (they are — used by existing endpoints).

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_manual_detonation.py -k serialize_manual -v`
Expected: PASS

- [ ] **Step 5: Import-sanity + commit**

Run: `python -c "import sys; sys.path.insert(0,'src'); import routers.detonation_proxy"`
Expected: no error.

```bash
git add src/routers/detonation_proxy.py tests/test_manual_detonation.py
git commit -m "feat: manual detonation API — upload, list, confirm endpoints"
```

---

## Task 8: Branch B promotion hook + status surfacing

**Files:**
- Modify: `src/main.py` (`run_pipeline`, near the normal-completion end and the early idle returns)
- Modify: `src/routers/emails.py:844-896` (`api_detonation_status`)
- Test: `tests/test_manual_detonation.py`

**Interfaces:**
- Consumes: `database.promote_deferred_detonations`, `database.list_manual_detonations`.
- Produces: `/api/detonation/status` response gains `manual_ready: [{id, filename, sha256}]` (rows with `status=="ready"`, `email_id IS NULL`). The `_manual_ready_rows(db) -> list[dict]` helper is unit-tested.

- [ ] **Step 1: Write the failing test**

```python
def test_manual_ready_rows_filters_ready():
    from routers import emails as e

    class Row:
        def __init__(self, id, status, email_id):
            self.id = id; self.status = status; self.email_id = email_id
            self.filename = f"f{id}.exe"; self.sha256 = "b" * 64

    rows = [Row(1, "ready", None), Row(2, "done", None), Row(3, "ready", None)]

    class FakeDB:
        def close(self): pass

    # list_manual_detonations returns all manual rows; helper filters to ready
    import routers.emails as em
    em.list_manual_detonations = lambda db, limit=100: rows  # monkeypatch-ish
    out = e._manual_ready_rows(FakeDB())
    ids = [r["id"] for r in out]
    assert ids == [1, 3]
    assert out[0]["filename"] == "f1.exe"
```

(If assigning `em.list_manual_detonations` directly is awkward, use `monkeypatch.setattr` with the `monkeypatch` fixture — add it to the test signature.)

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_manual_detonation.py -k manual_ready_rows -v`
Expected: FAIL (`_manual_ready_rows` not defined)

- [ ] **Step 3a: Add the helper + surface it in the status endpoint**

At the top of `src/routers/emails.py`, ensure `list_manual_detonations` is importable (it lives in `database`). Add near the other detonation helpers:

```python
def _manual_ready_rows(db) -> list[dict]:
    """Branch-B rows awaiting operator confirmation (status 'ready', no email)."""
    from database import list_manual_detonations
    out = []
    for r in list_manual_detonations(db):
        if r.status == "ready":
            out.append({"id": r.id, "filename": r.filename, "sha256": r.sha256})
    return out
```

In `api_detonation_status`, inside the `try:` where `db` is open, compute `manual_ready = _manual_ready_rows(db)` and add `"manual_ready": manual_ready` to the returned dict.

- [ ] **Step 3b: Promote deferred rows at the end of a pipeline tick**

In `src/main.py`, in `run_pipeline()`, at the **normal end** of a successful run (after analysis completes, before the function returns), add:

```python
    # Branch-B manual detonations: the email backlog for this tick is now
    # cleared, so any deferred manual file becomes 'ready' for the operator.
    try:
        from database import SessionLocal as _SL, promote_deferred_detonations as _promote
        _db = _SL()
        try:
            n = _promote(_db)
            if n:
                print(f"[DETONATION] {n} deferred manual detonation(s) now READY for operator confirmation")
        finally:
            _db.close()
    except Exception as _e:
        print(f"[DETONATION] deferred promotion skipped: {_e}")
```

Place this so it runs whenever a tick finishes having done its analysis work (the natural end of `run_pipeline`). Do **not** place it before the `detonation_state.is_active()` / Ollama-down early returns — a paused/deferred tick did not analyze anything, so it must not claim the backlog is clear.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_manual_detonation.py -k manual_ready_rows -v`
Expected: PASS

- [ ] **Step 5: Import-sanity + commit**

Run: `python -c "import sys; sys.path.insert(0,'src'); import main, routers.emails"`
Expected: no error.

```bash
git add src/main.py src/routers/emails.py tests/test_manual_detonation.py
git commit -m "feat: promote deferred detonations on backlog-clear + surface manual_ready in status"
```

---

## Task 9: Page route, template, nav link, CSP

**Files:**
- Modify: `src/routers/dashboard.py` (add route after `/admin`)
- Create: `src/dashboard/templates/manual_detonation.html`
- Modify: `src/dashboard/templates/base.html` (nav link + admin JS perm list)
- No test (template/route wiring — verified live in Task 11).

- [ ] **Step 1: Add the page route**

In `src/routers/dashboard.py`, after `dashboard_admin` (line ~95):

```python
@dashboard_router.get("/manual-detonation", response_class=HTMLResponse)
async def dashboard_manual_detonation(request: Request):
    ctx = _ctx(request, "manual_detonation")
    if not _has_perm(ctx, "detonation.manual"):
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "manual_detonation.html", ctx)
```

- [ ] **Step 2: Add the nav link**

In `src/dashboard/templates/base.html`, after the User Management block (line ~74, before the closing `</div>` of `sidebar-nav`):

```html
                {% if role == 'admin' or permissions.get('detonation.manual', False) %}
                <a href="/manual-detonation" class="nav-link {% if active_page == 'manual_detonation' %}active{% endif %}">
                    <span class="nav-icon">🧨</span>
                    <span>Manual Detonation</span>
                </a>
                {% endif %}
```

- [ ] **Step 3: Add `detonation.manual` to the admin JS permission list**

In `base.html` line ~152, add `'detonation.manual'` to the array literal so admins' `userCan('detonation.manual')` returns true:

```javascript
            {% for p in ['emails.view','emails.release','emails.quarantine','emails.override','emails.revert','emails.bulk','emails.scan','blocklist.view','blocklist.manage','whitelist.view','whitelist.manage','audit.view','reports.view','health.view','alerts.view','alerts.acknowledge','export.csv','users.manage','detonation.manual'] %}
```

- [ ] **Step 4: Create the template**

Create `src/dashboard/templates/manual_detonation.html`:

```html
{% extends "base.html" %}
{% block title %}Manual Detonation — Attijari SOC{% endblock %}
{% block content %}
<div class="page-header" style="display:flex;align-items:center;justify-content:space-between;gap:16px;">
  <div>
    <h2>🧨 Manual Detonation</h2>
    <p style="color:var(--text-muted);font-size:0.88rem;">
      Upload a file to run in the isolated CAPE sandbox and watch it live.
      The file is stored locally and only sent to the sandbox VM.
    </p>
  </div>
  <button class="btn btn-primary" id="md-attach-btn">➕ Attach file &amp; detonate</button>
  <input type="file" id="md-file-input" style="display:none">
</div>

<div id="md-table-wrap" class="card" style="margin-top:16px;">
  <table class="data-table" id="md-table">
    <thead>
      <tr><th>File</th><th>SHA-256</th><th>Malscore</th><th>Verdict</th><th>Status</th><th>Operator</th><th>When</th><th></th></tr>
    </thead>
    <tbody id="md-tbody">
      <tr><td colspan="8" style="text-align:center;color:var(--text-muted);">No manual detonations yet.</td></tr>
    </tbody>
  </table>
</div>

<!-- Two-outcome consent modal -->
<div class="modal-overlay" id="md-modal-overlay">
  <div class="modal">
    <h3>How should this run?</h3>
    <p id="md-modal-file" style="color:var(--text-muted);font-size:0.85rem;margin-bottom:12px;"></p>
    <div class="btn-group" style="flex-direction:column;gap:10px;align-items:stretch;">
      <button class="btn btn-danger" id="md-branch-now">
        ⛔ Open now — stop email analysis and detonate immediately
      </button>
      <button class="btn btn-outline" id="md-branch-queue">
        🕒 Priority queue — finish current emails first, then alert me to open it
      </button>
      <button class="btn btn-outline" id="md-branch-cancel">Cancel</button>
    </div>
    <p style="color:var(--text-muted);font-size:0.78rem;margin-top:12px;">
      While the sandbox window is active, email analysis is suspended and unread mail stays on the IMAP server.
    </p>
  </div>
</div>
{% endblock %}
{% block scripts %}
<script src="{{ static_v('js/manual_detonation.js') }}"></script>
{% endblock %}
```

(If class names like `card`/`data-table`/`btn-danger` don't exist in `dashboard.css`, reuse the closest existing classes seen in `admin.html`/`inbox.html`; the structure matters more than exact class names.)

- [ ] **Step 5: Import-sanity + commit**

Run: `python -c "import sys; sys.path.insert(0,'src'); import routers.dashboard"`
Expected: no error.

```bash
git add src/routers/dashboard.py src/dashboard/templates/manual_detonation.html src/dashboard/templates/base.html
git commit -m "feat: manual detonation page route, template, nav link"
```

---

## Task 10: Frontend JS — upload, table, 3-channel ready alert

**Files:**
- Create: `src/dashboard/static/js/manual_detonation.js`
- Modify: `src/dashboard/static/js/dashboard.js` (global ready-alert in the existing detonation-status poller)
- No unit test (browser behavior — verified live in Task 11).

- [ ] **Step 1: Create the page JS**

Create `src/dashboard/static/js/manual_detonation.js`:

```javascript
// Manual Detonation page — upload, two-outcome modal, history table.
(function () {
  const attachBtn = document.getElementById("md-attach-btn");
  const fileInput = document.getElementById("md-file-input");
  const modal = document.getElementById("md-modal-overlay");
  const modalFile = document.getElementById("md-modal-file");
  let pendingFile = null;

  if (!attachBtn) return; // not on this page

  // Ask for desktop-notification permission up front (needs a user gesture on some browsers)
  attachBtn.addEventListener("click", () => {
    if ("Notification" in window && Notification.permission === "default") {
      Notification.requestPermission();
    }
    fileInput.click();
  });

  fileInput.addEventListener("change", () => {
    if (!fileInput.files.length) return;
    pendingFile = fileInput.files[0];
    modalFile.textContent = `${pendingFile.name} (${Math.round(pendingFile.size / 1024)} KB)`;
    modal.classList.add("open");
  });

  function closeModal() { modal.classList.remove("open"); fileInput.value = ""; }
  document.getElementById("md-branch-cancel").addEventListener("click", closeModal);

  async function submit(branch) {
    if (!pendingFile) return;
    const fd = new FormData();
    fd.append("file", pendingFile);
    fd.append("branch", branch);
    modal.classList.remove("open");
    try {
      const r = await fetch("/api/detonation/manual", { method: "POST", body: fd });
      const data = await r.json();
      if (!data.success) { alert(data.error || "Upload failed"); }
      else if (branch === "queue") { toast("Queued with priority — you'll be alerted when it's ready."); }
      else if (data.window === "active") { toast("Added to the active sandbox window."); }
      else { toast("Sandbox starting…"); openViewerIfAvailable(data.id); }
    } catch (e) { alert("Upload error: " + e); }
    fileInput.value = "";
    loadTable();
  }
  document.getElementById("md-branch-now").addEventListener("click", () => submit("now"));
  document.getElementById("md-branch-queue").addEventListener("click", () => submit("queue"));

  function toast(msg) {
    // reuse global toast if present, else fall back to a transient banner
    if (window.showToast) return window.showToast(msg);
    console.log("[manual-detonation] " + msg);
  }

  function openViewerIfAvailable(id) {
    if (window.openSandboxViewer) window.openSandboxViewer(id);
  }

  function esc(s) { const d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; }

  async function loadTable() {
    let data;
    try { data = await (await fetch("/api/detonation/manual")).json(); }
    catch (e) { return; }
    const tbody = document.getElementById("md-tbody");
    const rows = data.detonations || [];
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--text-muted);">No manual detonations yet.</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map((r) => {
      const verdict = r.escalate === true ? "🔴 malicious" : (r.status === "done" ? "🟢 clean" : "—");
      const mal = (r.malscore == null) ? "—" : r.malscore;
      const action = (r.status === "ready")
        ? `<button class="btn btn-sm btn-primary" data-confirm="${r.id}">Open now</button>`
        : (r.cape_task_id ? `<button class="btn btn-sm btn-outline" data-view="${r.id}">See in VM</button>` : "");
      return `<tr>
        <td>${esc(r.filename)}</td>
        <td title="${esc(r.sha256)}">${esc((r.sha256 || "").slice(0, 12))}…</td>
        <td>${esc(String(mal))}</td>
        <td>${verdict}</td>
        <td>${esc(r.status)}</td>
        <td>${esc(r.created_by)}</td>
        <td>${esc(r.updated_at || r.created_at || "")}</td>
        <td>${action}</td>
      </tr>`;
    }).join("");
  }

  // Event delegation for row buttons (no inline handlers — CSP discipline)
  document.getElementById("md-tbody").addEventListener("click", async (ev) => {
    const c = ev.target.closest("[data-confirm]");
    const v = ev.target.closest("[data-view]");
    if (c) {
      const r = await (await fetch(`/api/detonation/manual/${c.dataset.confirm}/confirm`, { method: "POST" })).json();
      if (!r.success) alert(r.error || "Could not start");
      else { toast("Sandbox starting…"); openViewerIfAvailable(Number(c.dataset.confirm)); }
      loadTable();
    } else if (v && window.openSandboxViewer) {
      window.openSandboxViewer(Number(v.dataset.view));
    }
  });

  loadTable();
  setInterval(loadTable, 8000);
})();
```

- [ ] **Step 2: Add the global 3-channel ready alert to dashboard.js**

Find the existing detonation-status poller in `src/dashboard/static/js/dashboard.js` (it fetches `/api/detonation/status` to toggle `#detonation-banner`). Inside that poller's success handler, after the banner toggle, add:

```javascript
      // Branch-B manual detonations that just became ready → alert on any page
      (function (ready) {
        window.__mdReadySeen = window.__mdReadySeen || {};
        (ready || []).forEach(function (row) {
          if (window.__mdReadySeen[row.id]) return;
          window.__mdReadySeen[row.id] = true;
          const msg = "Emails analyzed — \"" + (row.filename || "your file") + "\" is ready to open.";
          // 1) in-page banner
          const b = document.getElementById("detonation-banner");
          if (b) { b.style.display = "block"; b.textContent = "✅ " + msg; }
          // 2) desktop notification
          if ("Notification" in window && Notification.permission === "granted") {
            new Notification("Attijari SOC — sandbox ready", { body: msg });
          }
          // 3) sound cue (WebAudio beep — no asset, no CSP change)
          try {
            const ctx = new (window.AudioContext || window.webkitAudioContext)();
            const o = ctx.createOscillator(), g = ctx.createGain();
            o.type = "sine"; o.frequency.value = 880; o.connect(g); g.connect(ctx.destination);
            g.gain.setValueAtTime(0.15, ctx.currentTime);
            g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.6);
            o.start(); o.stop(ctx.currentTime + 0.6);
          } catch (e) { /* audio not available — banner + notification still fire */ }
        });
      })(data.manual_ready);
```

Where `data` is the parsed `/api/detonation/status` JSON in that handler (match the existing variable name). If the poller doesn't already parse JSON into a variable, adapt to its structure.

- [ ] **Step 3: Sanity check the JS**

Run: `node -e "require('fs').readFileSync('src/dashboard/static/js/manual_detonation.js','utf8'); console.log('ok')"`
Expected: `ok` (no syntax throw). If `node` is unavailable, open the page in Task 11 and check the browser console for parse errors.

- [ ] **Step 4: Commit**

```bash
git add src/dashboard/static/js/manual_detonation.js src/dashboard/static/js/dashboard.js
git commit -m "feat: manual detonation frontend — upload, table, 3-channel ready alert"
```

---

## Task 11: Live verification (whole feature)

**Files:** none (manual verification + build-log entry).

This is the DB-integration + browser gate the hermetic tests intentionally skip. Requires the dashboard restarted (`start.bat`). The CAPE VM being reachable is NOT required for most checks — only the actual live-detonation step needs it.

- [ ] **Step 1: Run the full new test file**

Run: `python -m pytest tests/test_manual_detonation.py -v`
Expected: all PASS. Also run `python -m pytest tests/test_detonation.py tests/test_cape_dashboard.py -v` to confirm no regressions.

- [ ] **Step 2: Restart the dashboard and confirm migration ran**

Restart via `start.bat`. In the console, confirm no crash and (first run only) the `[DB] Added column pending_detonation.created_by / .priority` lines. Verify `python -c "..."` or a psql check that `pending_detonation` now has `created_by` + `priority`.

- [ ] **Step 3: Permission gate**

As `admin`, confirm the "🧨 Manual Detonation" nav link shows and `/manual-detonation` loads. As a viewer/analyst WITHOUT the permission, confirm the link is hidden and `/manual-detonation` redirects to `/`. Grant `detonation.manual` to an analyst in User Management; confirm the link appears for them.

- [ ] **Step 4: Upload rejections**

Attach a `.txt` and a `.png` — expect a 400 with "CAPEv2 cannot detonate". Attach a >50 MB file — expect "too large".

- [ ] **Step 5: Branch A + Branch B (no live CAPE needed to see behavior)**

Attach a `.pdf`/`.exe`, choose "Open now" → a `queued` row appears and a drain window starts (banner shows; without a reachable CAPE VM it will fail-safe to `error` — that's expected and shown honestly in the table). Attach again, choose "Priority queue" → row is `deferred`, no window. Wait for a pipeline tick (≤60s) → row flips to `ready`; confirm the desktop notification + sound + banner fire; press "Open now" → window starts.

- [ ] **Step 6: History table + report link**

Confirm the table lists only manual (non-email) detonations with filename, sha, malscore, verdict, status, operator, time, and the row actions behave.

- [ ] **Step 7: Update the build log**

Add a dated entry to `CLAUDE.md` Build Log summarizing the feature, the `detonation.manual` permission, the two-branch flow, `CAPE_DETONABLE_EXTENSIONS`, the WebAudio sound choice (deviates from the spec's mp3 to avoid an asset + CSP change), and that live end-to-end detonation still needs the attijari VM powered on.

- [ ] **Step 8: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: build log — manual detonation page shipped"
```

---

## Self-Review Notes

- **Spec coverage:** page (T9), upload+history (T5–T7), two-branch warning (T6/T9/T10), Branch B ready via desktop+sound+banner (T8/T10), permission `detonation.manual` (T2/T9), `CAPE_DETONABLE_EXTENSIONS` (T1), priority/created_by columns + migration (T3), fail-safe reuse (existing), audit `detonation_manual_upload`/`_confirm` (T6), cache header on list (T7). All covered.
- **Deviations from spec (intentional, simpler):** (1) sound is a WebAudio beep, not a bundled mp3 — removes the binary asset and the `media-src` CSP change; (2) no user-row permission migration — the permission catalog + `.get(default False)` make it unnecessary. Both noted in the build-log step.
- **Type consistency:** `handle_upload(content, filename, branch, username)`, `confirm_ready(pending_id, username)`, `enqueue_detonation(..., created_by, priority, status)`, `promote_deferred_detonations(db)->int`, `list_manual_detonations(db)`, `_serialize_manual(row)`, `_manual_ready_rows(db)` — names consistent across tasks. Branch values are `"now"`/`"queue"` throughout; statuses `deferred`→`ready`→`queued` throughout.
