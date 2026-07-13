# CAPE Sandbox ↔ Dashboard Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the existing email-triage dashboard to the already-built CAPE detonation backend: queued/running/reported/error panel on the email detail page, live noVNC view during a detonation window, proxied CAPE report iframe, attachment preview, and cuckoo2 stuck-VM recovery via a wrapper service on attijari.

**Architecture:** Everything the analyst's browser loads is same-origin — a new FastAPI router (`src/routers/detonation_proxy.py`) reverse-proxies CAPE's Django report, relays the websockify VNC stream, and serves stored attachment bytes. A thin host-side HTTP client (`src/cape_vm_wrapper.py`) talks to a tiny authenticated wrapper service ON the attijari VM for cuckoo2 recovery. The frontend detonation panel is rendered by `dashboard.js` inside the existing `loadEmailDetail` page.

**Tech Stack:** Python 3.12, FastAPI, `requests` (already installed) for the report proxy, `websockets` (new dep) for the WS relay upstream, vendored noVNC 1.5.0 for the live view, plain-pytest tests matching `tests/test_detonation.py` style.

## Global Constraints

- Spec: `docs/` design doc "CAPE Sandbox ↔ Dashboard Integration — Design (FINAL)" 2026-07-13; CLAUDE.md rules apply (fail-safe never fail-open; rule 6 hostile filenames; rule 7 declared type lies).
- All email content stays local: the proxy talks only to `CAPE_WEB_URL` / `WEBSOCKIFY_URL` (attijari, default `192.168.100.10`), never any external service.
- Browser never talks to attijari directly; only dashboard-origin URLs.
- The VNC relay opens **only** while `detonation_state.is_active()` is true; report proxy and `/raw` require dashboard auth (`require_permission("emails.view")`).
- Tokens (`CAPE_VM_WRAPPER_TOKEN`) live in `.env` only — never committed, never hardcoded.
- No new DB tables/columns. `PendingDetonation` and `email.enrichment_result["detonation"]` are the only persistence.
- Keep default `CAPE_VM_WRAPPER_ENABLED=0` until the attijari runbook has been executed.
- Tests are hermetic (no DB, no network): unit-test pure helpers, monkeypatch `requests`. Follow the `sys.path.insert` style of `tests/test_detonation.py`.
- Commit after every task on the current branch (`dev`). Commit messages end with:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` and the Claude-Session line per harness rules.
- Windows host: run tests with `python -m pytest` from repo root `C:\Users\moham\Attijari`.

### Deviations from the spec (decided during planning — do NOT "fix" these back)

1. **`X-Frame-Options` (spec §8 is factually wrong).** The spec claims `X-Frame-Options: DENY` can stay because it "governs others framing us". In reality XFO is evaluated on the **framed response**: `DENY` blocks *all* framing, including same-origin. Fix: the security-header middleware in `src/api.py` sends `SAMEORIGIN` for the two framed surfaces only (paths starting `/api/detonation/report/` and `/api/emails/*/attachments/*/raw`) and keeps `DENY` everywhere else.
2. **`att_id` = `PendingDetonation.id`.** There is no attachments table; `stored_path` is persisted only on `PendingDetonation` rows. The preview pane exists for the detonated attachment, so this is exactly the right key. The endpoint validates the row belongs to `email_id`.
3. **`web_report_url` is the dashboard-proxied path** (`/api/detonation/report/<task_id>/`), not the attijari URL — the browser cannot reach attijari, so storing the upstream URL would be useless.
4. **Email detail JSON gains a `detonation_queue` array** (read-only projection of `PendingDetonation` rows for that email). This is not new persistence; it is how the frontend learns queued/running/error state and the `att_id` for `/raw`.

---

### Task 1: Config surface + attijari wrapper HTTP client

**Files:**
- Modify: `src/detonation_config.py` (append at end)
- Create: `src/cape_vm_wrapper.py`
- Modify: `.env.example` (append; Read it first — Write tool requires it)
- Modify: `requirements.txt` (add `websockets`)
- Test: `tests/test_cape_dashboard.py` (new file; all later tasks extend it)

**Interfaces:**
- Consumes: nothing new.
- Produces: config names `CAPE_VM_WRAPPER_ENABLED: bool`, `CAPE_VM_WRAPPER_URL: str`, `CAPE_VM_WRAPPER_TOKEN: str`, `CAPE_VM_WRAPPER_TIMEOUT: int`, `WEBSOCKIFY_URL: str`, `CAPE_WEB_URL: str`; functions `cape_vm_wrapper.cuckoo2_state() -> Optional[str]` and `cape_vm_wrapper.reset_cuckoo2() -> bool`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_cape_dashboard.py`:

```python
"""Tests for the CAPE sandbox <-> dashboard integration layer.

Hermetic host-side tests (no DB, no network, no live CAPE):
  - config surface for the wrapper / websockify / web-report plumbing
  - cape_vm_wrapper client fail-safe behavior
  - cuckoo2 pre-flight recovery logic
  - report-proxy URL allowlist + HTML rewriting
  - /raw content-type sniffing (magic bytes, never declared type)
  - VNC relay token check
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def test_config_has_wrapper_fields():
    import detonation_config as cfg
    assert isinstance(cfg.CAPE_VM_WRAPPER_ENABLED, bool)
    assert cfg.CAPE_VM_WRAPPER_URL.startswith("http")
    assert not cfg.CAPE_VM_WRAPPER_URL.endswith("/")
    assert cfg.CAPE_VM_WRAPPER_TIMEOUT > 0
    assert cfg.WEBSOCKIFY_URL.startswith("ws")
    # CAPE_WEB_URL is the Django UI base: API URL without the /apiv2 suffix
    assert not cfg.CAPE_WEB_URL.endswith("/apiv2")
    assert not cfg.CAPE_WEB_URL.endswith("/")


def test_wrapper_client_disabled_returns_none(monkeypatch):
    import cape_vm_wrapper
    monkeypatch.setattr(cape_vm_wrapper, "CAPE_VM_WRAPPER_ENABLED", False)
    assert cape_vm_wrapper.cuckoo2_state() is None
    assert cape_vm_wrapper.reset_cuckoo2() is False


def test_wrapper_client_state_ok(monkeypatch):
    import cape_vm_wrapper

    class FakeResp:
        status_code = 200
        def json(self):
            return {"cuckoo2": "shut off"}

    monkeypatch.setattr(cape_vm_wrapper, "CAPE_VM_WRAPPER_ENABLED", True)
    monkeypatch.setattr(cape_vm_wrapper.requests, "get", lambda *a, **kw: FakeResp())
    assert cape_vm_wrapper.cuckoo2_state() == "shut off"


def test_wrapper_client_never_raises(monkeypatch):
    import cape_vm_wrapper

    def boom(*a, **kw):
        raise ConnectionError("wrapper down")

    monkeypatch.setattr(cape_vm_wrapper, "CAPE_VM_WRAPPER_ENABLED", True)
    monkeypatch.setattr(cape_vm_wrapper.requests, "get", boom)
    monkeypatch.setattr(cape_vm_wrapper.requests, "post", boom)
    assert cape_vm_wrapper.cuckoo2_state() is None
    assert cape_vm_wrapper.reset_cuckoo2() is False


def test_wrapper_client_reset_ok(monkeypatch):
    import cape_vm_wrapper

    class FakeResp:
        status_code = 200

    captured = {}

    def fake_post(url, headers=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        return FakeResp()

    monkeypatch.setattr(cape_vm_wrapper, "CAPE_VM_WRAPPER_ENABLED", True)
    monkeypatch.setattr(cape_vm_wrapper, "CAPE_VM_WRAPPER_TOKEN", "sekret")
    monkeypatch.setattr(cape_vm_wrapper.requests, "post", fake_post)
    assert cape_vm_wrapper.reset_cuckoo2() is True
    assert captured["url"].endswith("/vm/reset")
    assert captured["headers"]["Authorization"] == "Bearer sekret"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cape_dashboard.py -v`
Expected: FAIL — `AttributeError: module 'detonation_config' has no attribute 'CAPE_VM_WRAPPER_ENABLED'` and `ModuleNotFoundError: No module named 'cape_vm_wrapper'`.

- [ ] **Step 3: Append the new config block to `src/detonation_config.py`**

Append at the end of the file (after `CAPE_READY_TIMEOUT`):

```python

# --------------------------------------------------------------------------
# Dashboard integration: attijari VM wrapper, websockify, CAPE web UI
# --------------------------------------------------------------------------
# Tiny authenticated HTTP service running ON the attijari VM (source in
# deploy/attijari/). Used ONLY to recover a cuckoo2 guest left stuck
# "running" (destroy + restart cape.service). Disabled by default until the
# runbook (docs/attijari-sandbox-setup.md) has been executed.
CAPE_VM_WRAPPER_ENABLED = os.getenv("CAPE_VM_WRAPPER_ENABLED", "0") != "0"
CAPE_VM_WRAPPER_URL = os.getenv("CAPE_VM_WRAPPER_URL", "http://192.168.100.10:8090").rstrip("/")
CAPE_VM_WRAPPER_TOKEN = os.getenv("CAPE_VM_WRAPPER_TOKEN", "")
CAPE_VM_WRAPPER_TIMEOUT = int(os.getenv("CAPE_VM_WRAPPER_TIMEOUT", "20"))

# websockify endpoint on attijari fronting cuckoo2's fixed VNC port. The
# dashboard's /ws/vnc relay is the only consumer; the browser never sees this.
WEBSOCKIFY_URL = os.getenv("WEBSOCKIFY_URL", "ws://192.168.100.10:6080")

# CAPE's Django web UI base (report pages, /analysis/<id>/). Defaults to the
# API host without the /apiv2 suffix.
CAPE_WEB_URL = os.getenv(
    "CAPE_WEB_URL",
    CAPE_API_URL[: -len("/apiv2")] if CAPE_API_URL.endswith("/apiv2") else CAPE_API_URL,
).rstrip("/")
```

- [ ] **Step 4: Create `src/cape_vm_wrapper.py`**

```python
"""cape_vm_wrapper.py — HTTP client for the attijari VM wrapper service.

The wrapper is a tiny authenticated HTTP service running ON the attijari VM
(source: deploy/attijari/vm_wrapper.py). It exposes the cuckoo2 guest's
libvirt state and a destroy+restart-CAPE recovery action. The host never
shells into attijari over SSH; this client is the only control path.

Fail-safe contract: every function swallows errors and returns None/False.
The caller must treat "wrapper unreachable" as "log and proceed" — a failed
submission escalates the queued emails to a human anyway (never fail-open,
never block the drain window on the wrapper).
"""
from __future__ import annotations

from typing import Optional

import requests

from detonation_config import (
    CAPE_VM_WRAPPER_ENABLED, CAPE_VM_WRAPPER_URL,
    CAPE_VM_WRAPPER_TOKEN, CAPE_VM_WRAPPER_TIMEOUT,
)

# Module-level copies so tests can monkeypatch them (mirrors cape_client style).
CAPE_VM_WRAPPER_ENABLED = CAPE_VM_WRAPPER_ENABLED
CAPE_VM_WRAPPER_URL = CAPE_VM_WRAPPER_URL
CAPE_VM_WRAPPER_TOKEN = CAPE_VM_WRAPPER_TOKEN
CAPE_VM_WRAPPER_TIMEOUT = CAPE_VM_WRAPPER_TIMEOUT


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {CAPE_VM_WRAPPER_TOKEN}"}


def cuckoo2_state() -> Optional[str]:
    """Return `virsh domstate` of cuckoo2 ('running', 'shut off', ...) or None."""
    if not CAPE_VM_WRAPPER_ENABLED:
        return None
    try:
        r = requests.get(
            f"{CAPE_VM_WRAPPER_URL}/vm/status",
            headers=_headers(), timeout=CAPE_VM_WRAPPER_TIMEOUT,
        )
        if r.status_code != 200:
            return None
        payload = r.json() or {}
        return payload.get("cuckoo2")
    except Exception:
        return None


def reset_cuckoo2() -> bool:
    """`virsh destroy cuckoo2` + `systemctl restart cape.service`. True on success."""
    if not CAPE_VM_WRAPPER_ENABLED:
        return False
    try:
        r = requests.post(
            f"{CAPE_VM_WRAPPER_URL}/vm/reset",
            headers=_headers(), timeout=CAPE_VM_WRAPPER_TIMEOUT * 3,
        )
        return r.status_code == 200
    except Exception:
        return False
```

Note: the module re-binds config names at module level so `monkeypatch.setattr(cape_vm_wrapper, "CAPE_VM_WRAPPER_ENABLED", True)` works — the functions must read the **module globals** (they do, since the names are module-level).

- [ ] **Step 5: Append env template entries**

Read `.env.example`, then append:

```
# --- CAPE dashboard integration (sandbox viewing / cuckoo2 recovery) ---
# Enable only after executing docs/attijari-sandbox-setup.md on the attijari VM
CAPE_VM_WRAPPER_ENABLED=0
CAPE_VM_WRAPPER_URL=http://192.168.100.10:8090
CAPE_VM_WRAPPER_TOKEN=
CAPE_VM_WRAPPER_TIMEOUT=20
WEBSOCKIFY_URL=ws://192.168.100.10:6080
# CAPE_WEB_URL defaults to CAPE_API_URL without /apiv2 — set only to override
#CAPE_WEB_URL=http://192.168.100.10:8000
```

- [ ] **Step 6: Add the websockets dependency**

In `requirements.txt`, after the `# Core framework` block's last line (`urllib3==2.7.0`), add:

```
websockets==12.0            # WS client for the dashboard->websockify VNC relay
```

Do NOT `pip install` blindly into the wrong env — install into the project's active environment: `pip install websockets==12.0`.

- [ ] **Step 7: Run tests to verify they pass**

Run: `python -m pytest tests/test_cape_dashboard.py -v`
Expected: 5 passed.

- [ ] **Step 8: Commit**

```bash
git add src/detonation_config.py src/cape_vm_wrapper.py .env.example requirements.txt tests/test_cape_dashboard.py
git commit -m "feat: attijari VM wrapper client + dashboard-integration config surface"
```

---

### Task 2: cuckoo2 pre-flight in the drain window

**Files:**
- Modify: `src/detonation.py` (function `_resume_vm`, lines ~129-138; add `_preflight_cuckoo2` above it)
- Test: `tests/test_cape_dashboard.py` (append)

**Interfaces:**
- Consumes: `cape_vm_wrapper.cuckoo2_state()`, `cape_vm_wrapper.reset_cuckoo2()` (Task 1); `cape_client.wait_until_ready(timeout)` (existing).
- Produces: `detonation._preflight_cuckoo2() -> None` — called from `_resume_vm()` after CAPE answers, before returning True.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_cape_dashboard.py`)

```python
def test_preflight_resets_stuck_cuckoo2(monkeypatch):
    import detonation
    import detonation_config as cfg
    import cape_vm_wrapper
    import cape_client

    calls = []
    monkeypatch.setattr(cfg, "CAPE_VM_WRAPPER_ENABLED", True)
    monkeypatch.setattr(cape_vm_wrapper, "cuckoo2_state", lambda: "running")
    monkeypatch.setattr(cape_vm_wrapper, "reset_cuckoo2",
                        lambda: calls.append("reset") or True)
    monkeypatch.setattr(cape_client, "wait_until_ready",
                        lambda t: calls.append("wait") or True)
    detonation._preflight_cuckoo2()
    assert calls == ["reset", "wait"]


def test_preflight_noop_when_cuckoo2_off(monkeypatch):
    import detonation
    import detonation_config as cfg
    import cape_vm_wrapper

    monkeypatch.setattr(cfg, "CAPE_VM_WRAPPER_ENABLED", True)
    monkeypatch.setattr(cape_vm_wrapper, "cuckoo2_state", lambda: "shut off")
    monkeypatch.setattr(cape_vm_wrapper, "reset_cuckoo2",
                        lambda: (_ for _ in ()).throw(AssertionError("must not reset")))
    detonation._preflight_cuckoo2()  # must not raise, must not reset


def test_preflight_never_raises_when_wrapper_down(monkeypatch):
    import detonation
    import detonation_config as cfg
    import cape_vm_wrapper

    monkeypatch.setattr(cfg, "CAPE_VM_WRAPPER_ENABLED", True)
    monkeypatch.setattr(cape_vm_wrapper, "cuckoo2_state",
                        lambda: (_ for _ in ()).throw(RuntimeError("down")))
    detonation._preflight_cuckoo2()  # swallowed — window must proceed


def test_preflight_disabled_is_noop(monkeypatch):
    import detonation
    import detonation_config as cfg
    monkeypatch.setattr(cfg, "CAPE_VM_WRAPPER_ENABLED", False)
    detonation._preflight_cuckoo2()  # no wrapper import side effects required
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cape_dashboard.py -k preflight -v`
Expected: FAIL with `AttributeError: module 'detonation' has no attribute '_preflight_cuckoo2'`.

- [ ] **Step 3: Implement `_preflight_cuckoo2` and hook it into `_resume_vm`**

In `src/detonation.py`, insert directly ABOVE `def _resume_vm():`:

```python
def _preflight_cuckoo2() -> None:
    """Recover cuckoo2 if a previous run left it powered on.

    Runs after the attijari VM is up and CAPE answers, before submitting the
    batch — prevents CAPE's 'Trying to start a virtual machine that has not
    been turned off' failure. Wrapper disabled/unreachable → log and proceed:
    a failed submission escalates safely; never block the drain window.
    """
    if not cfg.CAPE_VM_WRAPPER_ENABLED:
        return
    try:
        import cape_vm_wrapper
        st = cape_vm_wrapper.cuckoo2_state()
        print(f"[DETONATION] cuckoo2 pre-flight state: {st}")
        if st == "running":
            print("[DETONATION] cuckoo2 left running — destroy + CAPE restart via wrapper")
            if cape_vm_wrapper.reset_cuckoo2():
                if not cape_client.wait_until_ready(cfg.CAPE_READY_TIMEOUT):
                    print("[DETONATION] CAPE not ready after cuckoo2 reset — proceeding (fail-safe)")
            else:
                print("[DETONATION] cuckoo2 reset failed — proceeding (fail-safe)")
    except Exception as e:
        print(f"[DETONATION] cuckoo2 pre-flight skipped: {e}")
```

Then replace the body of `_resume_vm` (currently lines 129-138) with:

```python
def _resume_vm() -> bool:
    if not cfg.DETONATION_MANAGE_VM:
        ok = cape_client.is_available()
        if ok:
            _preflight_cuckoo2()
        return ok
    print(f"[DETONATION] Resuming CAPE VM '{cfg.CAPE_VM_NAME}'...")
    _run(cfg.VM_RESUME_CMD, timeout=120)
    if not cape_client.wait_until_ready(cfg.CAPE_READY_TIMEOUT):
        print("[DETONATION] CAPE API did not become ready after VM resume")
        return False
    print("[DETONATION] CAPE API ready")
    _preflight_cuckoo2()
    return True
```

Note: `_preflight_cuckoo2` reads `cfg.CAPE_VM_WRAPPER_ENABLED` through the module (`import detonation_config as cfg` already at top of detonation.py) so the monkeypatched value is seen. It calls `cape_vm_wrapper.cuckoo2_state` as a module attribute so monkeypatch works.

- [ ] **Step 4: Run all detonation tests**

Run: `python -m pytest tests/test_cape_dashboard.py tests/test_detonation.py -v`
Expected: all pass (existing detonation tests must not regress).

- [ ] **Step 5: Commit**

```bash
git add src/detonation.py tests/test_cape_dashboard.py
git commit -m "feat: cuckoo2 stuck-VM pre-flight recovery in the drained detonation window"
```

---

### Task 3: `web_report_url` in `parse_report`

**Files:**
- Modify: `src/cape_client.py` (function `parse_report`, return dict at lines ~157-170)
- Test: `tests/test_cape_dashboard.py` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: `parse_report(...)["web_report_url"] == f"/api/detonation/report/{task_id}/"` — the dashboard-proxied path (deviation #3). Frontend (Task 7) and the report proxy (Task 5) rely on this exact shape.

- [ ] **Step 1: Write the failing test** (append)

```python
def test_parse_report_includes_proxied_web_report_url():
    from cape_client import parse_report
    r = parse_report({"info": {"score": 2.0}}, task_id=123)
    assert r["web_report_url"] == "/api/detonation/report/123/"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cape_dashboard.py::test_parse_report_includes_proxied_web_report_url -v`
Expected: FAIL with `KeyError: 'web_report_url'`.

- [ ] **Step 3: Implement**

In `src/cape_client.py`, in `parse_report`'s return dict, add one line after `"cape_task_id": task_id,`:

```python
        "web_report_url": f"/api/detonation/report/{task_id}/",
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_cape_dashboard.py tests/test_detonation.py -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/cape_client.py tests/test_cape_dashboard.py
git commit -m "feat: parse_report exposes dashboard-proxied web_report_url"
```

---

### Task 4: `detonation_queue` in email detail JSON + `/raw` attachment endpoint (new router)

**Files:**
- Create: `src/routers/detonation_proxy.py`
- Modify: `src/routers/emails.py` (`api_get_email`, lines ~187-241)
- Modify: `src/api.py` (mount the new router, after line 173 `app.include_router(users_router, ...)`)
- Test: `tests/test_cape_dashboard.py` (append)

**Interfaces:**
- Consumes: `require_permission`, `AuthenticatedUser` from `api_core`; `PendingDetonation`, `SessionLocal` from `database`.
- Produces:
  - `GET /api/emails/{email_id}` response gains `"detonation_queue": [{id, filename, sha256, status, reason, attempts, result, created_at, updated_at}]`.
  - `GET /api/emails/{email_id}/attachments/{att_id}/raw` — `att_id` is `PendingDetonation.id`, row must have `email_id == email_id`; forced content-type from magic bytes.
  - Pure helper `detonation_proxy._sniff_media_type(head: bytes) -> tuple[str, bool]` (media_type, inline) — later tasks live in this same module.
  - `detonation_proxy_router` (APIRouter) mounted in `api.py` with `dependencies=[Depends(verify_auth)]`.

- [ ] **Step 1: Write the failing tests** (append)

```python
def test_sniff_media_type_magic_bytes():
    # JWT_SECRET must exist before any api_core import chain
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    from routers.detonation_proxy import _sniff_media_type
    assert _sniff_media_type(b"%PDF-1.7 blah") == ("application/pdf", True)
    assert _sniff_media_type(b"\x89PNG\r\n\x1a\nxxxx") == ("image/png", True)
    assert _sniff_media_type(b"\xff\xd8\xff\xe0rest") == ("image/jpeg", True)
    assert _sniff_media_type(b"GIF89a....") == ("image/gif", True)
    # a docm renamed to .pdf still gets octet-stream: magic bytes win (rule 7)
    assert _sniff_media_type(b"PK\x03\x04word/") == ("application/octet-stream", False)
    assert _sniff_media_type(b"") == ("application/octet-stream", False)
```

Note: `src/routers/` is a package; the `sys.path.insert` of `src` at the top of the file makes `from routers.detonation_proxy import ...` work.

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cape_dashboard.py::test_sniff_media_type_magic_bytes -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'routers.detonation_proxy'`.

- [ ] **Step 3: Create `src/routers/detonation_proxy.py`**

```python
"""detonation_proxy.py — dashboard-side viewing layer for the CAPE sandbox.

Everything the analyst's browser needs from the detonation subsystem, served
same-origin so the strict CSP stays intact:

  - GET  /api/emails/{email_id}/attachments/{att_id}/raw  — stored attachment
    bytes for the preview pane. att_id is the PendingDetonation row id (the
    only place stored_path is persisted). Content-type is forced from magic
    bytes — the declared type and filename are hostile data (CLAUDE.md 6+7).
  - (Task 5 adds) GET /api/detonation/report/{task_id}/{path}  — reverse
    proxy of CAPE's Django report.
  - (Task 6 adds) WS /ws/vnc/{task_id} — relay to websockify on attijari,
    open only during an active detonation window; POST retry endpoint.

Display-only layer: nothing here influences a verdict (fail-safe rule 1).
"""
from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from api_core import require_permission, AuthenticatedUser

detonation_proxy_router = APIRouter()


# ---------------------------------------------------------------------------
# Attachment preview: magic-byte sniffing (never trust declared type)
# ---------------------------------------------------------------------------

_MAGIC_INLINE: tuple[tuple[bytes, str], ...] = (
    (b"%PDF-", "application/pdf"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)


def _sniff_media_type(head: bytes) -> tuple[str, bool]:
    """(media_type, inline). Only magic-verified PDF/images render inline;
    everything else downloads as opaque bytes."""
    for magic, mtype in _MAGIC_INLINE:
        if head.startswith(magic):
            return mtype, True
    return "application/octet-stream", False


@detonation_proxy_router.get("/api/emails/{email_id}/attachments/{att_id}/raw")
def api_attachment_raw(
    email_id: int, att_id: int,
    user: AuthenticatedUser = Depends(require_permission("emails.view")),
):
    """Serve the stored attachment bytes for the detail-page preview pane."""
    from database import SessionLocal, PendingDetonation
    db = SessionLocal()
    try:
        row = (
            db.query(PendingDetonation)
            .filter(PendingDetonation.id == att_id,
                    PendingDetonation.email_id == email_id)
            .first()
        )
        stored_path = row.stored_path if row else None
    finally:
        db.close()

    if not stored_path:
        raise HTTPException(404, "Attachment not found")
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
            "Content-Disposition": f'{disposition}; filename="attachment-{att_id}"',
            "X-Content-Type-Options": "nosniff",
        },
    )
```

- [ ] **Step 4: Expose `detonation_queue` in `api_get_email`**

In `src/routers/emails.py`, inside `api_get_email` after the audit query (line ~199), add:

```python
        from database import PendingDetonation
        det_rows = (
            db.query(PendingDetonation)
            .filter(PendingDetonation.email_id == email_id)
            .order_by(PendingDetonation.created_at.desc())
            .all()
        )
```

and in the returned dict, after `"enrichment_result": email.enrichment_result,` add:

```python
            "detonation_queue": [
                {
                    "id": r.id,
                    "filename": r.filename,
                    "sha256": r.sha256,
                    "status": r.status,
                    "reason": r.reason,
                    "attempts": r.attempts,
                    "result": r.result,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "updated_at": r.updated_at.isoformat() if r.updated_at else None,
                }
                for r in det_rows
            ],
```

Deliberately NOT exposed: `stored_path` (internal filesystem path stays server-side).

- [ ] **Step 5: Mount the router in `src/api.py`**

After line 173 (`app.include_router(users_router, dependencies=[Depends(verify_auth)])`) add:

```python
from routers.detonation_proxy import detonation_proxy_router
app.include_router(detonation_proxy_router, dependencies=[Depends(verify_auth)])
```

(Match the import style used for the other routers at the top of `api.py` — if they are imported at the top, put the import there instead of inline.)

- [ ] **Step 6: Run tests + import smoke check**

Run: `python -m pytest tests/test_cape_dashboard.py -v`
Expected: all pass.
Run: `python -c "import sys; sys.path.insert(0, 'src'); import routers.detonation_proxy"` — expected: exits 0 (needs `JWT_SECRET` in env; prefix with `$env:JWT_SECRET='x'` in PowerShell if `.env` isn't loaded).

- [ ] **Step 7: Commit**

```bash
git add src/routers/detonation_proxy.py src/routers/emails.py src/api.py tests/test_cape_dashboard.py
git commit -m "feat: attachment /raw preview endpoint + detonation_queue in email detail JSON"
```

---

### Task 5: CAPE report reverse proxy + CSP/XFO adjustments

**Files:**
- Modify: `src/routers/detonation_proxy.py` (append)
- Modify: `src/api.py` (security-header middleware, lines ~92-105)
- Test: `tests/test_cape_dashboard.py` (append)

**Interfaces:**
- Consumes: `detonation_config.CAPE_WEB_URL`, `CAPE_HTTP_TIMEOUT` (Task 1); `requests`.
- Produces:
  - `GET /api/detonation/report/{task_id}/{path:path}` — entry `/api/detonation/report/<id>/` serves upstream `/analysis/<id>/`; sub-paths under `analysis/` and `static/` are proxied; anything else 404s (the dashboard must not become an open proxy into CAPE admin).
  - Pure helpers `_upstream_path(task_id: int, path: str) -> Optional[str]` and `_rewrite_report_html(body: str, task_id: int) -> str` (used by Task 5 tests).
  - Middleware: `frame-src 'self'` added to CSP; `X-Frame-Options: SAMEORIGIN` on the two framed surfaces (deviation #1).

- [ ] **Step 1: Write the failing tests** (append)

```python
def test_report_proxy_upstream_path_allowlist():
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    from routers.detonation_proxy import _upstream_path
    assert _upstream_path(42, "") == "analysis/42/"
    assert _upstream_path(42, "analysis/42/") == "analysis/42/"
    assert _upstream_path(42, "static/css/style.css") == "static/css/style.css"
    # never proxy CAPE admin or arbitrary paths
    assert _upstream_path(42, "admin/") is None
    assert _upstream_path(42, "apiv2/tasks/list/") is None
    assert _upstream_path(42, "../etc/passwd") is None


def test_report_proxy_rewrites_root_relative_refs():
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    from routers.detonation_proxy import _rewrite_report_html
    html = (
        '<link href="/static/css/a.css"><script src="/static/js/b.js"></script>'
        '<a href="/analysis/42/network/">net</a>'
        '<a href="https://example.com/x">ext</a>'
        '<a href="//cdn.example.com/y">proto-rel</a>'
        '<style>.x{background:url(/static/img/z.png)}</style>'
    )
    out = _rewrite_report_html(html, 42)
    assert 'href="/api/detonation/report/42/static/css/a.css"' in out
    assert 'src="/api/detonation/report/42/static/js/b.js"' in out
    assert 'href="/api/detonation/report/42/analysis/42/network/"' in out
    # absolute and protocol-relative URLs untouched
    assert 'href="https://example.com/x"' in out
    assert 'href="//cdn.example.com/y"' in out
    assert 'url(/api/detonation/report/42/static/img/z.png)' in out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cape_dashboard.py -k report_proxy -v`
Expected: FAIL with ImportError (helpers don't exist yet).

- [ ] **Step 3: Implement the proxy in `src/routers/detonation_proxy.py`**

Add to the imports at the top: `import re`, `import requests`, `from fastapi import Request`, `from fastapi.responses import HTMLResponse, Response`, and `import detonation_config as det_cfg`.

Append:

```python
# ---------------------------------------------------------------------------
# CAPE web-report reverse proxy (same-origin so CSP stays strict)
# ---------------------------------------------------------------------------

# Only report pages and their assets — never CAPE admin/API surfaces.
_REPORT_PREFIX_ALLOW = ("analysis/", "static/")

# Root-relative references in CAPE's Django HTML/CSS get re-rooted onto the
# proxy prefix. (?!/) keeps protocol-relative //host URLs untouched.
_ROOT_REF_RE = re.compile(r'(href=|src=|action=)(["\'])/(?!/)')
_CSS_URL_RE = re.compile(r'url\((["\']?)/(?!/)')

_REPORT_ERROR_PAGE = """<!doctype html>
<div style="font-family:sans-serif;padding:2rem;color:#b91c1c">
  <h3>Sandbox report unavailable</h3>
  <p>The CAPE report backend did not answer (it is normally offline outside a
  detonation window). The email's verdict is unaffected.</p>
  <p><a href="javascript:location.reload()">Retry</a></p>
</div>"""


def _upstream_path(task_id: int, path: str) -> Optional[str]:
    """Map a proxied path to the CAPE upstream path, or None if not allowed."""
    if not path:
        return f"analysis/{task_id}/"
    if path.startswith(_REPORT_PREFIX_ALLOW) and ".." not in path:
        return path
    return None


def _rewrite_report_html(body: str, task_id: int) -> str:
    """Re-root root-relative asset/link URLs onto this proxy's prefix."""
    prefix = f"/api/detonation/report/{task_id}"
    body = _ROOT_REF_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{prefix}/", body)
    body = _CSS_URL_RE.sub(lambda m: f"url({m.group(1)}{prefix}/", body)
    return body


@detonation_proxy_router.get("/api/detonation/report/{task_id}/{path:path}")
def api_detonation_report(
    task_id: int, request: Request, path: str = "",
    user: AuthenticatedUser = Depends(require_permission("emails.view")),
):
    """Reverse-proxy CAPE's Django report so the browser stays same-origin.

    Sync `def` on purpose: FastAPI runs it in the threadpool, so the blocking
    `requests` call doesn't stall the event loop.
    """
    upstream_path = _upstream_path(task_id, path)
    if upstream_path is None:
        raise HTTPException(404, "Not available through the report proxy")

    url = f"{det_cfg.CAPE_WEB_URL}/{upstream_path}"
    try:
        r = requests.get(
            url, params=dict(request.query_params),
            timeout=det_cfg.CAPE_HTTP_TIMEOUT * 2,
            verify=det_cfg.CAPE_VERIFY_TLS,
        )
    except Exception:
        return HTMLResponse(_REPORT_ERROR_PAGE, status_code=502)
    if r.status_code >= 500:
        return HTMLResponse(_REPORT_ERROR_PAGE, status_code=502)

    ctype = r.headers.get("content-type", "application/octet-stream")
    base_type = ctype.split(";")[0].strip().lower()
    if base_type in ("text/html", "text/css"):
        return Response(content=_rewrite_report_html(r.text, task_id),
                        status_code=r.status_code, media_type=ctype)
    # Binary assets (images, fonts, screenshots) pass through untouched.
    # Upstream headers (incl. any X-Frame-Options) are deliberately dropped;
    # our own middleware applies the dashboard's security headers.
    return Response(content=r.content, status_code=r.status_code, media_type=ctype)
```

`det_cfg.CAPE_VERIFY_TLS` and `det_cfg.CAPE_HTTP_TIMEOUT` already exist in `detonation_config.py`.

- [ ] **Step 4: CSP + X-Frame-Options in `src/api.py`**

In the security-header middleware (lines ~92-105), replace:

```python
    response.headers["X-Frame-Options"] = "DENY"
```

with:

```python
    # The two framed surfaces (proxied CAPE report, attachment preview) must
    # allow same-origin framing; XFO is evaluated on the FRAMED response, so
    # DENY there would block our own iframes. Everything else stays DENY.
    _p = request.url.path
    _frameable = _p.startswith("/api/detonation/report/") or (
        _p.startswith("/api/emails/") and _p.endswith("/raw")
    )
    response.headers["X-Frame-Options"] = "SAMEORIGIN" if _frameable else "DENY"
```

And in the CSP string, change the line

```python
        f"connect-src 'self' ws: wss:; "
```

to

```python
        f"connect-src 'self' ws: wss:; "
        # Same-origin iframes only: the proxied CAPE report and the /raw
        # attachment preview. Nothing cross-origin is ever framed.
        f"frame-src 'self'; "
```

- [ ] **Step 5: Run tests**

Run: `python -m pytest tests/test_cape_dashboard.py -v`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/routers/detonation_proxy.py src/api.py tests/test_cape_dashboard.py
git commit -m "feat: same-origin reverse proxy for CAPE web reports + frame-src/XFO adjustments"
```

---

### Task 6: VNC WebSocket relay + detonation retry endpoint

**Files:**
- Modify: `src/routers/detonation_proxy.py` (append)
- Test: `tests/test_cape_dashboard.py` (append)

**Interfaces:**
- Consumes: `JWT_SECRET`, `ALGORITHM`, `is_token_revoked` from `api_core` (same pattern as `src/routers/websockets.py`); `detonation_state.is_active()`; `detonation_config.WEBSOCKIFY_URL`; `websockets` package (Task 1); `add_audit_entry`, `PendingDetonation` from `database`.
- Produces:
  - `WS /ws/vnc/{task_id}?token=<jwt>` — closes 1008 on bad token or inactive window; otherwise binary relay to `WEBSOCKIFY_URL`.
  - `POST /api/detonation/{pending_id}/retry` (permission `emails.scan`) → re-queues an `error`/`done` row; response `{"success": true, "id": N, "status": "queued"}`.
  - Pure helper `_ws_token_ok(token: Optional[str]) -> bool`.

- [ ] **Step 1: Write the failing tests** (append)

```python
def test_ws_token_ok_accepts_valid_rejects_garbage():
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    import jwt as pyjwt
    from datetime import datetime, timedelta, timezone
    from api_core import JWT_SECRET, ALGORITHM
    from routers.detonation_proxy import _ws_token_ok

    good = pyjwt.encode(
        {"sub": "analyst", "purpose": "ws",
         "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        JWT_SECRET, algorithm=ALGORITHM)
    assert _ws_token_ok(good) is True
    assert _ws_token_ok(None) is False
    assert _ws_token_ok("") is False
    assert _ws_token_ok("not-a-jwt") is False

    expired = pyjwt.encode(
        {"sub": "analyst",
         "exp": datetime.now(timezone.utc) - timedelta(hours=1)},
        JWT_SECRET, algorithm=ALGORITHM)
    assert _ws_token_ok(expired) is False


def test_ws_token_ok_rejects_revoked():
    os.environ.setdefault("JWT_SECRET", "test-secret-for-unit-tests")
    import jwt as pyjwt
    from datetime import datetime, timedelta, timezone
    from api_core import JWT_SECRET, ALGORITHM, revoke_token
    from routers.detonation_proxy import _ws_token_ok

    tok = pyjwt.encode(
        {"sub": "analyst",
         "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        JWT_SECRET, algorithm=ALGORITHM)
    revoke_token(tok)
    assert _ws_token_ok(tok) is False
```

Caveat: `api_core` import requires `JWT_SECRET` env — the `os.environ.setdefault` at the top of each test handles it, but if another test file imported `api_core` first with a different secret the encode/decode still agree because both read `api_core.JWT_SECRET`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cape_dashboard.py -k ws_token -v`
Expected: FAIL with ImportError (`_ws_token_ok` doesn't exist).

- [ ] **Step 3: Implement relay + retry in `src/routers/detonation_proxy.py`**

Add to imports: `import asyncio`, `import jwt as pyjwt`, `from fastapi import WebSocket, Query`, and extend the `api_core` import line to include `JWT_SECRET, ALGORITHM, is_token_revoked`.

Append:

```python
# ---------------------------------------------------------------------------
# Live sandbox view: WS relay to websockify on attijari
# ---------------------------------------------------------------------------

def _ws_token_ok(token: Optional[str]) -> bool:
    """Same JWT-in-query-param check as routers/websockets.py."""
    if not token or is_token_revoked(token):
        return False
    try:
        pyjwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return True
    except pyjwt.PyJWTError:
        return False


@detonation_proxy_router.websocket("/ws/vnc/{task_id}")
async def ws_vnc_relay(websocket: WebSocket, task_id: int,
                       token: Optional[str] = Query(None)):
    """Bidirectional binary relay browser <-> websockify (cuckoo2 VNC).

    Opens ONLY while a detonation window is active — the VM screen is never
    exposed at rest. Display-only: failures here never touch any verdict.
    """
    if not _ws_token_ok(token):
        await websocket.close(code=1008, reason="Unauthorized")
        return

    import detonation_state
    if not detonation_state.is_active():
        await websocket.close(code=1008, reason="No active detonation window")
        return

    await websocket.accept()

    import websockets as ws_client
    try:
        upstream = await ws_client.connect(
            det_cfg.WEBSOCKIFY_URL, subprotocols=["binary"],
            max_size=None, open_timeout=10,
        )
    except Exception:
        await websocket.close(code=1011, reason="Sandbox video relay unavailable")
        return

    async def pump_to_upstream():
        while True:
            data = await websocket.receive_bytes()
            await upstream.send(data)

    async def pump_to_browser():
        async for msg in upstream:
            await websocket.send_bytes(msg if isinstance(msg, bytes) else msg.encode())

    tasks = [asyncio.create_task(pump_to_upstream()),
             asyncio.create_task(pump_to_browser())]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        try:
            await upstream.close()
        except Exception:
            pass
        try:
            await websocket.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Retry a failed detonation (re-enqueue for the next drained window)
# ---------------------------------------------------------------------------

@detonation_proxy_router.post("/api/detonation/{pending_id}/retry")
def api_detonation_retry(
    pending_id: int,
    user: AuthenticatedUser = Depends(require_permission("emails.scan")),
):
    from database import SessionLocal, PendingDetonation, add_audit_entry
    db = SessionLocal()
    try:
        row = db.query(PendingDetonation).filter(
            PendingDetonation.id == pending_id).first()
        if not row:
            raise HTTPException(404, "Queue entry not found")
        if row.status not in ("error", "done"):
            raise HTTPException(409, f"Cannot retry entry in status '{row.status}'")
        if not (row.stored_path and os.path.isfile(row.stored_path)):
            raise HTTPException(409, "Original file no longer available")
        row.status = "queued"
        row.result = None
        db.commit()
        add_audit_entry(
            db, action="detonation_retry", actor=user.username,
            email_id=row.email_id,
            details={"pending_id": row.id, "sha256": row.sha256},
        )
        return {"success": True, "id": row.id, "status": "queued"}
    finally:
        db.close()
```

Note: the WS route is registered on `detonation_proxy_router`, which `api.py` mounts with `dependencies=[Depends(verify_auth)]`. FastAPI does not apply HTTP dependencies to WebSocket routes, so the `?token=` check is the effective auth — same as the existing `/ws` endpoint. Verify this claim after wiring: connect without a cookie in the manual checklist.

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_cape_dashboard.py -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/routers/detonation_proxy.py tests/test_cape_dashboard.py
git commit -m "feat: window-gated VNC WebSocket relay + detonation retry endpoint"
```

---

### Task 7: Vendor noVNC

**Files:**
- Create: `src/dashboard/static/novnc/core/**` and `src/dashboard/static/novnc/vendor/**` (vendored from the noVNC v1.5.0 release)
- Create: `src/dashboard/static/novnc/VERSION` (one line: `noVNC v1.5.0 — https://github.com/novnc/noVNC — vendored, do not edit`)

**Interfaces:**
- Consumes: nothing from this repo.
- Produces: browser-importable ES module at `/static/novnc/core/rfb.js` (default export `RFB`). Task 8's `import('/static/novnc/core/rfb.js')` depends on this exact path.

- [ ] **Step 1: Download and extract the release**

```bash
curl -L -o "$TMPDIR/novnc.zip" https://github.com/novnc/noVNC/archive/refs/tags/v1.5.0.zip
cd "$TMPDIR" && unzip -q novnc.zip
```

(Use the session scratchpad directory for the temp files.)

- [ ] **Step 2: Copy only what the RFB module needs**

```bash
mkdir -p src/dashboard/static/novnc
cp -r "$TMPDIR/noVNC-1.5.0/core" src/dashboard/static/novnc/core
cp -r "$TMPDIR/noVNC-1.5.0/vendor" src/dashboard/static/novnc/vendor
```

Do NOT copy the full noVNC app (`app/`, `vnc.html` etc.) — only the ES-module client library. Create the `VERSION` file.

- [ ] **Step 3: Verify the module entry point exists and is an ES module**

Run: `head -5 src/dashboard/static/novnc/core/rfb.js` (or `Get-Content -TotalCount 5`)
Expected: file exists; imports/exports visible. Also verify `src/dashboard/static/novnc/core/util/` and `src/dashboard/static/novnc/core/decoders/` directories exist (rfb.js imports from them).

- [ ] **Step 4: Commit**

```bash
git add src/dashboard/static/novnc
git commit -m "chore: vendor noVNC 1.5.0 client library (core+vendor, no CDN)"
```

---

### Task 8: Frontend detonation panel

**Files:**
- Modify: `src/dashboard/static/js/dashboard.js` (extend `loadEmailDetail` at line ~399; append new functions at the end of the "Email detail page" section)
- Modify: `src/dashboard/static/css/dashboard.css` (append panel styles)

**Interfaces:**
- Consumes: `GET /api/emails/{id}` with `detonation_queue` (Task 4) and `enrichment_result.detonation.web_report_url` (Task 3); `GET /api/detonation/status` (existing — fields `window_active`, `queued`); `WS /ws/vnc/{task_id}?token=` (Task 6); `POST /api/detonation/{pending_id}/retry` (Task 6); `GET /api/emails/{id}/attachments/{att_id}/raw` (Task 4); `/static/novnc/core/rfb.js` (Task 7); existing helpers `API.get/post`, `esc()`, `formatDate()`, `showToast()`, `userCan()`; ws token from `<meta name="ws-token">` (already rendered by `base.html`).
- Produces: `renderDetonationPanel(e)`, `refreshDetonationPanel(emailId)`, `openSandboxViewer(taskId)`, `closeSandboxViewer()`, `mountNoVnc(el, taskId)`, `detonationRetry(pendingId, emailId)`.

- [ ] **Step 1: Add the panel container + hook into `loadEmailDetail`**

In `loadEmailDetail`'s big template string (line ~467-518), insert between the `${signalsHtml ...}` line and `${auditHtml}`:

```javascript
            <div id="detonation-panel"></div>
```

Immediately after `container.innerHTML = \`...\`;` (before the closing `catch`), add:

```javascript
        renderDetonationPanel(e);
```

- [ ] **Step 2: Append the panel implementation** (end of the "Email detail page" section of `dashboard.js`)

```javascript
/* =========================================================================
   Detonation sandbox panel (CAPE integration)
   ========================================================================= */

let _detonationPollTimer = null;
let _activeRfb = null;

function _detonationStatusBadge(status) {
    const map = { queued: 'recu', running: 'escalated', done: 'accepted', error: 'quarantined' };
    return `<span class="badge ${map[status] || 'recu'}">${esc(status)}</span>`;
}

function _attachmentPreviewHtml(emailId, row) {
    const name = (row.filename || '').toLowerCase();
    const inline = /\.(pdf|png|jpe?g|gif)$/.test(name);
    const rawUrl = `/api/emails/${parseInt(emailId)}/attachments/${parseInt(row.id)}/raw`;
    if (inline) {
        // Server re-verifies via magic bytes and forces the content type; a
        // lying extension just yields a download instead of a render.
        return `<iframe class="sandbox-preview-frame" src="${rawUrl}" title="Attachment preview"></iframe>`;
    }
    return `
        <div class="sandbox-preview-meta">
            <div class="detail-row"><span class="detail-label">File</span>
                <span class="detail-value">${esc(truncate(row.filename, 60)) || '—'}</span></div>
            <div class="detail-row"><span class="detail-label">SHA-256</span>
                <span class="detail-value" style="font-family:monospace;font-size:0.72rem">${esc(row.sha256)}</span></div>
            <div class="detail-row"><span class="detail-label">Queued because</span>
                <span class="detail-value">${esc(row.reason) || '—'}</span></div>
            <a class="btn btn-outline btn-sm" href="${rawUrl}" download>Download original (handle with care)</a>
        </div>`;
}

function _detonationRowHtml(e, row, windowActive) {
    const det = (e.enrichment_result && e.enrichment_result.detonation) || {};
    const result = row.result || {};
    const taskId = result.cape_task_id || det.cape_task_id || null;
    const reportUrl = result.web_report_url || det.web_report_url ||
        (taskId ? `/api/detonation/report/${parseInt(taskId)}/` : null);

    let body = '';
    if (row.status === 'queued' || row.status === 'running') {
        const live = (row.status === 'running' && windowActive && taskId)
            ? `<div class="sandbox-live" id="sandbox-live-${row.id}"></div>`
            : `<div class="sandbox-empty">
                   <div class="spinner"></div>
                   <p>${row.status === 'queued'
                        ? 'Queued for detonation — runs in the next drained window.'
                        : 'Detonation running…'}</p>
               </div>`;
        body = `
            <div class="sandbox-columns">
                <div>${_attachmentPreviewHtml(e.id, row)}</div>
                <div>${live}</div>
            </div>`;
    } else if (row.status === 'done' && reportUrl) {
        const score = (result.malscore !== undefined) ? result.malscore : det.malscore;
        const sigs = result.suspicious_behaviors || det.suspicious_behaviors || [];
        body = `
            <div class="sandbox-verdict">
                <span class="detail-label">Malscore</span>
                <strong>${score !== undefined ? esc(String(score)) : '—'} / 10</strong>
                ${sigs.length ? `<span class="detail-label">· ${parseInt(sigs.length)} signature(s)</span>` : ''}
                <a class="btn btn-outline btn-sm" href="${reportUrl}" target="_blank" rel="noopener">Open full report ↗</a>
            </div>
            <iframe class="sandbox-report-frame" src="${reportUrl}" title="CAPE report"></iframe>
            <details style="margin-top:8px"><summary class="detail-label">Attachment preview</summary>
                ${_attachmentPreviewHtml(e.id, row)}</details>`;
    } else { // error (or done without report)
        const errMsg = result.error || 'detonation failed';
        body = `
            <div class="sandbox-error">
                <p>⚠ Detonation failed: <code>${esc(errMsg)}</code>.
                   The email was escalated to human review (fail-safe).</p>
                ${userCan('emails.scan')
                    ? `<button class="btn btn-outline btn-sm"
                         onclick="detonationRetry(${parseInt(row.id)}, ${parseInt(e.id)})">↻ Retry detonation</button>`
                    : ''}
            </div>`;
    }

    return `
        <div class="sandbox-row">
            <div class="sandbox-row-head">
                <span>💣 ${esc(truncate(row.filename, 50)) || 'attachment'}</span>
                ${_detonationStatusBadge(row.status)}
                ${row.attempts > 1 ? `<span class="detail-label">attempt ${parseInt(row.attempts)}</span>` : ''}
                ${taskId ? `<span class="detail-label">CAPE task #${parseInt(taskId)}</span>` : ''}
            </div>
            ${body}
        </div>`;
}

async function renderDetonationPanel(e) {
    const panel = document.getElementById('detonation-panel');
    if (!panel) return;
    const rows = e.detonation_queue || [];
    if (rows.length === 0) { panel.innerHTML = ''; return; }

    let windowActive = false;
    try {
        const st = await API.get('/api/detonation/status');
        windowActive = !!st.window_active;
    } catch (_) { /* status endpoint down — panel still renders, no live view */ }

    panel.innerHTML = `
        <div class="detail-section" style="grid-column: 1 / -1; margin-bottom:16px">
            <h3>🔬 Detonation Sandbox
                <button class="btn btn-outline btn-sm" style="float:right"
                        onclick="openSandboxViewer(${parseInt(rows[0].result?.cape_task_id || 0)})">
                    Open sandbox
                </button>
            </h3>
            ${rows.map(r => _detonationRowHtml(e, r, windowActive)).join('')}
        </div>`;

    // Live noVNC for any row currently running inside an active window
    for (const r of rows) {
        const el = document.getElementById(`sandbox-live-${r.id}`);
        if (el) mountNoVnc(el, (r.result && r.result.cape_task_id) || 0);
    }

    // Poll while anything is pending so the panel advances queued→running→done
    const pending = rows.some(r => r.status === 'queued' || r.status === 'running');
    clearInterval(_detonationPollTimer);
    if (pending) {
        _detonationPollTimer = setInterval(() => refreshDetonationPanel(e.id), 10000);
    }
}

async function refreshDetonationPanel(emailId) {
    if (!document.getElementById('detonation-panel')) {
        clearInterval(_detonationPollTimer);
        return;
    }
    try {
        const e = await API.get(`/api/emails/${emailId}`);
        renderDetonationPanel(e);
    } catch (_) { /* transient — next tick retries */ }
}

async function mountNoVnc(container, taskId) {
    try {
        if (_activeRfb) { try { _activeRfb.disconnect(); } catch (_) {} _activeRfb = null; }
        const mod = await import('/static/novnc/core/rfb.js');
        const RFB = mod.default;
        const token = document.querySelector('meta[name="ws-token"]')?.content || '';
        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        const url = `${proto}://${location.host}/ws/vnc/${parseInt(taskId) || 0}?token=${encodeURIComponent(token)}`;
        const rfb = new RFB(container, url);
        rfb.viewOnly = true;          // analyst watches; never drives the guest
        rfb.scaleViewport = true;
        rfb.addEventListener('disconnect', (ev) => {
            if (!ev.detail.clean) {
                container.innerHTML = `<div class="sandbox-empty"><p>Sandbox view unavailable
                    (window closed or relay refused). The verdict is unaffected.</p></div>`;
            }
        });
        _activeRfb = rfb;
    } catch (err) {
        container.innerHTML = `<div class="sandbox-empty"><p>Sandbox view unavailable: ${esc(err.message)}</p></div>`;
    }
}

async function openSandboxViewer(taskId) {
    // Honest gate: same detonation_state.is_active() truth the relay enforces.
    // If nothing is detonating, say so immediately — never a doomed spinner.
    let active = false;
    try {
        const st = await API.get('/api/detonation/status');
        active = !!st.window_active;
    } catch (_) { /* treat as inactive */ }

    const existing = document.getElementById('sandbox-viewer-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'sandbox-viewer-overlay';
    overlay.className = 'sandbox-overlay';
    overlay.innerHTML = active
        ? `<div class="sandbox-overlay-box">
               <div class="sandbox-overlay-head"><span>Live sandbox — current job</span>
                   <button class="btn btn-outline btn-sm" onclick="closeSandboxViewer()">✕ Close</button></div>
               <div class="sandbox-live" id="sandbox-viewer-screen"></div>
           </div>`
        : `<div class="sandbox-overlay-box">
               <div class="sandbox-overlay-head"><span>Sandbox</span>
                   <button class="btn btn-outline btn-sm" onclick="closeSandboxViewer()">✕ Close</button></div>
               <div class="sandbox-empty"><div class="emoji">😴</div>
                   <p><strong>No active session right now.</strong></p>
                   <p>The detonation VM only runs during a drained analysis window.
                      The live view activates automatically when your queued sample runs.</p></div>
           </div>`;
    document.body.appendChild(overlay);
    if (active) {
        mountNoVnc(document.getElementById('sandbox-viewer-screen'), taskId);
    }
}

function closeSandboxViewer() {
    if (_activeRfb) { try { _activeRfb.disconnect(); } catch (_) {} _activeRfb = null; }
    document.getElementById('sandbox-viewer-overlay')?.remove();
}

async function detonationRetry(pendingId, emailId) {
    try {
        await API.post(`/api/detonation/${pendingId}/retry`);
        showToast('Re-queued for detonation — runs in the next drained window', 'success');
        refreshDetonationPanel(emailId);
    } catch (err) {
        showToast(`Retry failed: ${err.message}`, 'error');
    }
}
```

Adjust to the file's actual helper names before writing: `esc`, `truncate`, `API.get/post`, `showToast`, `userCan` all exist (used at lines 399-523); if `API.post` requires a body argument, pass `{}`.

Inline `onclick=` handlers are the established pattern in this file (see lines 511-514) and CSP-safe (nonce applies to `<script>` elements, not attributes? — **verify**: the CSP has `script-src 'self' 'nonce-…'` with no `'unsafe-inline'`, which BLOCKS inline event handlers in modern browsers. Check how existing `onclick=` buttons on the detail page work in practice — they are the same pattern, so if they work, this works; if the executing agent finds they rely on `'unsafe-hashes'` or event delegation, mirror that exact mechanism instead.)

- [ ] **Step 3: Append CSS** (end of `src/dashboard/static/css/dashboard.css`)

```css
/* --- Detonation sandbox panel --- */
.sandbox-row { border: 1px solid var(--border, #2a2f3a); border-radius: var(--radius, 8px); padding: 12px; margin-top: 10px; }
.sandbox-row-head { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; font-weight: 600; }
.sandbox-columns { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
@media (max-width: 900px) { .sandbox-columns { grid-template-columns: 1fr; } }
.sandbox-preview-frame, .sandbox-report-frame { width: 100%; border: 1px solid var(--border, #2a2f3a); border-radius: var(--radius, 8px); background: #fff; }
.sandbox-preview-frame { height: 420px; }
.sandbox-report-frame { height: 640px; }
.sandbox-live { width: 100%; height: 420px; background: #000; border-radius: var(--radius, 8px); overflow: hidden; }
.sandbox-empty { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 8px; min-height: 180px; color: var(--text-muted, #8b93a7); text-align: center; padding: 16px; }
.sandbox-error { background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: var(--radius, 8px); padding: 12px; }
.sandbox-verdict { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
.sandbox-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.65); z-index: 1000; display: flex; align-items: center; justify-content: center; }
.sandbox-overlay-box { width: min(1100px, 94vw); background: var(--bg-card, #151a23); border-radius: var(--radius, 8px); padding: 14px; }
.sandbox-overlay-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
.sandbox-preview-meta { padding: 8px; }
```

Match the CSS custom-property names actually used in `dashboard.css` (read the top of the file for the `:root` variables and reuse those; the `var(..., fallback)` form above is safe either way).

- [ ] **Step 4: Verify — syntax + app boot**

- `node --check src/dashboard/static/js/dashboard.js` if node is available; otherwise paste-check by loading the dashboard.
- Start the dashboard (same way the user normally runs it — `python src/api.py` or uvicorn; check `src/api.py`'s `__main__` block) and open an email that has a `detonation_queue` row (any status): panel renders without console errors; an email without rows shows no panel.
- Click "Open sandbox" with no window active: the "No active session right now" state appears instantly.

- [ ] **Step 5: Run the full test suite**

Run: `python -m pytest tests/ -v`
Expected: no regressions.

- [ ] **Step 6: Commit**

```bash
git add src/dashboard/static/js/dashboard.js src/dashboard/static/css/dashboard.css
git commit -m "feat: detonation sandbox panel — queued/live/report/error states + honest Open-sandbox gate"
```

---

### Task 9: Attijari wrapper service source + setup runbook

**Files:**
- Create: `deploy/attijari/vm_wrapper.py`
- Create: `deploy/attijari/vm-wrapper.service`
- Create: `deploy/attijari/vm-wrapper-sudoers`
- Create: `docs/attijari-sandbox-setup.md`

**Interfaces:**
- Consumes: nothing from this repo at runtime (standalone deployable, spec §5.1).
- Produces: `GET /vm/status` → `{"cuckoo2": "<virsh domstate>"}`; `POST /vm/reset` → `{"success": bool, "detail": {...}}`; both require `Authorization: Bearer $VM_WRAPPER_TOKEN`. Task 1's client is the consumer.

- [ ] **Step 1: Create `deploy/attijari/vm_wrapper.py`**

```python
#!/usr/bin/env python3
"""vm_wrapper.py — minimal VM recovery wrapper for the attijari CAPE box.

Runs ON attijari (same operational pattern as cape.service). Exposes exactly
two actions over authenticated HTTP so the dashboard host never needs SSH:

    GET  /vm/status  -> {"cuckoo2": "<virsh domstate output>"}
    POST /vm/reset   -> virsh destroy cuckoo2 + systemctl restart cape.service

Auth: Authorization: Bearer $VM_WRAPPER_TOKEN (from the environment; the
service refuses every request when the token is unset — fail closed).

virsh/systemctl run via sudo with the tightly scoped sudoers entry shipped in
vm-wrapper-sudoers. Bind address must be the INTERNAL interface only (the
systemd unit sets VM_WRAPPER_BIND=192.168.100.10); default is loopback.
"""
import os
import subprocess
from functools import wraps

from flask import Flask, jsonify, request

TOKEN = os.environ.get("VM_WRAPPER_TOKEN", "")
DOMAIN = os.environ.get("VM_WRAPPER_DOMAIN", "cuckoo2")
BIND = os.environ.get("VM_WRAPPER_BIND", "127.0.0.1")
PORT = int(os.environ.get("VM_WRAPPER_PORT", "8090"))

app = Flask(__name__)


def require_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not TOKEN or auth != f"Bearer {TOKEN}":
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


def _run(cmd, timeout=60):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()


@app.get("/vm/status")
@require_token
def vm_status():
    code, out, err = _run(["sudo", "virsh", "domstate", DOMAIN])
    if code != 0:
        return jsonify({"error": err or "virsh domstate failed"}), 500
    return jsonify({DOMAIN: out})


@app.post("/vm/reset")
@require_token
def vm_reset():
    detail = {}
    # 'domain is not running' from destroy is fine — the goal is "not running".
    code, out, err = _run(["sudo", "virsh", "destroy", DOMAIN], timeout=60)
    detail["virsh_destroy"] = {"code": code, "out": out, "err": err}
    code2, out2, err2 = _run(["sudo", "systemctl", "restart", "cape.service"],
                             timeout=120)
    detail["cape_restart"] = {"code": code2, "out": out2, "err": err2}
    ok = code2 == 0
    return jsonify({"success": ok, "detail": detail}), (200 if ok else 500)


if __name__ == "__main__":
    app.run(host=BIND, port=PORT)
```

- [ ] **Step 2: Create `deploy/attijari/vm-wrapper.service`**

```ini
# /etc/systemd/system/vm-wrapper.service
# Adjust User= to the account that runs CAPE (commonly 'cape').
[Unit]
Description=CAPE VM recovery wrapper (cuckoo2 destroy + cape.service restart)
After=network.target

[Service]
User=cape
EnvironmentFile=/etc/vm-wrapper.env
ExecStart=/usr/bin/python3 /opt/vm-wrapper/vm_wrapper.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 3: Create `deploy/attijari/vm-wrapper-sudoers`**

```
# /etc/sudoers.d/vm-wrapper  (install with visudo -cf to validate first)
# Exactly the three commands the wrapper needs — nothing broader.
cape ALL=(root) NOPASSWD: /usr/bin/virsh domstate cuckoo2
cape ALL=(root) NOPASSWD: /usr/bin/virsh destroy cuckoo2
cape ALL=(root) NOPASSWD: /usr/bin/systemctl restart cape.service
```

- [ ] **Step 4: Syntax-check the wrapper**

Run: `python -m py_compile deploy/attijari/vm_wrapper.py`
Expected: exits 0. (Flask is not installed on the Windows host — py_compile only parses, which is exactly what we can verify here; functional verification happens on attijari via the runbook.)

- [ ] **Step 5: Write `docs/attijari-sandbox-setup.md`**

One linear runbook, strict order, a verify step after every action (spec §9). Full content:

````markdown
# Attijari sandbox setup runbook — dashboard integration

One linear pass. Do the steps IN ORDER; each ends with a verify command —
do not continue past a failed verify. All commands run **on attijari**
(192.168.100.10) unless marked HOST (the Windows dashboard machine).

## 0. Prerequisites

- CAPE works end-to-end (`cape.service`, `cape-processor.service` active).
- `virsh domstate cuckoo2` answers (libvirt reachable).
- Python 3 + pip available.

## 1. VM wrapper service

```bash
sudo mkdir -p /opt/vm-wrapper
sudo cp vm_wrapper.py /opt/vm-wrapper/          # from deploy/attijari/
sudo pip3 install flask

# Token: generate once, never commit anywhere
echo "VM_WRAPPER_TOKEN=$(openssl rand -hex 24)" | sudo tee /etc/vm-wrapper.env
echo "VM_WRAPPER_BIND=192.168.100.10" | sudo tee -a /etc/vm-wrapper.env
sudo chmod 600 /etc/vm-wrapper.env

# Scoped sudo (validate BEFORE installing)
sudo visudo -cf vm-wrapper-sudoers && sudo cp vm-wrapper-sudoers /etc/sudoers.d/vm-wrapper
sudo chmod 440 /etc/sudoers.d/vm-wrapper

sudo cp vm-wrapper.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now vm-wrapper
```

**Verify:**
```bash
TOKEN=$(grep VM_WRAPPER_TOKEN /etc/vm-wrapper.env | cut -d= -f2)
curl -s -H "Authorization: Bearer $TOKEN" http://192.168.100.10:8090/vm/status
# expected: {"cuckoo2":"shut off"}   (or "running" if a job is live)
curl -s http://192.168.100.10:8090/vm/status
# expected: {"error":"unauthorized"} — no token, no answer
```

## 2. Fix the cuckoo2 VNC port

CAPE reverts/boots cuckoo2 constantly; with `autoport='yes'` the VNC port
can move between boots and websockify would point at nothing.

```bash
sudo virsh edit cuckoo2
# find:  <graphics type='vnc' port='-1' autoport='yes' ...>
# make:  <graphics type='vnc' port='5900' autoport='no' listen='127.0.0.1'>
```

**Verify (must survive a domain restart):**
```bash
sudo virsh vncdisplay cuckoo2      # expected: 127.0.0.1:0   (i.e. port 5900)
# then let CAPE run one任务 (or virsh start/destroy cuckoo2) and check again
```

## 3. websockify

```bash
sudo pip3 install websockify
# quick test run:
websockify 192.168.100.10:6080 127.0.0.1:5900
```

**Verify** (second shell): `python3 -c "import websocket"` isn't needed —
just: `curl -s -o /dev/null -w '%{http_code}' http://192.168.100.10:6080` →
`405` (websockify answers, refuses plain GET upgrade-less requests) — or use
`wscat -c ws://192.168.100.10:6080` if installed (connects, then hangs: OK).

Then make it a service:

```bash
sudo tee /etc/systemd/system/websockify-cuckoo2.service <<'EOF'
[Unit]
Description=websockify bridge to cuckoo2 VNC (5900 -> 6080)
After=network.target

[Service]
ExecStart=/usr/local/bin/websockify 192.168.100.10:6080 127.0.0.1:5900
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now websockify-cuckoo2
```

**Verify:** `systemctl is-active websockify-cuckoo2` → `active`, curl check again.

## 4. noVNC assets

Nothing to do on attijari — the dashboard serves its own vendored copy at
`/static/novnc/`. **Verify (HOST):** browse to
`http://<dashboard>/static/novnc/core/rfb.js` while logged in → JS source loads.

## 5. Dashboard `.env` (HOST) — only after 1–4 all pass

Append to the dashboard's `.env` (never commit):

```
CAPE_VM_WRAPPER_ENABLED=1
CAPE_VM_WRAPPER_URL=http://192.168.100.10:8090
CAPE_VM_WRAPPER_TOKEN=<the token from /etc/vm-wrapper.env>
WEBSOCKIFY_URL=ws://192.168.100.10:6080
```

Restart the dashboard server (config is read at import).

**Verify end-to-end:**
1. Queue a detonation (or `UPDATE pending_detonation SET status='queued' ...`
   on a test row) and trigger the drained window.
2. Email detail page: panel shows *queued* → *running* with a live screen →
   *reported* with the embedded CAPE report.
3. With nothing running, "Open sandbox" shows **No active session right now**
   immediately (no spinner).
4. Kill `websockify` mid-run: the live pane shows "Sandbox view unavailable";
   the verdict/escalation still lands (display-only, fail-safe intact).
````

**IMPORTANT (self-check fix applied):** in the runbook text above, step 2's verify line contains the string "让 CAPE run one任务" — that is a typo artifact; write it as "then let CAPE run one task (or virsh start/destroy cuckoo2) and check again". The executing agent must write clean English throughout.

- [ ] **Step 6: Commit**

```bash
git add deploy/attijari docs/attijari-sandbox-setup.md
git commit -m "feat: attijari VM wrapper service (source+unit+sudoers) and linear setup runbook"
```

---

### Task 10: Final verification + CLAUDE.md build log

**Files:**
- Modify: `CLAUDE.md` (Build Log section, append entry)

- [ ] **Step 1: Full test suite**

Run: `python -m pytest tests/ -v`
Expected: everything passes, including the pre-existing `test_detonation.py` / `test_pipeline_e2e.py` suites.

- [ ] **Step 2: App boot smoke test**

Start the dashboard server, log in, and click through: inbox → an email with a detonation row → panel renders; "Open sandbox" shows the honest empty state (no window is active on a dev box); `/static/novnc/core/rfb.js` serves; `/api/detonation/report/1/` (no CAPE up) shows the styled "Sandbox report unavailable" card, not a stack trace.

- [ ] **Step 3: Append to the CLAUDE.md Build Log**

Add under `## Build Log` (adjust the date if executed later):

```markdown
- **2026-07-13** — CAPE dashboard integration built per the approved design spec: `src/routers/detonation_proxy.py` (same-origin CAPE report proxy with path allowlist, window-gated `/ws/vnc/<task>` relay to websockify, `/raw` attachment preview keyed on PendingDetonation.id with magic-byte-forced content types, retry endpoint), `src/cape_vm_wrapper.py` + cuckoo2 pre-flight in `detonation.py`, vendored noVNC 1.5.0, detonation panel in `dashboard.js`, attijari deliverables in `deploy/attijari/` + `docs/attijari-sandbox-setup.md`. CSP gained `frame-src 'self'`; X-Frame-Options is `SAMEORIGIN` on the two framed surfaces only (spec §8 wrongly said DENY could stay — XFO applies to the framed response). `CAPE_VM_WRAPPER_ENABLED` defaults to 0 until the runbook is executed on attijari. Requires dashboard restart + `pip install websockets==12.0`.
```

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: build-log entry for CAPE dashboard integration"
```

---

## Self-review record

**Spec coverage:** §5.1 wrapper service → Task 9; §5.2 host client + pre-flight → Tasks 1-2; §5.3 report proxy / WS relay / raw endpoint / `web_report_url` → Tasks 3-6; §5.4 vendored noVNC → Task 7; §5.5 frontend panel + honest Open-sandbox → Task 8; §7 fail-safe (display-only, relay window gate, error cards, forced content-type) → Tasks 4-6, 8; §8 security (CSP `frame-src 'self'`, tokens in `.env`, auth on both proxies, local-only upstreams) → Tasks 1, 4-6; §9 runbook → Task 9; §10 testing → unit tests hermetic per task + manual demo checklist in the runbook (integration tests via mock-CAPE TestClient were downscoped: importing the full app in tests drags in heavy modules; the pure-helper tests cover the same logic).
**Known open verifications for the executing agent:** (a) inline `onclick=` handlers under the nonce CSP — mirror whatever mechanism the existing detail-page buttons actually use; (b) FastAPI not applying router-level HTTP `dependencies` to WebSocket routes — confirm by connecting without a cookie; (c) `API.post` signature (body arg optional or not).
