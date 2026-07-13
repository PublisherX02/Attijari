# Manual VM Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Operators can manually start the drained detonation window (with an informed-consent warning) and watch a specific attachment execute live in the sandbox VM, without any possibility of two windows running at once.

**Architecture:** One new atomic primitive (`detonation_state.try_begin()`) closes the existing check-then-act race; one new endpoint (`POST /api/detonation/run-window`) triggers the *existing* `process_detonation_queue()` in a daemon thread; the frontend adds a warning modal, a global button, a per-row "See in VM" button, a suspension banner, and a third "starting…" viewer state. No parallel detonation code path exists — the cuckoo2 pre-flight and fail-safe watchdog apply to manual windows automatically.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy, pytest (existing `tests/test_cape_dashboard.py` style: direct function calls + `monkeypatch`, no TestClient), vanilla JS dashboard.

**Spec:** `docs/superpowers/specs/2026-07-13-manual-vm-control-design.md`

## Global Constraints

- Fail-safe, never fail-open: any failure path must leave the pipeline restorable (the existing `try/finally` watchdog in `process_detonation_queue` is the guarantee — do not bypass it).
- `detonation_state._lock` MUST remain a `threading.Lock` (raw OS mutex). An `asyncio.Lock` would silently reopen the cross-thread race (test enforces this).
- Permission for all manual detonation controls: `emails.scan`. Buttons hidden via `userCan('emails.scan')` / Jinja `permissions.get('emails.scan')`.
- All new UI copy in English matching existing dashboard tone; warning modal must state that mail stays on the IMAP server.
- Run tests from repo root with: `.venv/Scripts/python.exe -m pytest tests/test_cape_dashboard.py -v` (imports resolve because the test file already does `sys.path.insert` for `src/`).
- Commit after each task; do NOT push.
- The server must be restarted (`start.bat`) before browser verification of Task 3.

---

### Task 1: Atomic window acquisition — `try_begin()`

**Files:**
- Modify: `src/detonation_state.py` (add `try_begin` after `begin`, ~line 30)
- Modify: `src/detonation.py:259-264` (replace `is_active()` check + `begin()` with `try_begin()`)
- Test: `tests/test_cape_dashboard.py` (append)

**Interfaces:**
- Produces: `detonation_state.try_begin(reason: str = "") -> bool` — atomically claims the window; `False` if already active. Task 2's endpoint relies on `process_detonation_queue()` returning `{"processed": 0, "status": "already_running"}` when the window is held.

- [ ] **Step 1: Write the failing tests** — append to `tests/test_cape_dashboard.py`:

```python
# ---------------------------------------------------------------------------
# Manual VM control — atomic window acquisition (try_begin)
# ---------------------------------------------------------------------------

class _DummyDB:
    def close(self):
        pass


def test_try_begin_claims_and_refuses_when_active():
    import detonation_state as ds
    ds.end()
    assert ds.try_begin("t1") is True
    assert ds.is_active() is True
    assert ds.try_begin("t2") is False          # already held
    ds.end()
    assert ds.try_begin("t3") is True           # reusable after end()
    ds.end()


def test_detonation_lock_is_cross_thread_mutex():
    # An asyncio.Lock here would only synchronize coroutines on one event
    # loop and silently reopen the poller-vs-endpoint race. Must be a raw
    # OS mutex.
    import _thread
    import detonation_state as ds
    assert isinstance(ds._lock, _thread.LockType)


def test_try_begin_race_exactly_one_winner():
    import threading
    from concurrent.futures import ThreadPoolExecutor
    import detonation_state as ds
    ds.end()
    n = 16
    barrier = threading.Barrier(n)

    def claim(_):
        barrier.wait()                          # all threads fire together
        return ds.try_begin("race")

    with ThreadPoolExecutor(max_workers=n) as ex:
        results = list(ex.map(claim, range(n)))
    ds.end()
    assert results.count(True) == 1
    assert results.count(False) == n - 1


def test_process_queue_already_running_when_window_held(monkeypatch):
    import database
    import detonation
    import detonation_state as ds
    monkeypatch.setattr(database, "SessionLocal", lambda: _DummyDB())
    monkeypatch.setattr(database, "count_queued_detonations", lambda db: 1)
    ds.end()
    assert ds.try_begin("held-by-test")
    try:
        out = detonation.process_detonation_queue()
        assert out == {"processed": 0, "status": "already_running"}
    finally:
        ds.end()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_cape_dashboard.py -k "try_begin or lock_is or already_running_when_window_held" -v`
Expected: FAIL — `AttributeError: module 'detonation_state' has no attribute 'try_begin'` (the lock-type test may already pass; that's fine).

- [ ] **Step 3: Implement `try_begin` in `src/detonation_state.py`** — insert between `begin()` and `end()`:

```python
def try_begin(reason: str = "") -> bool:
    """Atomically claim the window. Returns False if already active.

    This is the ONLY safe way to acquire the window when more than one
    trigger exists (background poller + manual run-window endpoint, which
    runs on a separate OS thread). is_active()-then-begin() is a race.
    """
    global _active, _since, _reason
    with _lock:
        if _active:
            return False
        _active = True
        _since = time.time()
        _reason = reason
        return True
```

- [ ] **Step 4: Use it in `src/detonation.py`** — replace (currently lines 259–265):

```python
    if state.is_active():
        return {"processed": 0, "status": "already_running"}

    summary = {"processed": 0, "escalated": 0, "errors": 0, "status": "ok"}
    cycle_deadline = time.time() + cfg.DETONATION_CYCLE_TIMEOUT
    state.begin("processing detonation queue")
    print("[DETONATION] === Entering drained detonation window ===")
```

with:

```python
    if not state.try_begin("processing detonation queue"):
        return {"processed": 0, "status": "already_running"}

    summary = {"processed": 0, "escalated": 0, "errors": 0, "status": "ok"}
    cycle_deadline = time.time() + cfg.DETONATION_CYCLE_TIMEOUT
    print("[DETONATION] === Entering drained detonation window ===")
```

(The existing `try/…/finally: state.end()` below is unchanged and still guarantees release.)

- [ ] **Step 5: Run the full test file**

Run: `.venv/Scripts/python.exe -m pytest tests/test_cape_dashboard.py -v`
Expected: ALL PASS (29 existing + 4 new).

- [ ] **Step 6: Commit**

```bash
git add src/detonation_state.py src/detonation.py tests/test_cape_dashboard.py
git commit -m "feat: atomic detonation-window acquisition (try_begin) closes check-then-act race"
```

---

### Task 2: `POST /api/detonation/run-window` endpoint

**Files:**
- Modify: `src/routers/detonation_proxy.py` (append new section at end of file)
- Test: `tests/test_cape_dashboard.py` (append)

**Interfaces:**
- Consumes: `detonation_state.is_active()`, `database.count_queued_detonations(db)`, `database.add_audit_entry(...)`, `detonation.process_detonation_queue()` (Task 1 made it race-safe).
- Produces: `POST /api/detonation/run-window` → `{"status": "started"}` | `{"status": "empty"}` | HTTP 409. Task 3's JS calls this.

- [ ] **Step 1: Write the failing tests** — append to `tests/test_cape_dashboard.py`:

```python
# ---------------------------------------------------------------------------
# Manual VM control — run-window endpoint
# ---------------------------------------------------------------------------

def test_run_window_409_when_window_active():
    from types import SimpleNamespace
    from fastapi import HTTPException
    import detonation_state as ds
    from routers.detonation_proxy import api_detonation_run_window
    ds.end()
    assert ds.try_begin("held-by-test")
    try:
        try:
            api_detonation_run_window(user=SimpleNamespace(username="op"))
            assert False, "expected HTTPException 409"
        except HTTPException as e:
            assert e.status_code == 409
    finally:
        ds.end()


def test_run_window_empty_queue_is_noop(monkeypatch):
    from types import SimpleNamespace
    import database
    import detonation_state as ds
    from routers.detonation_proxy import api_detonation_run_window
    ds.end()
    monkeypatch.setattr(database, "SessionLocal", lambda: _DummyDB())
    monkeypatch.setattr(database, "count_queued_detonations", lambda db: 0)
    out = api_detonation_run_window(user=SimpleNamespace(username="op"))
    assert out == {"status": "empty"}
    assert ds.is_active() is False              # nothing was drained/started


def test_run_window_starts_thread_and_writes_audit(monkeypatch):
    import threading
    from types import SimpleNamespace
    import database
    import detonation
    import detonation_state as ds
    from routers.detonation_proxy import api_detonation_run_window
    ds.end()
    audits = []
    ran = threading.Event()
    monkeypatch.setattr(database, "SessionLocal", lambda: _DummyDB())
    monkeypatch.setattr(database, "count_queued_detonations", lambda db: 2)
    monkeypatch.setattr(database, "add_audit_entry",
                        lambda db, **kw: audits.append(kw))
    monkeypatch.setattr(detonation, "process_detonation_queue",
                        lambda: (ran.set(), {"status": "ok"})[1])
    out = api_detonation_run_window(user=SimpleNamespace(username="op"))
    assert out == {"status": "started"}
    assert ran.wait(5), "process_detonation_queue never ran in the thread"
    assert audits and audits[0]["action"] == "detonation_window_manual"
    assert audits[0]["actor"] == "op"
    assert audits[0]["details"]["queued"] == 2


def test_run_window_route_registered_with_scan_permission():
    from routers.detonation_proxy import detonation_proxy_router
    match = [r for r in detonation_proxy_router.routes
             if getattr(r, "path", "") == "/api/detonation/run-window"]
    assert match, "run-window route not registered"
    assert "POST" in match[0].methods
```

(Spec test #3 asked for a 403-without-permission test; permission enforcement
lives in the shared `require_permission` dependency already covered by the
existing auth tests, so this plan asserts the route registration instead and
verifies the permission gate manually in the browser in Task 3.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/Scripts/python.exe -m pytest tests/test_cape_dashboard.py -k run_window -v`
Expected: FAIL — `ImportError: cannot import name 'api_detonation_run_window'`.

- [ ] **Step 3: Implement the endpoint** — append to `src/routers/detonation_proxy.py`:

```python
# ---------------------------------------------------------------------------
# Manually start the drained detonation window (operator-triggered)
# ---------------------------------------------------------------------------

@detonation_proxy_router.post("/api/detonation/run-window")
def api_detonation_run_window(
    user: AuthenticatedUser = Depends(require_permission("emails.scan")),
):
    """Start processing the detonation queue NOW instead of waiting for the
    next poll tick. Email analysis is suspended for the duration (the caller
    has confirmed a warning modal).

    The 409 below is a fast-path courtesy; the AUTHORITATIVE mutual
    exclusion is detonation_state.try_begin() inside
    process_detonation_queue() — two racing calls cannot both drain.
    """
    import threading

    import detonation_state
    from database import SessionLocal, count_queued_detonations, add_audit_entry

    if detonation_state.is_active():
        raise HTTPException(409, "detonation window already active")

    db = SessionLocal()
    try:
        queued = count_queued_detonations(db)
        if queued == 0:
            return {"status": "empty"}
        add_audit_entry(
            db, action="detonation_window_manual", actor=user.username,
            details={"queued": queued},
        )
    finally:
        db.close()

    from detonation import process_detonation_queue
    threading.Thread(
        target=process_detonation_queue,
        daemon=True,
        name="manual-detonation-window",
    ).start()
    return {"status": "started"}
```

- [ ] **Step 4: Run the full test file**

Run: `.venv/Scripts/python.exe -m pytest tests/test_cape_dashboard.py -v`
Expected: ALL PASS (33 + 4 new = 37).

- [ ] **Step 5: Commit**

```bash
git add src/routers/detonation_proxy.py tests/test_cape_dashboard.py
git commit -m "feat: POST /api/detonation/run-window — operator-triggered drained window"
```

---

### Task 3: Frontend — warning modal, global button, See-in-VM, banner, viewer starting state

**Files:**
- Modify: `src/dashboard/static/js/dashboard.js` (rewrite `openSandboxViewer`/`closeSandboxViewer` ~lines 692–730; add new functions after `detonationRetry` ~line 740; add See-in-VM buttons in `_detonationRowHtml` done/error branches ~lines 584–607)
- Modify: `src/dashboard/templates/inbox.html:10-12` (global button)
- Modify: `src/dashboard/templates/base.html:15-16` (banner element)
- Modify: `src/dashboard/static/css/dashboard.css` (banner style, append to file)
- Modify: `src/routers/emails.py:845` (status endpoint permission `health.view` → `emails.view`)
- Test: browser verification (no JS test harness exists in this repo)

**Interfaces:**
- Consumes: `POST /api/detonation/run-window` (Task 2), existing `POST /api/detonation/{id}/retry`, existing `GET /api/detonation/status` (`window_active`, `by_status.running`), existing `mountNoVnc`, `showToast`, `userCan`, `API` helpers.
- Produces: global JS functions `openVmWindow()`, `seeInVm(pendingId, emailId)`, `confirmVmSuspension(onConfirm)`, `refreshDetonationBanner()` (referenced from inline `onclick` attributes — they MUST be top-level functions, not module-scoped).

- [ ] **Step 1: Relax `/api/detonation/status` permission** — in `src/routers/emails.py:845` change:

```python
async def api_detonation_status(user: AuthenticatedUser = Depends(require_permission("health.view"))):
```

to:

```python
async def api_detonation_status(user: AuthenticatedUser = Depends(require_permission("emails.view"))):
```

Rationale (add as a code comment on the line above): the suspension banner and the sandbox viewer's honest-state gate poll this from every dashboard page; analysts with `emails.view` already see every filename it could reveal.

- [ ] **Step 2: Banner element** — in `src/dashboard/templates/base.html`, insert between line 15 `<body>` and line 16 `<div class="app-layout">`:

```html
    <div id="detonation-banner" class="detonation-banner" style="display:none">
        🔬 Detonation window active — email analysis temporarily suspended.
        Unprocessed mail stays on the IMAP server.
    </div>
```

- [ ] **Step 3: Banner style** — append to `src/dashboard/static/css/dashboard.css`:

```css
/* --- Detonation suspension banner --- */
.detonation-banner {
    position: sticky;
    top: 0;
    z-index: 900; /* under modals (1000), over content */
    padding: 10px 16px;
    text-align: center;
    font-size: 0.85rem;
    font-weight: 600;
    color: #78350f;
    background: linear-gradient(90deg, #fbbf24, #f59e0b);
    border-bottom: 1px solid #d97706;
}
```

- [ ] **Step 4: Global button** — in `src/dashboard/templates/inbox.html`, replace lines 10–12:

```html
    {% if role == 'admin' or permissions.get('emails.scan', False) %}
    <button class="btn btn-primary" id="scan-btn" onclick="triggerScan()">🔄 Scan Now</button>
    {% endif %}
```

with:

```html
    {% if role == 'admin' or permissions.get('emails.scan', False) %}
    <div style="display:flex;gap:8px">
        <button class="btn btn-primary" id="scan-btn" onclick="triggerScan()">🔄 Scan Now</button>
        <button class="btn btn-outline" id="open-vm-btn" onclick="openVmWindow()">🔬 Open sandbox VM</button>
    </div>
    {% endif %}
```

- [ ] **Step 5: JS — modal, triggers, banner poller** — in `src/dashboard/static/js/dashboard.js`, insert after `detonationRetry` (after line 740):

```javascript
/* --- Manual VM control ------------------------------------------------- */

function confirmVmSuspension(onConfirm) {
    document.getElementById('vm-warning-overlay')?.remove();
    const ov = document.createElement('div');
    ov.id = 'vm-warning-overlay';
    ov.className = 'modal-overlay open';
    ov.innerHTML = `
        <div class="modal">
            <h3>⚠ Suspend email analysis?</h3>
            <p>Email analysis will be <strong>temporarily suspended</strong> while the
               sandbox VM is running. Unprocessed mail stays safely on the IMAP server
               and is analyzed when the window closes.</p>
            <div class="action-bar" style="margin-top:16px">
                <button class="btn btn-outline" id="vm-warning-cancel">Cancel</button>
                <button class="btn btn-danger" id="vm-warning-confirm">Suspend analysis &amp; open VM</button>
            </div>
        </div>`;
    document.body.appendChild(ov);
    ov.querySelector('#vm-warning-cancel').onclick = () => ov.remove();
    ov.querySelector('#vm-warning-confirm').onclick = () => { ov.remove(); onConfirm(); };
}

async function _startWindowAndView() {
    try {
        const r = await API.post('/api/detonation/run-window');
        if (r.status === 'empty') {
            showToast('Nothing in the detonation queue — the sandbox only opens with work to run', 'warning');
            return;
        }
        refreshDetonationBanner();
        openSandboxViewer(0);
    } catch (err) {
        if (String(err.message).startsWith('API 409')) {
            openSandboxViewer(0);   // a window is already live — just show it
        } else {
            showToast(`Could not start sandbox window: ${err.message}`, 'error');
        }
    }
}

function openVmWindow() {
    confirmVmSuspension(_startWindowAndView);
}

function seeInVm(pendingId, emailId) {
    confirmVmSuspension(async () => {
        try {
            await API.post(`/api/detonation/${parseInt(pendingId)}/retry`);
        } catch (err) {
            // 409 = already queued/running — fine, keep going. Anything else is fatal.
            if (!String(err.message).startsWith('API 409')) {
                showToast(`Could not queue the sample: ${err.message}`, 'error');
                return;
            }
        }
        if (emailId) refreshDetonationPanel(parseInt(emailId));
        await _startWindowAndView();
    });
}

async function refreshDetonationBanner() {
    const banner = document.getElementById('detonation-banner');
    if (!banner) return;
    try {
        const st = await API.get('/api/detonation/status');
        banner.style.display = st.window_active ? 'block' : 'none';
    } catch (_) { /* not permitted or transient — leave as-is */ }
}
setInterval(refreshDetonationBanner, 30000);
document.addEventListener('DOMContentLoaded', refreshDetonationBanner);
```

- [ ] **Step 6: JS — viewer with "starting" state** — replace `openSandboxViewer` and `closeSandboxViewer` (currently dashboard.js lines 692–730) with:

```javascript
let _viewerPollTimer = null;

async function openSandboxViewer(taskId) {
    document.getElementById('sandbox-viewer-overlay')?.remove();
    clearInterval(_viewerPollTimer);

    const overlay = document.createElement('div');
    overlay.id = 'sandbox-viewer-overlay';
    overlay.className = 'sandbox-overlay';
    overlay.innerHTML = `
        <div class="sandbox-overlay-box">
            <div class="sandbox-overlay-head"><span>Sandbox</span>
                <button class="btn btn-outline btn-sm" onclick="closeSandboxViewer()">✕ Close</button></div>
            <div id="sandbox-viewer-body"></div>
        </div>`;
    document.body.appendChild(overlay);

    // Three honest states driven by /api/detonation/status:
    //   window_active + a running task  -> live noVNC feed
    //   window_active, nothing running  -> "starting" (drain + VM wake gap, 10-20s+)
    //   no window                       -> "no active session" (never a doomed spinner)
    let mounted = false;
    const render = async () => {
        const body = document.getElementById('sandbox-viewer-body');
        if (!body) { clearInterval(_viewerPollTimer); return; }
        let st = { window_active: false, by_status: {} };
        try { st = await API.get('/api/detonation/status'); } catch (_) {}
        const running = (st.by_status && st.by_status.running) || 0;

        if (st.window_active && running > 0) {
            if (!mounted) {
                body.innerHTML = '<div class="sandbox-live" id="sandbox-viewer-screen"></div>';
                mountNoVnc(document.getElementById('sandbox-viewer-screen'), parseInt(taskId) || 0);
                mounted = true;
            }
        } else if (st.window_active) {
            mounted = false;
            body.innerHTML = `<div class="sandbox-empty"><div class="spinner"></div>
                <p><strong>Starting sandbox…</strong></p>
                <p>Draining RAM and waking the VM — the live view appears when the
                   sample starts running.</p></div>`;
        } else {
            mounted = false;
            body.innerHTML = `<div class="sandbox-empty"><div class="emoji">😴</div>
                <p><strong>No active session right now.</strong></p>
                <p>The detonation VM only runs during a drained analysis window.
                   The live view activates automatically when your queued sample runs.</p></div>`;
        }
    };
    await render();
    _viewerPollTimer = setInterval(render, 5000);
}

function closeSandboxViewer() {
    clearInterval(_viewerPollTimer);
    _viewerPollTimer = null;
    if (_activeRfb) { try { _activeRfb.disconnect(); } catch (_) {} _activeRfb = null; }
    document.getElementById('sandbox-viewer-overlay')?.remove();
    refreshDetonationBanner();
}
```

- [ ] **Step 7: JS — See-in-VM buttons in the detonation panel** — in `_detonationRowHtml`:

In the **done** branch, after the "Open full report ↗" link (line ~592), add:

```javascript
                ${userCan('emails.scan')
                    ? `<button class="btn btn-outline btn-sm"
                         onclick="seeInVm(${parseInt(row.id)}, ${parseInt(e.id)})">🖥 See in VM</button>`
                    : ''}
```

In the **error** branch, after the existing Retry button `` `...Retry detonation</button>` `` (line ~605), add inside the same `userCan('emails.scan')` template string:

```javascript
                       <button class="btn btn-outline btn-sm"
                         onclick="seeInVm(${parseInt(row.id)}, ${parseInt(e.id)})">🖥 See in VM</button>
```

(so the error branch reads: Retry button followed by See-in-VM button, both gated by the one existing `userCan('emails.scan')` conditional).

- [ ] **Step 8: Syntax check + full test suite**

Run: `node --check src/dashboard/static/js/dashboard.js && .venv/Scripts/python.exe -m pytest tests/test_cape_dashboard.py -v`
Expected: syntax OK; ALL tests PASS.

- [ ] **Step 9: Restart server and verify in browser**

Run: `Start-Process -FilePath "C:\Users\moham\Attijari\start.bat" -WorkingDirectory "C:\Users\moham\Attijari"` (start.bat kills the old process itself), wait for `curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/login` → 200.

Then verify in the browser (hard-refresh):
1. Inbox shows "🔬 Open sandbox VM" next to "Scan Now" (admin user).
2. Click it → warning modal appears; Cancel closes with no request fired.
3. Click again → Confirm with empty queue → toast "Nothing in the detonation queue…", no viewer.
4. `GET /api/detonation/status` returns 200 for a logged-in analyst (permission now `emails.view`).
5. Temporarily hold the window from a shell to fake an active window, then confirm the banner appears and the viewer shows "Starting sandbox…":
   `.venv/Scripts/python.exe -c "import sys; sys.path.insert(0,'src'); import detonation_state as ds; ds.try_begin('manual-test'); import time; time.sleep(90)"` —
   NOTE: this holds the flag in a *separate process*, which the server cannot see (in-process flag). Instead verify the starting state by stubbing: in the browser console run `API.get = async (u) => u.includes('/api/detonation/status') ? {window_active: true, by_status: {}} : fetch(u).then(r=>r.json());` then `openSandboxViewer(0)` → must show "Starting sandbox…" spinner state. Reload the page afterwards to undo the stub.
6. Open an email that has a detonation row in `done`/`error` status (email with `analysis_failed` detonation or any past detonation) → row shows "🖥 See in VM" button.

- [ ] **Step 10: Commit**

```bash
git add src/dashboard/static/js/dashboard.js src/dashboard/templates/inbox.html src/dashboard/templates/base.html src/dashboard/static/css/dashboard.css src/routers/emails.py
git commit -m "feat: manual VM controls — open-sandbox button, See-in-VM, suspension warning + banner, viewer starting state"
```

---

### Task 4: Build log + docs

**Files:**
- Modify: `CLAUDE.md` (Build Log — note: CLAUDE.md is gitignored, edit only, no commit)
- Modify: `docs/superpowers/specs/2026-07-13-manual-vm-control-design.md` (status → Implemented)

**Interfaces:** none.

- [ ] **Step 1:** Add a Build Log entry to `CLAUDE.md` dated 2026-07-13 (late), covering: try_begin race fix, run-window endpoint, UI additions, status-endpoint permission change (`health.view` → `emails.view`), and the standing limitation that nothing detonates for real until the attijari runbook is executed.

- [ ] **Step 2:** In the spec header change `**Status:** Approved (pending user review of this document)` to `**Status:** Implemented (Phase 1) — 2026-07-13`.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-07-13-manual-vm-control-design.md
git commit -m "docs: mark manual VM control spec implemented (Phase 1)"
```
