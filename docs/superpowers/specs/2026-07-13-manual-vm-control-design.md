# Manual VM Control — Design Spec

**Date:** 2026-07-13
**Status:** Approved (pending user review of this document)
**Phase:** 1 of 2 (Phase 2 — idle inspection session — deferred until the attijari runbook is executed and proven)

## Problem

The detonation sandbox currently has exactly one trigger: the automatic path
(`main.py` poll tick → `process_detonation_queue()` after all emails are
handled). Operators have no way to:

1. Start the detonation window on demand ("run the queue now, I'm watching").
2. Watch a specific attachment execute inside the VM ("See in VM").

Both must respect the RAM-drain design: the CAPE VM only runs inside a drained
window (Ollama unloaded, Llama Guard freed, Docker stopped), and email analysis
is suspended for the duration. The operator must be warned about that
suspension and it must be impossible to start two windows at once.

## Design

### 1. Atomic window acquisition — `detonation_state.try_begin()`

`process_detonation_queue()` currently does `is_active()` → … → `begin()` as
two separate lock acquisitions (detonation.py:259, 264). With a second trigger
path (human button, possibly double-clicked, possibly from two tabs, possibly
racing the poller) this check-then-act is a genuine race.

Add to `detonation_state.py`:

```python
def try_begin(reason: str = "") -> bool:
    """Atomically claim the window. Returns False if already active."""
    global _active, _since, _reason
    with _lock:
        if _active:
            return False
        _active = True
        _since = time.time()
        _reason = reason
        return True
```

`process_detonation_queue()` replaces its `is_active()` check + `begin()` pair
with a single `try_begin()` call; on `False` it returns
`{"processed": 0, "status": "already_running"}` exactly as today. `begin()`
stays for backward compatibility but nothing in the codebase should call it
for window acquisition anymore.

### 2. Endpoint — `POST /api/detonation/run-window`

Lives in `src/routers/detonation_proxy.py` alongside the existing detonation
routes. Permission: `emails.scan` (same as the manual scan trigger).

Behavior, in order:

1. Window already active → **409** `{"detail": "detonation window already active"}`.
2. Queue empty (`count_queued_detonations == 0`) → **200** `{"status": "empty"}`;
   nothing is drained, nothing starts.
3. Otherwise spawn a daemon thread running `process_detonation_queue()` and
   return **200** `{"status": "started"}`.

The 409 in step 1 is a fast-path courtesy check; the *authoritative* guard is
`try_begin()` inside `process_detonation_queue()` itself. If two requests race
past step 1, one thread's `process_detonation_queue()` claims the window and
the other returns `already_running` immediately — no second drain, no second
VM resume. The endpoint does not need its own lock.

Audit: starting a window manually writes an audit entry
(`action="detonation_window_manual"`, actor = session user).

### 3. Warning modal (informed consent)

Every manual path that can start a window shows a confirm modal first:

> ⚠ **Email analysis will be temporarily suspended** while the sandbox VM is
> running. Unprocessed mail stays safely on the IMAP server and will be
> analyzed when the window closes. Continue?

Confirm → fire the request. Cancel → nothing. The modal reuses the existing
`.modal-overlay` pattern in `dashboard.js`.

### 4. Global "Open sandbox VM" button

- **Where:** inbox header, next to the manual Scan trigger; rendered only for
  users with `emails.scan` (same `userCan` gating as other action buttons).
- **Click →** warning modal → `POST /api/detonation/run-window`:
  - `started` → open the existing sandbox viewer (noVNC overlay).
  - `empty` → toast: "Nothing in the detonation queue — the sandbox only
    opens with work to run." Viewer is not opened.
  - `409` → open the viewer directly (a window is already live; show it).
- **Suspension banner:** while `/api/detonation/status` reports
  `window_active`, all dashboard pages show a persistent banner:
  *"Detonation window active — email analysis suspended."* Implemented as a
  small poller in `dashboard.js` (30s interval, plus immediately after any
  manual trigger); banner element lives in `base.html`.

### 5. Per-attachment "See in VM" button

- **Where:** in each detonation-panel row of the email detail view, next to
  the existing Retry button. Shown for rows in `done` or `error` status (a
  `queued` row needs no re-queue; a `running` row already shows the live
  view). Permission: `emails.scan`.
- **Click →** warning modal → then, in sequence:
  1. `POST /api/detonation/{pending_id}/retry` (existing endpoint — re-queues
     the sample).
  2. `POST /api/detonation/run-window`.
  3. Open the sandbox viewer.
- **Startup gap is expected, not an error:** between `started` and cuckoo2
  actually executing there is a real 10–20 s+ gap (attijari VM resume + CAPE
  readiness + task pickup). During that gap the viewer must show a
  distinct **"Starting sandbox — draining RAM and waking the VM…"** state
  (spinner), *not* the "no active session" honest-empty state. Rule: if
  `window_active` is true but no VNC feed is connectable yet → "starting"
  state; if `window_active` is false → "no active session" as today. The
  viewer polls `/api/detonation/status` every 5 s while open and mounts noVNC
  once a task is running.

### 6. What is explicitly out of scope (Phase 2)

- Idle VM session with no task (boot cuckoo2 outside CAPE, push a file, let
  the operator drive). Requires new wrapper verbs (`virsh start`, file push),
  a cleanup contract so CAPE isn't broken by a leftover guest, and sudoers
  changes. Deferred until the attijari runbook (docs/attijari-sandbox-setup.md)
  is executed and the live detonation path is proven end-to-end.
- Re-analyze feature for the 24 `analysis_failed` residue emails (separate
  concern, tracked in CLAUDE.md).

## Known limitation (accepted)

Until the attijari runbook is executed (`CAPE_VM_WRAPPER_ENABLED=1`,
websockify bridge, VNC port fix), a manually-started window will drain RAM,
fail to reach CAPE, escalate queued items (fail-safe), and restore. The
buttons work; the VM won't answer. This is the existing fail-safe behavior,
not a defect of this feature.

## Testing

Unit/integration (extend `tests/test_cape_dashboard.py`):

1. `run-window` with active window → 409.
2. `run-window` with empty queue → `{"status": "empty"}`, and
   `detonation_state.is_active()` stays False (no drain started).
3. `run-window` without `emails.scan` permission → 403.
4. **Race:** two near-simultaneous `run-window` calls with a non-empty queue
   (patch `process_detonation_queue`'s drain/VM internals to a slow no-op) →
   exactly one caller observes a started window; the other's
   `process_detonation_queue` returns `already_running`. Assert via
   `try_begin` semantics: N real OS threads (barrier-released
   `ThreadPoolExecutor`) calling `try_begin` concurrently → exactly one True.
   Additionally assert the synchronization primitive itself provides
   **cross-thread** exclusion, not just cross-coroutine:
   `detonation_state._lock` must be a `threading.Lock`
   (`isinstance(_lock, _thread.LockType)`). Verified at design time:
   `detonation_state.py:18` is `_lock = threading.Lock()` — a raw OS mutex —
   so the endpoint's daemon thread and the poller genuinely exclude each
   other. This assertion exists to catch a future refactor to
   `asyncio.Lock`, which would only synchronize coroutines on one event loop
   and silently reopen the race.
5. `try_begin` when active → False; after `end()` → True again.
6. Audit entry written on manual start.

Manual verification (browser, like tonight's CSP fix): modal appears and
cancels cleanly; empty-queue toast; banner appears/disappears with
window_active; "starting sandbox" state renders during the gap.

## Files touched

| File | Change |
|------|--------|
| `src/detonation_state.py` | add `try_begin()` |
| `src/detonation.py` | use `try_begin()` for window acquisition |
| `src/routers/detonation_proxy.py` | add `POST /api/detonation/run-window` + audit |
| `src/dashboard/static/js/dashboard.js` | warning modal, global button handler, See-in-VM handler, status banner poller, viewer "starting" state |
| `src/dashboard/templates/inbox.html` | global "Open sandbox VM" button |
| `src/dashboard/templates/base.html` | suspension banner element |
| `src/dashboard/static/css/dashboard.css` | banner + starting-state styles |
| `tests/test_cape_dashboard.py` | tests 1–6 above |
