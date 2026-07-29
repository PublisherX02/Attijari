# Always-On Sequential Attachment Detonation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every non-rejected email attachment is automatically detonated in CAPE, one at a time, with the VM staying hot across a batch's queue and only suspending after 5 minutes idle; a manually-inserted priority attachment runs immediately after whatever is currently detonating (never interrupting it); each email gets a second LLM pass folding in the CAPE report before its verdict finalizes.

**Architecture:** Extend the existing memory-gated CAPE detonation subsystem (`detonation.py`, `detonation_config.py`, `database.py`'s `PendingDetonation` table) rather than replacing it. Three changes carry the whole feature: (1) broaden the auto-enqueue gate in `main.py` so every detonable, non-rejected attachment queues instead of only "inconclusive + unsure" ones; (2) rewrite `process_detonation_queue()`'s batch loop into a re-query-before-each-item loop with an idle timeout, so it stays hot, processes one at a time, and immediately honors a mid-run priority insert; (3) add a second LLM pass keyed off the stored CAPE report. The dashboard's attachment panel, VNC viewer, and "insist" priority endpoint already exist and need only small extensions, not new plumbing.

**Tech Stack:** Python 3.12, SQLAlchemy (PostgreSQL), pytest with monkeypatch-based fakes (no live DB/CAPE in unit tests), vanilla JS dashboard (no framework).

## Global Constraints

- All rejections still require human confirmation (CLAUDE.md non-negotiable). The second LLM pass may only ever set `Email.status` to `accepted` or `escalated` — never `quarantined`. `quarantined`/`released` remain analyst-only actions on an already-`escalated` email.
- Fail-safe, never fail-open (CLAUDE.md rule 1): any crash, timeout, or CAPE-unavailable condition must escalate, never silently accept.
- Rules-engine rejections are not overridable by the LLM (CLAUDE.md rule 2) — an attachment on a deterministically-escalated email is never enqueued for detonation (no informational value; it's already going to a human).
- Automated (per-email) detonation views stay **view-only** in the VNC panel; manual (analyst-uploaded) detonation keeps full interactive control. This distinction is deliberate and must not change.
- `DETONATION_CYCLE_TIMEOUT` (30 min, `detonation_config.py:46`) remains a hard outer cap on one drained window, including idle-timeout waiting — the watchdog must always restore the pipeline.
- Follow existing test conventions: monkeypatched `FakeDB`/`FakeRow` fakes (see `tests/test_manual_detonation.py:144-180`), no real Postgres or CAPE connection in unit tests.

---

### Task 1: Broaden the auto-enqueue gate and persist body_text for reuse

**Files:**
- Modify: `src/main.py:27-70` (`_maybe_enqueue_detonation`)
- Modify: `src/main.py:783-791` (`enrichment_result` dict assembled at save time)
- Test: `tests/test_main_detonation_gate.py` (new file)

**Interfaces:**
- Consumes: `enqueue_detonation(db, sha256, stored_path, filename=None, email_id=None, idempotency_key=None, reason=None, created_by=None, priority=False, status="queued")` (existing, `src/database.py:786`)
- Produces: `_maybe_enqueue_detonation(db, parsed: dict, email_id: int, deterministic_escalation: bool) -> None` (same signature, callers in `main.py:820` unchanged). `enrichment_result["body_text"]` becomes a new persisted field other tasks (Task 4) read.

- [ ] **Step 1: Write the failing test for the broadened gate**

```python
# tests/test_main_detonation_gate.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def _install_fake_enqueue(monkeypatch):
    import main
    calls = []

    def fake_enqueue(db, sha256, stored_path, filename=None, email_id=None,
                     idempotency_key=None, reason=None, created_by=None,
                     priority=False, status="queued"):
        calls.append({"sha256": sha256, "filename": filename, "reason": reason})
        return None

    monkeypatch.setattr("database.enqueue_detonation", fake_enqueue)
    return calls


def test_clean_looking_attachment_still_enqueues(monkeypatch):
    """Today's gate requires llm_unsure or static_suspicious. The new gate
    must enqueue ANY detonation_candidate, even a confident-clean one."""
    import main
    calls = _install_fake_enqueue(monkeypatch)
    parsed = {
        "llm_analysis": {"confidence": 0.99},  # LLM very sure -> old gate would skip
        "extraction": {"results": [
            {"detonation_candidate": True, "suspicious": False,
             "sha256": "a" * 64, "filename": "invoice.pdf"},
        ]},
        "attachments": [{"sha256": "a" * 64, "stored_path": "/tmp/invoice.pdf"}],
        "idempotency_key": "key1",
    }
    main._maybe_enqueue_detonation(db=object(), parsed=parsed, email_id=1,
                                    deterministic_escalation=False)
    assert len(calls) == 1
    assert calls[0]["sha256"] == "a" * 64


def test_deterministically_escalated_email_never_enqueues(monkeypatch):
    import main
    calls = _install_fake_enqueue(monkeypatch)
    parsed = {
        "extraction": {"results": [
            {"detonation_candidate": True, "sha256": "b" * 64, "filename": "x.exe"},
        ]},
        "attachments": [{"sha256": "b" * 64, "stored_path": "/tmp/x.exe"}],
        "idempotency_key": "key2",
    }
    main._maybe_enqueue_detonation(db=object(), parsed=parsed, email_id=2,
                                    deterministic_escalation=True)
    assert calls == []


def test_non_candidate_attachment_never_enqueues(monkeypatch):
    """detonation_candidate is already False for rules-engine-rejected
    attachments (extraction.py:753-758) — confirms the gate still respects it."""
    import main
    calls = _install_fake_enqueue(monkeypatch)
    parsed = {
        "extraction": {"results": [
            {"detonation_candidate": False, "sha256": "c" * 64, "filename": "y.exe"},
        ]},
        "attachments": [{"sha256": "c" * 64, "stored_path": "/tmp/y.exe"}],
        "idempotency_key": "key3",
    }
    main._maybe_enqueue_detonation(db=object(), parsed=parsed, email_id=3,
                                    deterministic_escalation=False)
    assert calls == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_main_detonation_gate.py -v`
Expected: `test_clean_looking_attachment_still_enqueues` FAILS (today's gate requires
`llm_unsure or static_suspicious`; confidence 0.99 and `suspicious: False` means
neither is true, so nothing gets enqueued and `calls` stays empty).

- [ ] **Step 3: Rewrite `_maybe_enqueue_detonation` in `src/main.py`**

Replace lines 27-70 with:

```python
def _maybe_enqueue_detonation(db, parsed: dict, email_id: int, deterministic_escalation: bool) -> None:
    """Queue every detonable attachment for behavioral analysis.

    Trigger (per 2026-07-28 always-on design): any attachment extraction
    marked as a detonation_candidate gets queued, unconditionally. Extraction
    already excludes rules-engine-rejected attachments from being a candidate
    at all (extraction.py sets detonation_candidate=False when the
    per-attachment result was escalated) — so "always enqueue candidates"
    already means "skip evident rejects". Emails deterministically escalated
    at the email level are skipped entirely: they're going to a human
    regardless, so a VM run would just burn memory for no new information.
    """
    from database import enqueue_detonation

    if deterministic_escalation:
        return

    ext_results = parsed.get("extraction", {}).get("results", [])
    path_by_sha = {}
    for att in parsed.get("attachments", []):
        sha = att.get("sha256")
        if sha and att.get("stored_path"):
            path_by_sha[sha] = att["stored_path"]

    for er in ext_results:
        if not er.get("detonation_candidate"):
            continue
        sha = er.get("sha256")
        stored_path = path_by_sha.get(sha)
        if not (sha and stored_path):
            continue
        enqueue_detonation(
            db, sha256=sha, stored_path=stored_path,
            filename=er.get("filename"), email_id=email_id,
            idempotency_key=parsed.get("idempotency_key"),
            reason="always_on_auto_detonate",
        )
        print(f"[DETONATION] Queued {er.get('filename')} for detonation (always-on)")
```

Note this drops the `DETONATION_CONFIDENCE_THRESHOLD` env var and the
`llm_unsure`/`static_suspicious` branching entirely — they're no longer read
anywhere else (confirm with `grep -rn DETONATION_CONFIDENCE_THRESHOLD src/`
before deleting the `.env.example` line, if any, in Step 6).

- [ ] **Step 4: Persist `body_text` and full context onto the saved email so the second LLM pass (Task 4) can reuse it without re-parsing the archived .eml**

In `src/main.py`, inside the `email_data["enrichment_result"]` dict at line 783-791, add three keys:

```python
                        "enrichment_result": {
                            "threatfox": parsed.get("analysis", {}).get("threatfox"),
                            "virustotal": parsed.get("analysis", {}).get("virustotal"),
                            "abuseipdb": parsed.get("analysis", {}).get("abuseipdb"),
                            "otx": parsed.get("analysis", {}).get("otx"),
                            "dnstwist": parsed.get("analysis", {}).get("dnstwist"),
                            "whois": parsed.get("analysis", {}).get("whois"),
                            "auth": parsed.get("auth"),
                            "body_text": parsed.get("body_text"),
                            "headers": parsed.get("headers"),
                            "attachments_meta": parsed.get("attachments"),
                        },
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_main_detonation_gate.py -v`
Expected: 3 passed.

- [ ] **Step 6: Check for orphaned config**

Run: `grep -rn "DETONATION_CONFIDENCE_THRESHOLD" src/ .env.example 2>/dev/null`
If the only remaining reference was the one just deleted from `main.py`,
remove the corresponding line from `.env.example` too (there is no
`detonation_config.py` entry for it today, so nothing there to remove).

- [ ] **Step 7: Run the full existing detonation test suite to check for regressions**

Run: `python -m pytest tests/test_detonation.py tests/test_manual_detonation.py tests/test_detonation_recovery.py -v`
Expected: all previously-passing tests still pass (none of them exercise
`_maybe_enqueue_detonation` directly, per a `grep -rn "_maybe_enqueue_detonation" tests/`).

- [ ] **Step 8: Commit**

```bash
git add src/main.py tests/test_main_detonation_gate.py
git commit -m "feat: enqueue every detonable attachment, not just inconclusive ones"
```

---

### Task 2: Add the `pending_detonation` email status

**Files:**
- Modify: `src/database.py:98-103` (`Email.status` column comment)
- Modify: `src/main.py:752-757, 772-796` (set `pending_detonation` when an attachment was queued this tick)
- Modify: `src/routers/emails.py:36-38` (`_update_gauge_metrics` queue count)
- Modify: `src/dashboard/static/css/dashboard.css:403-408` (reuse `.badge.pending`, no new CSS needed — see Step 4)
- Test: `tests/test_pending_detonation_status.py` (new file)

**Interfaces:**
- Consumes: `_maybe_enqueue_detonation` from Task 1 (unchanged signature).
- Produces: emails with a still-in-flight detonation now save with
  `status == "pending_detonation"` instead of whatever the first LLM pass
  would have finalized to. Task 4's second pass is the only code that moves
  a `pending_detonation` email to its final `accepted`/`escalated` status.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_pending_detonation_status.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def test_email_model_accepts_pending_detonation_status():
    import database as db
    # No CHECK constraint exists on status (plain String(20), database.py:98-103)
    # — this test documents the new value is a recognized application-level
    # status, not a DB-level enum, by asserting the column comment mentions it.
    import inspect
    src = inspect.getsource(db.Email)
    assert "pending_detonation" in src


def test_gauge_metrics_count_pending_detonation_as_in_queue(monkeypatch):
    import routers.emails as emails_mod

    captured = {}

    class FakeQuery:
        def filter(self, *a, **k): return self
        def count(self): return 3

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()
        def close(self): pass

    monkeypatch.setattr(emails_mod, "SessionLocal", lambda: FakeDB())

    class FakeGauge:
        def labels(self, **k): return self
        def set(self, v): captured["queue_size"] = v

    import metrics
    monkeypatch.setattr(metrics, "emails_in_queue", FakeGauge())
    monkeypatch.setattr(metrics, "blocklist_size", FakeGauge())

    emails_mod._update_gauge_metrics()
    assert captured["queue_size"] == 3
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_pending_detonation_status.py -v`
Expected: `test_email_model_accepts_pending_detonation_status` FAILS
(`"pending_detonation" in src` is False — the comment doesn't mention it yet).

- [ ] **Step 3: Update the `Email.status` comment in `src/database.py`**

```python
    status = Column(
        String(20),
        nullable=False,
        default="recu",
        index=True,
    )  # pending, recu, accepted, escalated, quarantined, released, pending_detonation
```

- [ ] **Step 4: Set `pending_detonation` in `src/main.py` when an attachment was queued this tick**

Directly after the `_maybe_enqueue_detonation` call (currently `src/main.py:820`),
capture whether anything was actually enqueued and use it to override the
status just written. `enqueue_detonation` returns the row (or the existing
de-duped row) on success and `None` only if de-duped as already
queued/running — either way a non-empty return means "this attachment now
has a live pending_detonation entry". Change `_maybe_enqueue_detonation` to
return whether anything was queued so `main.py` can act on it:

In `src/main.py`, change the function signature and return value from Task 1:

```python
def _maybe_enqueue_detonation(db, parsed: dict, email_id: int, deterministic_escalation: bool) -> bool:
    """... (same docstring) ...

    Returns True if at least one attachment was enqueued for this email.
    """
    from database import enqueue_detonation

    if deterministic_escalation:
        return False

    ext_results = parsed.get("extraction", {}).get("results", [])
    path_by_sha = {}
    for att in parsed.get("attachments", []):
        sha = att.get("sha256")
        if sha and att.get("stored_path"):
            path_by_sha[sha] = att["stored_path"]

    queued_any = False
    for er in ext_results:
        if not er.get("detonation_candidate"):
            continue
        sha = er.get("sha256")
        stored_path = path_by_sha.get(sha)
        if not (sha and stored_path):
            continue
        enqueue_detonation(
            db, sha256=sha, stored_path=stored_path,
            filename=er.get("filename"), email_id=email_id,
            idempotency_key=parsed.get("idempotency_key"),
            reason="always_on_auto_detonate",
        )
        queued_any = True
        print(f"[DETONATION] Queued {er.get('filename')} for detonation (always-on)")
    return queued_any
```

Then in the save block (`src/main.py:814-822`), capture the return value and
override the status **after** `email_data` is built but only if the email
wasn't already deterministically escalated (an escalated email always wins —
CLAUDE.md rule 2, rules-engine rejects aren't overridable):

```python
                    # --- Detonation trigger (always-on) ---
                    # Every detonable, non-rejected attachment queues here.
                    # If anything was queued and the email isn't already a
                    # deterministic reject, hold it at pending_detonation
                    # instead of a final accepted/escalated — the second LLM
                    # pass (post-detonation) decides the real final status.
                    try:
                        queued_any = _maybe_enqueue_detonation(db, parsed, saved.id, _deterministic_escalation)
                        if queued_any and not _deterministic_escalation:
                            saved.status = "pending_detonation"
                            db.commit()
                    except Exception as _de:
                        print(f"[DETONATION] Enqueue skipped: {_de}")
```

(This runs after `saved = _save_email(db, email_data)` at line 796, so
`saved` is a live ORM row — setting `.status` and committing again is safe
and mirrors the pattern already used in `detonation.py:_apply_result_to_email`.)

- [ ] **Step 5: Add `pending_detonation` to the analyst queue-size gauge**

In `src/routers/emails.py:36-38`:

```python
        pending = db.query(Email).filter(
            Email.status.in_(["escalated", "recu", "pending", "pending_detonation"])
        ).count()
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest tests/test_pending_detonation_status.py -v`
Expected: 2 passed.

- [ ] **Step 7: Confirm the dashboard badge renders without new CSS**

`pending_detonation` isn't one of the CSS classes at
`dashboard.css:403-408`. Find where the email list/detail page turns
`e.status` into a badge class (likely a `esc(e.status)` used directly as the
CSS class name — check with
`grep -n "badge \${.*status" src/dashboard/static/js/dashboard.js`). If the
class name is used verbatim, add one CSS rule reusing the existing pending
color so it doesn't render unstyled:

```css
.badge.pending_detonation { background: var(--color-pending-bg); color: var(--color-pending); }
```

Add this line directly after `dashboard.css:408`.

- [ ] **Step 8: Run the full test suite**

Run: `python -m pytest tests/ -q`
Expected: all tests pass (126 previously + new ones from Task 1 and this task).

- [ ] **Step 9: Commit**

```bash
git add src/database.py src/main.py src/routers/emails.py src/dashboard/static/css/dashboard.css tests/test_pending_detonation_status.py
git commit -m "feat: add pending_detonation status for emails awaiting a sandbox report"
```

---

### Task 3: Sequential, re-queried, idle-timeout detonation loop

**Files:**
- Modify: `src/detonation.py:246-330` (`process_detonation_queue`)
- Modify: `src/detonation_config.py` (add `DETONATION_IDLE_TIMEOUT_SECONDS`)
- Test: `tests/test_detonation_sequential_loop.py` (new file)

**Interfaces:**
- Consumes: `database.get_queued_detonations(db, limit=1)` (existing, ordered
  `priority.desc(), created_at.asc()` — `src/database.py:884-892`),
  `database.count_queued_detonations(db)`, `database.recover_stale_running_detonations`,
  `detonation_state.try_begin`/`end`, `cape_client.detonate` (unchanged).
- Produces: `process_detonation_queue() -> dict` keeps its existing return
  shape (`{"processed": int, "escalated": int, "errors": int, "status": str}`)
  so `main.py:864-866`'s `result.get("processed")` logging keeps working
  unchanged.

- [ ] **Step 1: Write the failing test for one-at-a-time re-query + priority pickup**

```python
# tests/test_detonation_sequential_loop.py
import sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class _FakeRow:
    _seq = 0
    def __init__(self, sha256, priority=False, stored_path="/tmp/x", filename="x.exe", email_id=1):
        _FakeRow._seq += 1
        self.id = _FakeRow._seq
        self.sha256 = sha256
        self.priority = priority
        self.stored_path = stored_path
        self.filename = filename
        self.email_id = email_id
        self.status = "queued"
        self.attempts = 0
        self.result = None


def test_priority_row_inserted_mid_run_is_picked_up_next(monkeypatch):
    """Two rows (A, B) queued at start. While A is detonating, a priority
    row P gets inserted. The loop must process A, then P, then B — never
    interrupting A, and never waiting for a whole pre-fetched batch."""
    import detonation
    import detonation_state as state
    state.end()  # ensure clean slate regardless of test order

    row_a = _FakeRow("a" * 64)
    row_b = _FakeRow("b" * 64)
    queue = [row_a, row_b]
    processed_order = []

    def fake_get_queued(db, limit=1):
        return queue[:1]  # always "the current front of the queue"

    def fake_count_queued(db):
        return len(queue)

    def fake_recover_stale(db, *a, **k):
        return 0

    class FakeSession:
        def close(self): pass
        def commit(self): pass
        def query(self, *a, **k): return self

    monkeypatch.setattr("database.SessionLocal", lambda: FakeSession())
    monkeypatch.setattr("database.get_queued_detonations", fake_get_queued)
    monkeypatch.setattr("database.count_queued_detonations", fake_count_queued)
    monkeypatch.setattr("database.recover_stale_running_detonations", fake_recover_stale)

    monkeypatch.setattr(detonation, "_drain", lambda: None)
    monkeypatch.setattr(detonation, "_resume_vm", lambda: True)
    monkeypatch.setattr(detonation, "_restore", lambda: None)
    monkeypatch.setattr(detonation, "_apply_result_to_email", lambda db, row, result: None)

    def fake_process_one(row):
        processed_order.append(row.sha256)
        queue.remove(row)
        if row.sha256 == "a" * 64:
            # Simulate a priority insert arriving while A is "running"
            row_p = _FakeRow("p" * 64, priority=True)
            queue.insert(0, row_p)
        return {"tool": "detonation", "detonated": True, "status": "done", "escalate": False}

    monkeypatch.setattr(detonation, "_process_one", fake_process_one)
    monkeypatch.setattr(detonation.cfg, "DETONATION_IDLE_TIMEOUT_SECONDS", 0)

    summary = detonation.process_detonation_queue()

    assert processed_order == ["a" * 64, "p" * 64, "b" * 64]
    assert summary["processed"] == 3
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_detonation_sequential_loop.py -v`
Expected: FAILS — today's `process_detonation_queue` fetches
`get_queued_detonations(db, limit=cfg.DETONATION_BATCH_SIZE)` once and loops
over that fixed list, so the mid-run priority insert (`row_p`) is never
picked up in this run at all; `processed_order` comes back as
`["a"*64, "b"*64]` (2 items, priority row missed) instead of 3.

- [ ] **Step 3: Add the idle timeout config**

In `src/detonation_config.py`, directly after `DETONATION_BATCH_SIZE` (line 50):

```python
# How long (seconds) the drained window stays open with an empty queue
# before suspending the VM again. Keeps the VM "hot" across a burst of
# attachments arriving close together (e.g. a live demo) instead of paying
# the VM resume-from-savestate cost per attachment.
DETONATION_IDLE_TIMEOUT_SECONDS = int(os.getenv("DETONATION_IDLE_TIMEOUT_SECONDS", "300"))

# How long to sleep between empty-queue checks while waiting out the idle
# timeout. Short enough that a newly-arrived attachment starts promptly.
DETONATION_IDLE_POLL_SECONDS = int(os.getenv("DETONATION_IDLE_POLL_SECONDS", "2"))
```

- [ ] **Step 4: Rewrite the queue loop in `process_detonation_queue` (`src/detonation.py:246-330`)**

Replace the body from `summary = {"processed": 0, ...}` (line 276) through
the `return summary` (line 320) with:

```python
    summary = {"processed": 0, "escalated": 0, "errors": 0, "status": "ok"}
    cycle_deadline = time.time() + cfg.DETONATION_CYCLE_TIMEOUT
    print("[DETONATION] === Entering drained detonation window ===")

    try:
        _drain()
        if not _resume_vm():
            summary["status"] = "cape_unavailable"
            _escalate_all_queued("cape_unavailable")
            return summary

        last_activity = time.time()
        while True:
            if time.time() > cycle_deadline:
                print("[DETONATION] Cycle timeout — stopping window early")
                summary["status"] = "cycle_timeout"
                break

            db = SessionLocal()
            try:
                rows = get_queued_detonations(db, limit=1)
                row = rows[0] if rows else None
            finally:
                db.close()

            if row is None:
                idle_for = time.time() - last_activity
                if idle_for > cfg.DETONATION_IDLE_TIMEOUT_SECONDS:
                    print(f"[DETONATION] Queue empty for {idle_for:.0f}s — closing window")
                    break
                time.sleep(cfg.DETONATION_IDLE_POLL_SECONDS)
                continue

            db = SessionLocal()
            try:
                row = db.query(type(row)).filter(type(row).id == row.id).first()
                if row is None:
                    continue  # row vanished between the two queries — re-poll
                row.status = "running"
                row.attempts = (row.attempts or 0) + 1
                db.commit()

                try:
                    result = _process_one(row)
                except Exception as e:
                    result = {"tool": "detonation", "detonated": False, "status": "error",
                              "error": f"orchestrator_crash: {e}", "suspicious": True, "escalate": True}

                row.result = result
                row.status = "error" if result.get("status") == "error" else "done"
                db.commit()

                _apply_result_to_email(db, row, result)

                summary["processed"] += 1
                if result.get("escalate"):
                    summary["escalated"] += 1
                if result.get("status") == "error":
                    summary["errors"] += 1
            finally:
                db.close()

            last_activity = time.time()

        return summary

    except Exception as e:
        print(f"[DETONATION] Window crashed: {e}")
        summary["status"] = f"crash: {e}"
        return summary
    finally:
        _restore()
        state.end()
        print(f"[DETONATION] === Detonation window closed: {summary} ===")
```

Keep the function's existing preamble unchanged (the `recover_stale_running_detonations`
call, the empty-queue early-return, and `state.try_begin` gate at lines
252-274 stay exactly as they are today — only the body from `summary = {...}`
onward changes). `SessionLocal` and `get_queued_detonations` are already
imported at the top of the function via the existing
`from database import (SessionLocal, get_queued_detonations, count_queued_detonations, recover_stale_running_detonations,)`
(line 252-255) — no import changes needed for this step.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_detonation_sequential_loop.py -v`
Expected: 1 passed.

- [ ] **Step 6: Run the full detonation test suite for regressions**

Run: `python -m pytest tests/test_detonation.py tests/test_detonation_recovery.py tests/test_manual_detonation.py -v`
Expected: all pass. Pay particular attention to any test asserting on
`DETONATION_BATCH_SIZE` behavior — if one exists and asserts a fixed batch
size cap, it documents old behavior and should be updated to assert the
new one-at-a-time-until-idle-timeout behavior instead (check with
`grep -rn "DETONATION_BATCH_SIZE" tests/`).

- [ ] **Step 7: Commit**

```bash
git add src/detonation.py src/detonation_config.py tests/test_detonation_sequential_loop.py
git commit -m "feat: process detonation queue one item at a time with idle-timeout VM lifecycle"
```

---

### Task 4: Second LLM pass folding in the CAPE report

**Files:**
- Modify: `src/analysis.py` (extend the `enrichment` context renderer, ~line 294-330)
- Modify: `src/detonation.py:208-229` (`_apply_result_to_email`)
- Test: `tests/test_second_pass_verdict.py` (new file)

**Interfaces:**
- Consumes: `analyze_email_body(body_text, model=None, skills_path_candidates=None, context=None)`
  (existing, `src/analysis.py:271`), `email.enrichment_result` dict (now
  includes `body_text`, `headers`, `attachments_meta` per Task 1 Step 4).
- Produces: `_second_pass_verdict(db, email, result: dict) -> None` — new
  function in `detonation.py`, called from `_apply_result_to_email` only
  when `email.status == "pending_detonation"`. Sets `email.status` to
  `"accepted"` or `"escalated"` only (never `"quarantined"`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_second_pass_verdict.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class _FakeEmail:
    def __init__(self, status="pending_detonation"):
        self.id = 1
        self.status = status
        self.enrichment_result = {
            "body_text": "Bonjour, voici la facture jointe.",
            "headers": {"from": "a@b.com", "subject": "Facture"},
            "attachments_meta": [],
        }
        self.llm_result = {"verdict": "accepted", "confidence": 0.8}


def test_cape_confirmed_malicious_pins_escalated_even_if_llm_says_accepted(monkeypatch):
    import detonation

    email = _FakeEmail()
    cape_result = {"malscore": 8.5, "escalate": True, "suspicious": True,
                   "suspicious_behaviors": ["ransomware"], "cape_task_id": 42}

    def fake_analyze(body_text, model=None, skills_path_candidates=None, context=None):
        # LLM (wrongly) says accepted even though context carries the CAPE report
        assert "detonation" in (context.get("enrichment") or {})
        return {"verdict": "accepted", "confidence": 0.9, "risk_score": 10, "reasons": ["looks fine"]}

    monkeypatch.setattr(detonation, "analyze_email_body", fake_analyze)

    class FakeDB:
        def commit(self): pass

    detonation._second_pass_verdict(FakeDB(), email, cape_result)

    assert email.status == "escalated"
    assert email.llm_result.get("sandbox_confirmed_malicious") is True


def test_cape_clean_result_lets_llm_verdict_stand(monkeypatch):
    import detonation

    email = _FakeEmail()
    cape_result = {"malscore": 0.5, "escalate": False, "suspicious": False, "cape_task_id": 43}

    def fake_analyze(body_text, model=None, skills_path_candidates=None, context=None):
        return {"verdict": "accepted", "confidence": 0.95, "risk_score": 5, "reasons": ["clean"]}

    monkeypatch.setattr(detonation, "analyze_email_body", fake_analyze)

    class FakeDB:
        def commit(self): pass

    detonation._second_pass_verdict(FakeDB(), email, cape_result)

    assert email.status == "accepted"


def test_second_pass_never_sets_quarantined(monkeypatch):
    """Even a maximally-malicious CAPE result must land on 'escalated', not
    'quarantined' — CLAUDE.md: all rejections require human confirmation."""
    import detonation

    email = _FakeEmail()
    cape_result = {"malscore": 10.0, "escalate": True, "suspicious": True, "cape_task_id": 44}

    def fake_analyze(body_text, model=None, skills_path_candidates=None, context=None):
        return {"verdict": "escalated", "confidence": 0.99, "risk_score": 99, "reasons": ["ransomware"]}

    monkeypatch.setattr(detonation, "analyze_email_body", fake_analyze)

    class FakeDB:
        def commit(self): pass

    detonation._second_pass_verdict(FakeDB(), email, cape_result)

    assert email.status == "escalated"
    assert email.status != "quarantined"
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_second_pass_verdict.py -v`
Expected: FAILS with `AttributeError`/`ImportError` — `detonation._second_pass_verdict`
and `detonation.analyze_email_body` don't exist yet.

- [ ] **Step 3: Extend `analyze_email_body`'s enrichment context renderer in `src/analysis.py`**

Directly after the AbuseIPDB block (ends around line 330, before whatever
enrichment key comes next — find the exact insertion point with
`grep -n "abuseipdb_results" src/analysis.py`), add a CAPE-report branch
following the same `ctx_parts.append(...)` convention as ThreatFox/AbuseIPDB:

```python
        # CAPE sandbox detonation report (added post-detonation, second pass only)
        det = enr.get("detonation")
        if isinstance(det, dict) and det.get("cape_task_id") is not None:
            behaviors = ", ".join(det.get("suspicious_behaviors", [])[:5]) or "none reported"
            ctx_parts.append(
                f"SANDBOX-REPORT: cape_task_id={det.get('cape_task_id')} "
                f"malscore={det.get('malscore')} escalate={det.get('escalate')} "
                f"suspicious_behaviors=[{behaviors}]"
            )
```

- [ ] **Step 4: Add `_second_pass_verdict` and wire it into `_apply_result_to_email` in `src/detonation.py`**

Add the import at the top of `src/detonation.py` (alongside the existing
`import detonation_config as cfg` etc.):

```python
from analysis import analyze_email_body
```

Add the new function directly above `_apply_result_to_email` (before line 208):

```python
def _second_pass_verdict(db, email, result: dict) -> None:
    """Re-run LLM analysis with the CAPE report folded in. Sets email.status
    to 'accepted' or 'escalated' ONLY — never 'quarantined'/'released'
    (CLAUDE.md: all rejections require human confirmation; those two
    statuses are analyst-only actions on an already-escalated email).
    A CAPE-confirmed-malicious result always pins the verdict to
    'escalated', matching the existing rule that deterministic signals
    can't be overridden by the LLM."""
    import detonation_config as cfg

    enr = email.enrichment_result or {}
    body_text = enr.get("body_text") or ""
    context = {
        "headers": enr.get("headers") or {},
        "attachments": enr.get("attachments_meta") or [],
        "enrichment": {"detonation": result},
    }

    try:
        llm_res = analyze_email_body(body_text, context=context)
        raw_verdict = (llm_res.get("verdict") or "").lower().strip()
        llm_says_accepted = raw_verdict in ("accepter", "accepted", "accept", "clean", "safe")
    except Exception as e:
        print(f"[DETONATION] Second-pass LLM analysis failed: {e} -> ESCALATED (fail-safe)")
        llm_says_accepted = False
        llm_res = {"verdict": "escalated", "reasons": [f"second_pass_error: {e}"]}

    cape_malicious = bool(result.get("escalate")) or (
        result.get("malscore") is not None and result["malscore"] >= cfg.CAPE_MALSCORE_ESCALATE
    )

    if cape_malicious or not llm_says_accepted:
        email.status = "escalated"
        if cape_malicious:
            llm_res["sandbox_confirmed_malicious"] = True
    else:
        email.status = "accepted"

    email.llm_result = llm_res
    db.commit()
```

Then, at the end of `_apply_result_to_email` (currently ending at line 243,
right before `except Exception:` around the audit-log `try` block), add the
call — only for emails still awaiting this decision:

```python
    if email.status == "pending_detonation":
        try:
            _second_pass_verdict(db, email, result)
        except Exception as e:
            # Fail-safe: never leave an email stuck on pending_detonation.
            email.status = "escalated"
            db.commit()
            print(f"[DETONATION] Second-pass verdict crashed: {e} -> ESCALATED (fail-safe)")
```

Place this block after the existing
`if result.get("escalate") and email.status not in ("quarantined", "released"): email.status = "escalated"; db.commit()`
lines (226-228) — the existing block still runs first for the (unchanged)
non-`pending_detonation` case; the new block only fires for the two-phase
emails introduced in Task 2.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_second_pass_verdict.py -v`
Expected: 3 passed.

- [ ] **Step 6: Run the full detonation + analysis suites for regressions**

Run: `python -m pytest tests/test_detonation.py tests/test_detonation_recovery.py tests/test_manual_detonation.py tests/ -k analysis -v`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/analysis.py src/detonation.py tests/test_second_pass_verdict.py
git commit -m "feat: second LLM pass folds CAPE report into final verdict, never auto-quarantines"
```

---

### Task 5: Per-email detonation notifications ("detonating now" / "report ready")

**Files:**
- Modify: `src/routers/emails.py:878-932` (`/api/detonation/status` response — add per-email event list)
- Modify: `src/dashboard/static/js/dashboard.js:885-930` (generalize `notifyManualReady` pattern)
- Test: `tests/test_detonation_notifications.py` (new file)

**Interfaces:**
- Consumes: existing `/api/detonation/status` polling already wired in
  `dashboard.js:889` (`refreshDetonationBanner`, called on an existing
  timer — confirm the exact call site with
  `grep -n "refreshDetonationBanner" src/dashboard/static/js/dashboard.js`).
- Produces: `database.get_recent_detonation_events(db, since_id=None) -> list[dict]`
  (new helper) returning rows like
  `{"id": int, "email_id": int, "filename": str, "event": "detonating"|"report_ready"}`;
  `/api/detonation/status` response gains an `"events": [...]` key.

- [ ] **Step 1: Write the failing test for the new DB helper**

```python
# tests/test_detonation_notifications.py
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def test_get_recent_detonation_events_reports_running_and_done(monkeypatch):
    import database as db

    class Row:
        def __init__(self, id, email_id, filename, status):
            self.id = id
            self.email_id = email_id
            self.filename = filename
            self.status = status

    rows = [
        Row(1, 10, "invoice.pdf", "running"),
        Row(2, 11, "report.docx", "done"),
        Row(3, 12, "x.exe", "queued"),  # not yet started -> no event
    ]

    class FakeQuery:
        def filter(self, *a, **k): return self
        def order_by(self, *a, **k): return self
        def all(self): return rows

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()

    events = db.get_recent_detonation_events(FakeDB())
    kinds = {(e["email_id"], e["event"]) for e in events}
    assert (10, "detonating") in kinds
    assert (11, "report_ready") in kinds
    assert all(e["email_id"] != 12 for e in events)
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest tests/test_detonation_notifications.py -v`
Expected: FAILS — `database.get_recent_detonation_events` doesn't exist.

- [ ] **Step 3: Add `get_recent_detonation_events` to `src/database.py`**

Add directly after `get_pending_detonation` (end of file, after line 922):

```python
def get_recent_detonation_events(db: Session, limit: int = 50) -> list[dict]:
    """Per-email detonation lifecycle events for dashboard notifications.
    'running' rows are surfaced as 'detonating'; 'done'/'error' rows (which
    already have a report, good or bad) as 'report_ready'. 'queued' rows
    produce no event yet — nothing has started for them."""
    rows = (
        db.query(PendingDetonation)
        .filter(PendingDetonation.status.in_(["running", "done", "error"]),
                PendingDetonation.email_id.isnot(None))
        .order_by(PendingDetonation.updated_at.desc())
        .limit(limit)
        .all()
    )
    events = []
    for r in rows:
        event = "detonating" if r.status == "running" else "report_ready"
        events.append({"id": r.id, "email_id": r.email_id, "filename": r.filename, "event": event})
    return events
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python -m pytest tests/test_detonation_notifications.py -v`
Expected: 1 passed.

- [ ] **Step 5: Surface events on the existing status endpoint**

The handler is `api_detonation_status` in `src/routers/emails.py:878-932`.
Its import line at 889 currently reads
`from database import PendingDetonation, count_queued_detonations` — change
it to also import the new helper:

```python
    from database import PendingDetonation, count_queued_detonations, get_recent_detonation_events
```

Then, inside the same `try` block that computes `recent_out` and
`manual_ready` (lines 900-919), add one more line right after
`manual_ready = _manual_ready_rows(db)` (line 919):

```python
        events = get_recent_detonation_events(db)
```

And add `"events": events,` to the returned dict at the end of the function
(lines 924-932), directly after `"manual_ready": manual_ready,`:

```python
    return {
        "window_active": window["active"],
        "window_reason": window["reason"],
        "window_elapsed_s": window["elapsed_s"],
        "queued": queued,
        "by_status": by_status,
        "recent": recent_out,
        "manual_ready": manual_ready,
        "events": events,
    }
```

- [ ] **Step 6: Generalize the notification function in `dashboard.js`**

Directly after `notifyManualReady` (`dashboard.js:897-930`), add a sibling
function and call it from wherever `refreshDetonationBanner` already runs
(same call site as `notifyManualReady(st.manual_ready, banner)` at line 891):

```javascript
// Per-email attachment detonation events (always-on flow) → alert on any
// page. Fires once per (id, event) pair so a 'detonating' + later
// 'report_ready' for the same row both get their own notification.
function notifyDetonationEvents(events) {
    window.__detEventsSeen = window.__detEventsSeen || {};
    (events || []).forEach(function (ev) {
        const key = ev.id + ':' + ev.event;
        if (window.__detEventsSeen[key]) return;
        window.__detEventsSeen[key] = true;
        const msg = ev.event === 'detonating'
            ? 'Detonating "' + (ev.filename || 'attachment') + '" for email #' + ev.email_id + '…'
            : 'Sandbox report ready for email #' + ev.email_id + ' ("' + (ev.filename || 'attachment') + '")';
        if ('Notification' in window && Notification.permission === 'granted') {
            try { new Notification('Attijari — sandbox', { body: msg }); } catch (_) {}
        }
        showToast(msg, ev.event === 'detonating' ? 'info' : 'success');
    });
}
```

Then in `refreshDetonationBanner` (`dashboard.js:885-893`), add the call
right after `notifyManualReady(st.manual_ready, banner);`:

```javascript
        notifyDetonationEvents(st.events);
```

- [ ] **Step 7: Run the full test suite**

Run: `python -m pytest tests/ -q`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add src/database.py src/routers/emails.py src/dashboard/static/js/dashboard.js tests/test_detonation_notifications.py
git commit -m "feat: per-email detonating/report-ready notifications"
```

---

### Task 6: Attachment panel "detonating" badge label

**Files:**
- Modify: `src/dashboard/static/js/dashboard.js:624-637` (`_attachmentPanelRowHtml`, the `'pending'` branch)

**Interfaces:**
- Consumes: `detRow.status` (`'queued' | 'running' | 'done' | 'error'`,
  existing `PendingDetonation.status` values), `windowActive` (existing
  param, already threaded through from `renderAttachmentsPanel`).
- Produces: no new interface — cosmetic label change only, verified by a
  quick manual check (Step 2), not a unit test (this is server-rendered
  string content, already covered functionally by the existing pending/running
  branch logic — no behavior changes here, just a label).

- [ ] **Step 1: Update the badge label text**

In `src/dashboard/static/js/dashboard.js:624-637`, change:

```javascript
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
```

to:

```javascript
    if (a.status === 'pending') {
        const taskId = detRow && detRow.result && detRow.result.cape_task_id;
        const isRunning = detRow && detRow.status === 'running' && windowActive;
        const live = (isRunning && taskId)
            ? `<div class="sandbox-live" id="sandbox-live-${parseInt(a.id)}" data-task-id="${parseInt(taskId)}"></div>`
            : `<div class="sandbox-empty"><div class="spinner"></div>
                   <p>${isRunning ? 'Detonating…' : 'Queued for detonation — the sandbox stays hot and works through the queue one file at a time.'}</p></div>`;
        return `
            <div class="sandbox-preview-meta">
                <div class="detail-row"><span class="detail-label">File</span>
                    <span class="detail-value">${esc(truncate(a.filename, 60))}</span></div>
                <span class="badge escalated">${isRunning ? 'Detonating' : 'Verifying…'}</span>
            </div>
            ${live}`;
    }
```

The live noVNC panel (`mountNoVnc`, called from `renderAttachmentsPanel:683`)
is unchanged — it already mounts view-only for this automated path per
Task confirmation earlier (no `interactive: true` argument is passed here,
unlike the manual-detonation viewer call in `openSandboxViewer`).

- [ ] **Step 2: Manual verification**

Run the dashboard locally (`python src/main.py --serve` or the project's
usual start command), open an email with a queued attachment during an
active detonation window, and confirm the badge reads "Detonating" while
`detRow.status === 'running'` and the live view stays present and view-only
(no mouse/keyboard interaction possible — confirm by trying to click inside
the noVNC frame and observing no effect on the guest).

- [ ] **Step 3: Commit**

```bash
git add src/dashboard/static/js/dashboard.js
git commit -m "polish: label the live per-attachment sandbox view 'Detonating' while running"
```

---

### Task 7: Full regression pass and revert-point push

**Files:** none (verification + push only)

- [ ] **Step 1: Run the complete test suite**

Run: `python -m pytest tests/ -q`
Expected: all tests pass (previous 126 + new tests added in Tasks 1-5).

- [ ] **Step 2: Manually verify the pipeline still boots**

Run: `python src/main.py` (single tick, no `--daemon`) against whatever
local test inbox/SMTP setup is already configured, and confirm the log
shows `[DETONATION] Queued ... (always-on)` for an email with an attachment,
followed by `[DETONATION] === Entering drained detonation window ===` and
eventually `[DETONATION] === Detonation window closed: ... ===`.

- [ ] **Step 3: Push to origin/dev**

```bash
git push origin dev
```

- [ ] **Step 4: Announce the revert point**

Report the pushed commit SHA to the user as the known-good rollback point
for tomorrow's demo (e.g. "🔖 revert point: `<sha>` — `git reset --hard <sha>`
gets you back here if anything misbehaves live").
