# Manual Detonation Page — Design Spec

**Date:** 2026-07-14
**Status:** Draft (awaiting user review)
**Author:** Mohamed + Claude
**Related:** `2026-07-13-manual-vm-control-design.md`, `2026-07-13-cape-dashboard-integration.md`

## 1. Purpose

A dedicated dashboard page (peer of "User Management" in the nav) that lets an
operator detonate an **arbitrary, non-email file** in the CAPE sandbox on demand
and watch it run live. Today detonation is only reachable through the email
pipeline (inconclusive attachments). This page decouples detonation from email
so an analyst can throw any file they have on hand at the sandbox.

The result of each manual detonation is recorded in a **history table** on the
page (filename, SHA-256, malscore, verdict, status, operator, time), each row
linking to the full CAPE report and the live-view replay.

## 2. Non-goals (explicitly out of scope — YAGNI)

- **No Redis / caching layer.** Manual detonation is the lowest-traffic surface
  in the app; the app's real latency lives in email analysis (LLM inference +
  sequential enrichment), not here. Cross-cutting scale work is a separate,
  measured effort. This page ships only free caching-friendly choices
  (`Cache-Control`/`ETag`, no N+1).
- **No operator-chosen open method.** CAPE auto-selects the package from the
  magic-byte file type. No package/args/timeout controls.
- **No blocklist feed.** A confirmed-malicious manual detonation does not (yet)
  offer a one-click "add hash to known-bad". Can be added later.
- **No idle "blank VM" inspection session.**

## 3. Architecture — reuse map

The feature is ~90% reuse of existing machinery. New surface is deliberately thin.

| Concern | Reused component | New work |
|---|---|---|
| File storage | same stored-file convention as attachments (internal id, hostile filename kept as data only) | manual-upload storage dir |
| Queue | `PendingDetonation` table + `enqueue_detonation(..., email_id=None)` | `priority` + `created_by` columns |
| Detonation window | `process_detonation_queue()` + `detonation_state.try_begin()` | none |
| Immediate trigger | `POST /api/detonation/run-window` drain flow | reused by Branch A |
| Live view | `/ws/vnc/{task_id}` relay + noVNC viewer | none |
| Report | same-origin CAPE report proxy | none |
| Status / banner | `/api/detonation/status` poller (drives suspension banner on every page) | add "manual ready" state |

`_apply_result_to_email` already no-ops when `email_id` is null, so a manual
detonation folds nowhere into an email — correct by construction.

## 4. The two-outcome warning

When the operator attaches a valid file and submits, a modal presents **two
mutually exclusive branches**. This replaces the single informed-consent modal
from the manual-VM-control feature.

### Branch A — "Open now (stop email analysis)"
Immediate. Equivalent to the existing `run-window` drain flow:
suspend polling/scheduler → unload Ollama → free Guard → stop Docker →
resume CAPE VM → detonate the file → live VNC. Email analysis is suspended for
the duration (the operator has explicitly consented via this modal).

### Branch B — "Priority queue (run after emails are analyzed)"
Non-interruptive. Sequence:

1. File is enqueued with `priority=True` and a deferred marker; email analysis
   **keeps running normally**. No VM is resumed, no Ollama unloaded yet.
2. A lightweight check on the existing poll tick detects when the
   pending-email-analysis backlog reaches zero.
3. On backlog-clear, the manual detonation flips to a **"ready"** state, surfaced
   through `/api/detonation/status`. The operator sees a
   "✅ Emails analyzed — your file is ready to open" prompt on whatever page
   they are on (reusing the global status poller/banner).
4. Operator presses **OK** → **only then** the drain window starts (VM resumes)
   and the file detonates with live VNC.

**Critical nuance (confirmed design intent):** the "OK" press gates the *start*
of the sandbox window. The VM is **not** resumed and left idle waiting for a
click — that would defeat the memory-gating the drain design exists to enforce
on the shared 16 GB host. Backlog-clear → notify → OK → *then* resume + detonate.

Because IMAP delivers continuously, "all emails analyzed" means "the pending
backlog is empty at a poll tick." New mail arriving after that stays on the IMAP
server (consistent with the existing defer-poll-during-detonation pattern) until
the manual window closes.

## 5. Data model changes

`PendingDetonation` gains two nullable columns (email-sourced rows leave them
null / default):

- `created_by TEXT NULL` — operator username for manual uploads; null for
  email-sourced rows.
- `priority BOOLEAN NOT NULL DEFAULT FALSE` — Branch B rows sort ahead of
  email-sourced rows in `get_queued_detonations`.
- (Reused) a deferred/awaiting-backlog marker for Branch B. Implementation
  choice deferred to the plan: either a dedicated status value
  (`deferred`) or a boolean; must not be picked up by an ordinary window until
  promoted to `queued`.

A migration adds the columns; existing rows backfill to null/false.

## 6. New endpoints (`routers/detonation_proxy.py` or a small new router)

All gated by `require_permission("emails.scan")` (same as run-window/retry).

- `POST /api/detonation/manual` — multipart upload.
  - Validates: size ≤ 50 MB; extension in `SUPPORTED_EXTENSIONS` (reject others
    with a clear message — do not queue a file CAPE can't handle).
  - Stores bytes under an internal id (never the attacker filename — CLAUDE.md
    rule 6). Computes SHA-256. Sniffs real type via magic bytes (rule 7).
  - `enqueue_detonation(sha256, stored_path, filename, email_id=None,
    created_by=user, priority=(branch=="B"))`.
  - Branch A → also triggers the run-window drain (daemon thread), same as the
    existing endpoint. If a window is already active → the file stays queued and
    the response says so (no 409 for the operator; honest "queued" — reuses the
    queue).
  - Branch B → enqueue as deferred; do **not** trigger the window.
  - Audit: `detonation_manual_upload`, actor + sha256 + filename + branch.
  - Returns the pending id + resulting state.

- `GET /api/detonation/manual` — list manual detonations
  (`PendingDetonation WHERE email_id IS NULL`), newest first, with filename,
  sha256, malscore/verdict (from `result`), status, `created_by`, timestamps,
  and links to report + live view. Responds with `Cache-Control` + `ETag`
  (cheap-win caching; short TTL, revalidated).

- (Branch B confirm) reuses `POST /api/detonation/run-window`; the ready-state
  promotion (deferred → queued) happens when the operator confirms.

## 7. Frontend

- New template `manual_detonation.html` extending `base.html`, following the
  `admin.html` (User Management) pattern: page header + primary action + table.
- Nav link added next to User Management (visible with `emails.scan`).
- `dashboard.js`: upload handler (multipart), two-outcome modal, history-table
  render/refresh, "ready" prompt driven by the existing status poller, and
  "See in VM" / "View report" row actions (reusing the existing viewer + report
  proxy wiring).
- All handlers via `addEventListener`/delegation (CSP is `'self' 'unsafe-inline'`
  today, but new code should not add inline `onclick=` — see the Jul-13 CSP
  incident in the build log).

## 8. Security & fail-safe

- **Isolation boundary unchanged:** the uploaded file is stored on the dashboard
  host and only ever *submitted* to the isolated CAPE VM; it is never executed on
  the host. The VM is the detonation boundary (non-privileged, no outbound net,
  ephemeral).
- **Hostile filename & declared type** handled per CLAUDE.md rules 6–7 (internal
  id path, magic-byte typing, original name stored as data only).
- **Fail-safe unchanged:** upload → drain window → if CAPE is unreachable, the
  row goes to `error`. There is no email to escalate, but the history row shows
  the failure honestly. Nothing auto-accepts.
- **Capability-expansion note:** this is the one path that lets an operator put
  an arbitrary non-email file into the sandbox on demand, so the
  `detonation_manual_upload` audit entry (actor + sha256 + filename) is the
  traceability record.

## 9. Testing

- Upload happy path (Branch A): file stored under internal id, enqueued
  `email_id=None, priority=False`, window triggered.
- Upload Branch B: enqueued deferred+priority, window NOT triggered; backlog-clear
  promotes to ready; confirm triggers window.
- Rejects: oversized file, unsupported extension, missing file.
- Filename hostility: a file named `../../etc/passwd` or `x.pdf.exe` never
  becomes a real path; stored under internal id.
- Priority ordering: a priority row sorts ahead of email-sourced queued rows.
- Concurrency: upload while a window is active → row queued, honest response, no
  double-drain (existing `try_begin()` barrier already covered).
- List endpoint returns only `email_id IS NULL` rows with correct fields + cache
  headers.

## 10. Open questions for user review

1. **Permission gate:** defaulted to `emails.scan` (same as run-window/retry).
   User Management is admin-only (`users.manage`). Confirm `emails.scan` is right,
   or tighten to admin-only.
2. **Supported files:** gate to `SUPPORTED_EXTENSIONS` (reject others) vs. accept
   anything and let CAPE decide. Defaulted to the gate.
3. **Branch B "ready" surfacing:** banner + modal prompt via the existing status
   poller — acceptable, or do you want a stronger signal (e.g. desktop/sound)?
