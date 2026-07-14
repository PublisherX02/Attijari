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
   through `/api/detonation/status`. The operator is alerted through **three
   channels at once** (the operator may have tabbed away from the dashboard):
   - a **desktop notification** via the Web Notifications API
     (`Notification.requestPermission()` obtained up front on the manual page;
     works on `localhost` without HTTPS),
   - a short **sound cue** (a bundled audio asset played on the ready transition),
   - an in-page **"✅ Emails analyzed — your file is ready to open"** prompt on
     whatever page they are on (reusing the global status poller/banner).
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

`PendingDetonation` gains the following (email-sourced rows leave them
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

All gated by a **new, grantable permission `detonation.manual`** (see §11) — not
admin-only, and distinct from `emails.scan` so an admin can hand this specific
capability to whichever operators they trust.

- `POST /api/detonation/manual` — multipart upload.
  - Validates: size ≤ 50 MB; extension in `CAPE_DETONABLE_EXTENSIONS` (the
    CAPE-supported set, see §12). Reject anything outside it with a clear
    "CAPEv2 cannot detonate this file type" message — CAPE aborts unsupported
    types anyway, so rejecting up front avoids burning a whole drain window on a
    guaranteed abort. **Backstop:** CAPE auto-detects by *content*; a file that
    passes the extension gate but whose real type CAPE can't handle will abort →
    the row goes to `error` and the history row shows it honestly.
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
- Nav link added next to User Management (visible only with `detonation.manual`).
- `dashboard.js`: upload handler (multipart), two-outcome modal, history-table
  render/refresh, "ready" prompt driven by the existing status poller, and
  "See in VM" / "View report" row actions (reusing the existing viewer + report
  proxy wiring).
- **Branch B alerting:** on the manual page, request Web Notification permission
  up front. When the status poller reports a manual detonation in the `ready`
  state, fire a desktop `Notification` + play a bundled sound asset (e.g.
  `static/sounds/ready.mp3`, self-hosted so CSP `media-src 'self'` covers it) in
  addition to the in-page banner/modal. Degrade gracefully if the user denied
  notification permission (banner + sound still fire).
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
- Rejects: oversized file, extension outside `CAPE_DETONABLE_EXTENSIONS`
  (e.g. `.txt`, `.png`), missing file.
- Filename hostility: a file named `../../etc/passwd` or `x.pdf.exe` never
  becomes a real path; stored under internal id. (`x.pdf.exe` → real ext `.exe`,
  supported; the point tested is path safety, not rejection.)
- Priority ordering: a priority row sorts ahead of email-sourced queued rows.
- Concurrency: upload while a window is active → row queued, honest response, no
  double-drain (existing `try_begin()` barrier already covered).
- List endpoint returns only `email_id IS NULL` rows with correct fields + cache
  headers.
- Permission: a user without `detonation.manual` gets 403 on both endpoints and
  never sees the nav link.

## 10. Resolved decisions (were open questions)

1. **Permission gate:** a **new grantable permission `detonation.manual`**, NOT
   admin-only. Admins assign it per-user via User Management (§11).
2. **Supported files:** gate to `CAPE_DETONABLE_EXTENSIONS` — the actual
   CAPEv2-supported set (§12), rejecting anything CAPE would abort on.
3. **Branch B "ready" surfacing:** desktop notification **+ sound + in-page
   banner/modal**, all three (§4, §7).

## 11. Permission: `detonation.manual`

- Added to the permission catalog `ALL_PERMISSIONS` in `database.py` (with a
  human label, so it appears as a toggle in the User Management permission editor).
- Role defaults: `admin` → true (admins hold all permissions anyway);
  `analyst` and `viewer` → **false by default**. An admin explicitly grants it to
  the analysts they trust — matching "admin decides to whom."
- All three server surfaces (`POST`/`GET /api/detonation/manual`, and the page
  route) require it. The nav link is rendered only when the session holds it.
- Existing users: a migration/backfill adds the key (default false) to every
  stored `permissions` JSON so the editor shows it for already-created accounts.

## 12. `CAPE_DETONABLE_EXTENSIONS` — the accepted set

Derived from CAPEv2's analysis-package extension map (authoritative source:
CAPE docs, `usage/packages.html`, and `analyzer/windows/modules/packages/`).
Defined once in `detonation_config.py`, config-overridable so it can be trimmed
to match the specific CAPE install's enabled packages.

```text
.mdb .accdb   .class   .iso .vhd   .chm   .url   .cpl   .dll
.doc .docm .docx   .eml   .exe   .hta   .hwp   .jar   .js .jse
.lnk   .mht   .build   .msg   .msi   .nsis   .one   .pdf
.ppt .pptm .pptx   .ps1   .pub .pubx   .py   .rar   .reg
.scr .sct   .swf   .vbs .vbe   .wsf   .xls .xlsm .xlsx   .xslt
.xps   .zip
```

Notes:
- This is **broader** than the email pipeline's `SUPPORTED_EXTENSIONS` (which is a
  curated "worth auto-detonating" subset). The two are intentionally distinct:
  the manual page is operator-driven, so it accepts everything CAPE *can* run;
  the email pipeline only queues the high-signal subset automatically.
- `.exe`/`.dll`/`.scr` etc. are accepted — this is a sandbox; running live
  malware in the isolated VM is the entire point.
- If a CAPE install disables a package (e.g. no Office in the guest), trim the
  set via config so operators get an honest up-front rejection instead of a
  CAPE-side abort.

## 13. CSP note

The sound cue needs `media-src 'self'` in the CSP (self-hosted asset only). The
Web Notifications API is a browser capability, not a network fetch, so it needs
no CSP change. Follow the build-log CSP discipline: no inline handlers.
