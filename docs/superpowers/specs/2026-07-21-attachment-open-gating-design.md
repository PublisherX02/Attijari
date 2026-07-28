# Attachment Safe-Open / Insist-to-VM — Design

**Date:** 2026-07-21
**Context:** Final fixes before demoing the POC to Mohamed's tutor and the SecOps manager. A previously-requested behavior was never actually built: on the email detail page, an attachment that has been verified safe should open directly from the dashboard; anything not verified safe should be blocked with a warning, and only opened (in the CAPE VM, live) if the analyst deliberately insists.

## Goal

For every attachment on an email's detail page:
- **Verified safe** (detonated in CAPE, malscore below the suspicious threshold) → opens/previews directly from the dashboard, as attachments already do today for detonation-queue rows.
- **Not verified safe** (never detonated, still queued/running, detonated-and-flagged, or a failed detonation) → the dashboard says so and blocks the direct open. The analyst can explicitly insist, which submits the file to the CAPE VM on demand and opens a live interactive session — reusing the existing manual-detonation "Branch A" instant-window mechanism, not the batch queue.

This closes the gap that today only attachments already flagged as detonation candidates (inconclusive static analysis + unsure LLM) have any viewer at all. Attachments static analysis cleared outright currently leave no queryable per-attachment record after the pipeline run — this spec adds that record for every attachment, without touching the existing detonation queue's state machine.

## Non-goals

- No Redis or other caching layer. The bottleneck this feature touches is a 3–10 minute CAPE detonation cycle (`CAPE_ANALYSIS_TIMEOUT=180s`, `CAPE_TOTAL_TIMEOUT=600s`), not the sub-5ms indexed Postgres lookup that determines safety status. Caching the lookup would not measurably change end-to-end latency. Reducing the detonation cycle itself (e.g. keeping the CAPE VM warm between runs instead of full resume/suspend) is a separate, future piece of work — not in scope here.
- No changes to `PendingDetonation`'s existing queue/dedup/drain-window state machine. It is read from, never restructured.
- No backfill for emails processed before this change ships — they keep today's behavior (bare `attachment_count`, or detonation-panel-only if a given attachment happened to already be a queued candidate). Only attachments from pipeline runs after this deploy get the new per-attachment record.
- No new UI surface outside the existing per-email detail page. "Open attachment" only ever appears in the context of that email's own detail view (sender, subject, verdict, headers) — never a general/global attachment browser or a page disconnected from the specific email.
- No change to which file types CAPE can detonate, or to the manual-detonation (arbitrary upload) page — untouched.

## Architecture

```text
Pipeline run (main.py, after _save_email)
    │
    ├─ NEW: for every attachment in parsed["attachments"] (not just
    │   detonation candidates), persist one Attachment row: email_id,
    │   sha256, stored_path, filename, real_type, size_bytes.
    │
    ├─ _maybe_enqueue_detonation (existing, unchanged) — still only
    │   queues a PendingDetonation row for inconclusive/unsure attachments.
    │
    ▼
Detail page load (GET /api/emails/{id}/attachments, NEW)
    │
    ├─ For each Attachment row, compute safety status by looking up the
    │   MOST RECENT PendingDetonation row for that sha256 (global, not
    │   scoped to this email — same file content carries the same verdict
    │   wherever it appears):
    │     no row              -> "unverified"
    │     status queued/running -> "pending"
    │     status done, malscore < CAPE_MALSCORE_SUSPICIOUS -> "safe"
    │     status done (malscore >= threshold or missing), or "error"
    │                          -> "unsafe"   (fail-safe default, rule 1)
    │
    ▼
Dashboard renders one panel per attachment:
    "safe"                -> inline preview / download (today's behavior)
    "pending"              -> existing live/queued spinner (unchanged)
    "unverified"/"unsafe"  -> warning + "Insist — open in VM" button
                              (hidden unless the analyst has emails.scan)
    │
    ▼
POST /api/emails/{id}/attachments/{attachment_id}/insist (NEW)
    │
    ├─ enqueue_detonation(sha256, stored_path, filename, email_id,
    │     reason="analyst_insist", priority=True, created_by=username)
    │   — reuses existing dedup (won't double-queue if already
    │   queued/running); a prior "done"/"error" row does NOT block a
    │   fresh submission, so insist always gets a live session.
    ├─ add_audit_entry(action="attachment_insist_open", ...) — analyst
    │   deliberately opening an unverified/unsafe file is a security-
    │   relevant decision and must be auditable.
    ├─ if no drain window is active, start one immediately
    │   (manual_detonation._start_window(), same mechanism Branch A
    │   manual uploads already use) — on-demand, not the batch queue.
    │
    ▼
Frontend switches that attachment's row into the existing live-VNC /
queued view (_detonationRowHtml, unchanged) once the row exists.
```

## Data model

New table, `database.py`:

```python
class Attachment(Base):
    __tablename__ = "attachments"
    id = Column(Integer, primary_key=True, autoincrement=True)
    email_id = Column(Integer, ForeignKey("emails.id"), nullable=False, index=True)
    sha256 = Column(String(64), nullable=False, index=True)
    stored_path = Column(Text, nullable=False)
    filename = Column(String(512), nullable=True)      # data only, never a real path (rule 6)
    real_type = Column(String(255), nullable=True)      # magic-verified at extraction time
    size_bytes = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
```

No `status` column on `Attachment` — safety is always derived live from `PendingDetonation`, never cached, so there is nothing to keep in sync or invalidate. Table is created automatically by `Base.metadata.create_all()` on next boot (same pattern as `RevokedToken`); no data migration needed since there is no prior data for a brand-new table.

Written in `main.py`, once per attachment, right after `_save_email()` succeeds — same iteration source (`parsed["attachments"]`) that `_maybe_enqueue_detonation` already reads, so this is an additive loop next to the existing one, not a restructuring of it.

## Endpoints (`src/routers/detonation_proxy.py`)

- **No separate list endpoint.** `GET /api/emails/{email_id}` (existing) gains an `"attachments"` key — one entry per `Attachment` row with computed `status`. This follows the same convention the existing `"detonation_queue"` key on that same response already uses, rather than a second round-trip; the frontend already fetches this endpoint on every detail-page load. Permission: unchanged (`emails.view`, already required for the endpoint).
- `GET /api/emails/{email_id}/attachments/{attachment_id}/raw` — rewritten to key on the new `Attachment.id` (currently keys on `PendingDetonation.id`, which only exists for detonation candidates). Computes status first: `"safe"` serves the bytes exactly as today (magic-byte sniffed content type, inline only for verified PDF/image, internal id in `Content-Disposition`, never the attacker filename); anything else returns `403` with `{"status": "<status>"}` and no bytes. Permission: `emails.view`.
- `POST /api/emails/{email_id}/attachments/{attachment_id}/insist` — the on-demand flow described above. Permission: `emails.scan` (same gate as the existing "See in VM" button, since it consumes VM/CAPE resources).

Both `{attachment_id}`-taking endpoints look the row up filtered by **both** `Attachment.id == attachment_id` AND `Attachment.email_id == email_id` (same pattern the existing `/raw` implementation already uses for `PendingDetonation`) — an attachment id valid on one email must 404, not 403, when requested under a different `email_id` in the path. Prevents an analyst from probing attachment ids across emails they may not have reason to be looking at.

Safety-status computation lives as a small, pure, unit-testable function, `attachment_safety_status(db, sha256: str) -> str` in a new `src/attachments.py` module — no FastAPI/HTTP state baked into the logic itself, so it can be tested against a list of fake `PendingDetonation`-shaped rows.

## Frontend (`dashboard.js`, `detail.html`)

The existing detonation-only section of the email detail page is replaced by one "Attachments" panel, driven by the `attachments` key embedded in the existing `GET /api/emails/{id}` response, rendering one row per attachment:

- `safe` → inline preview/download (today's `_attachmentPreviewHtml` behavior, reimplemented against the new per-attachment status).
- `pending` → today's spinner / live-VNC view (same pattern as today's `_detonationRowHtml`, reimplemented against the new data shape).
- `unverified` / `unsafe` → a warning line plus an "⚠ Not verified safe — insist and open in VM" button, hidden for analysts without `emails.scan`. Clicking it calls the insist endpoint, then the row switches into the same live/queued view `pending` uses.

This panel only ever renders inside the existing per-email detail view — it is not a new page, route, or modal.

## Error handling

Follows CLAUDE.md rule 1 (fail-safe, never fail-open) throughout:
- Missing/unparseable malscore on a `done` row → `unsafe`, not `safe`.
- A failed (`error`) detonation → `unsafe`, not treated as "never tried."
- `enqueue_detonation` failure during insist → the endpoint returns an error to the analyst; it does not silently pretend the file is being handled.
- The `/raw` endpoint's existing checks (stored file missing, path outside the expected root) are unchanged.

## Testing

New tests, alongside the existing `tests/test_detonation.py` / `tests/test_manual_detonation.py`:
- `_attachment_safety_status`: all four states, including malscore-missing and malscore-at-threshold edge cases.
- `GET /attachments`: lists rows correctly, statuses computed correctly for mixed states.
- `GET /attachments/{id}/raw`: 200 + correct bytes for `safe`, 403 for the other three states, 404 for a nonexistent attachment.
- `POST /attachments/{id}/insist`: creates/reuses a `PendingDetonation` row, starts a window when none is active, writes the audit entry, rejects a user without `emails.scan`.
- Regression: existing `PendingDetonation` queue/dedup/stale-recovery tests still pass unmodified — confirms the new table didn't touch that state machine.
