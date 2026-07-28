# Always-on sequential detonation — design

## Why

SecOps liked the sandbox demo and wants to see it front-and-center for a live
test tomorrow. Today, detonation is rare by design (only fires when static
analysis is inconclusive AND the LLM is unsure) and runs as a single silent
batch job. This spec makes detonation the default path for every attachment,
processed one at a time with live progress, so the sandbox is visibly doing
work throughout the demo instead of running invisibly in the background.

## Non-goals

- No change to the underlying CAPE submission/report-parsing logic
  (`cape_client.py`), the VM resume/suspend commands, or the watchdog
  fail-safe pattern in `detonation.py`.
- No change to `CLAUDE.md`'s rule that all rejections require human
  confirmation. `quarantined` remains an analyst-only status.
- Not touching outbound SMTP/reporting.

## Trigger — broaden the gate

`main.py::_maybe_enqueue_detonation` currently enqueues only when static
analysis was inconclusive and the LLM was unsure. Change the condition to:
enqueue every attachment whose extension is in
`detonation_config.SUPPORTED_EXTENSIONS`, **unless the rules engine already
issued a confident reject** for that email. Rules-engine rejects skip
detonation entirely and go straight to today's human-review path — there is
no informational value in detonating something already confidently blocked.

Emails with no attachment are entirely unaffected.

## Two-phase verdict per email

An email with at least one queued attachment gets its first LLM pass as
today, but instead of a final status it's set to a new `pending_detonation`
value on `Email.status`. The dashboard's status list/badge logic needs this
new value added alongside `pending, recu, accepted, escalated, quarantined,
released`. Emails with no attachment finalize immediately, unchanged.

## Batch boundary, unchanged

`run_pipeline()` keeps fetching up to 50 emails per tick
(`fetch_pending_smtp(limit=50)`, unchanged default). The full batch runs
through rules/extraction/enrichment/LLM first. Only once that first pass
completes for the whole batch does the detonation phase begin. New-email
fetching pauses for the duration of the detonation phase (matches today's
`detonation_state.is_active()` gate in `run_pipeline()` — no change needed
there, it already refuses a new tick while a window is active).

## Detonation phase — sequential, live-notified, non-preemptive priority

`detonation.py::process_detonation_queue()` changes from "fetch one batch of
`DETONATION_BATCH_SIZE`, loop over the in-memory list" to "loop until the
queue is empty, re-querying the DB immediately before each single item"
(`get_queued_detonations(db, limit=1)` each iteration instead of
`limit=cfg.DETONATION_BATCH_SIZE` once). This is what makes a manually
inserted `priority=True` row (existing field, existing
`priority.desc(), created_at.asc()` ordering) get picked up right after the
currently-running detonation finishes, without interrupting it — the running
item is never touched; only the *next* row picked is affected by a
priority insert made while it's in flight.

`DETONATION_BATCH_SIZE` becomes unused by the main loop; leave the config
value in place (harmless) or remove it if unused elsewhere — confirm during
implementation.

For each individual attachment:
1. Fire a "detonating" notification naming the email before submission.
2. Submit, poll, parse the report (existing `cape_client.detonate`,
   unchanged).
3. Fold the result into the email's `enrichment_result.detonation` (existing
   `_apply_result_to_email`, unchanged).
4. Fire a "report ready" notification naming the email, immediately —
   don't wait for the rest of the queue to drain.

Notifications: reuse the existing notification primitives already shipped
for the Branch-B manual-detonation "ready" alert (`notifyManualReady` in
`dashboard.js` — in-page banner + desktop `Notification` API + WebAudio beep,
driven by polling `/api/detonation/status`), generalized to fire for two new
events per email: "detonating now" (on submission) and "report ready" (on
result), each naming the email instead of a manual-upload filename. No new
transport needed — same poll-and-diff pattern, extended to cover
per-email-attachment rows instead of only Branch-B manual rows.

## VM lifecycle — hot during the run, idle-timeout suspend

The VM resumes once at the start of the detonation phase (as today) and
stays resumed across every item in this phase's queue — no per-attachment
resume/suspend cycle. After the queue empties, a 5-minute idle timer starts;
if no new item is enqueued before it fires, the existing `_restore()` runs
(suspend VM, restart Docker; Ollama reloads lazily as today). If a new
attachment arrives before the timer fires, the timer resets and the window
stays open.

Implementation note: this requires the detonation window to run as a
background watcher rather than a single synchronous call inside
`run_pipeline()`'s tail end — needs a small idle-timeout loop (similar
shape to `scheduler.py`'s `BackgroundScheduler` usage, or a simple
`threading.Timer` reset on each new enqueue) instead of the current
"process one fixed batch and return" call. Exact mechanism to be decided
during implementation planning.

## Second LLM pass

Once an email's attachment(s) all have a report, re-run the LLM analysis
with the CAPE report folded into the enrichment context (extend the
existing `signal_scoring`/`analysis.analyze_email_body` inputs — exact
wiring TBD during planning, but output stays within the existing
`accepted` / `escalated` `LLMVerdict.verdict` values). A CAPE-confirmed
malicious result (malscore >= `CAPE_MALSCORE_ESCALATE`) pins the verdict to
`escalated` regardless of what the LLM says (existing rule: rules/deterministic
signals the LLM can't override) and adds a clear "sandbox confirmed
malicious" flag to the stored verdict so the analyst's quarantine click is a
formality, not a guess. `quarantined` is never set automatically — matches
CLAUDE.md's non-negotiable human-confirmation rule and today's existing
semantics (`released`/`quarantined` are analyst actions on an `escalated`
email).

## Dashboard: per-email detonation visibility

On the email detail page's attachment section (`renderAttachmentsPanel` /
`_attachmentPanelRowHtml` in `dashboard.js`, already renders per-attachment
pending/running rows and mounts a live noVNC feed via `mountNoVnc` for
whatever's currently running in an active window), while an attachment's
detonation is in flight:
- Show a `detonating` status badge (extend the existing row-status
  rendering with this new state).
- The live sandbox feed is already mounted automatically for a running
  attachment (`mountNoVnc(el, taskId)` in `renderAttachmentsPanel`) — **no
  new wiring needed here**, only confirming it stays **view-only**
  (`interactive` flag left `false`/unset) for this automated path, exactly
  as today. Manual detonation (analyst-uploaded samples) keeps the existing
  interactive (`interactive: true`) mouse/keyboard control — deliberately
  unchanged; the two flows stay behaviorally distinct on purpose (automated
  verdicts must stay untainted/reproducible; manual samples are the
  analyst's own, safe to interact with).

Once the report lands, the badge flips to a completed state and (once the
second LLM pass runs) the email's final status updates.

## Fail-safe (unchanged)

- CAPE unreachable at window start → existing `_escalate_all_queued`
  fail-safe fires, escalating everything queued.
- Crash mid-run → existing `try/finally` watchdog in
  `process_detonation_queue` still guarantees `_restore()` runs.
- Idle-timeout suspend must go through the same `_restore()` path so the
  watchdog guarantee still holds even when the trigger is "timer fired"
  rather than "queue drained."

## Testing

- Unit: broadened enqueue-gate condition (attachment enqueued unless
  rules-engine reject).
- Unit: sequential re-query loop picks up a priority row inserted mid-run
  immediately after the current item, without interrupting it.
- Unit: idle-timeout triggers `_restore()` after N seconds of empty queue;
  resets on new enqueue.
- Unit: second-pass verdict never sets `quarantined`; CAPE malicious result
  pins to `escalated` with the sandbox-confirmed flag.
- Existing detonation fail-safe tests (CAPE unavailable, crash mid-window)
  continue to pass unmodified.
