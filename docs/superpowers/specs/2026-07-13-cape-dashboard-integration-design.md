# CAPE Sandbox ↔ Dashboard Integration — Design

**Date:** 2026-07-13
**Author:** Mohamed (with Claude)
**Status:** Approved for planning
**Related:** `CLAUDE.md` (Build Log 2026-07-10/13), memory `project_detonation_cape`, CAPE integration spec (provided by tutor)

---

## 1. Purpose

Wire the existing email-triage dashboard to the already-built CAPE detonation
backend so that an analyst can:

1. See that a suspicious attachment has been **queued for detonation**.
2. Watch the detonation VM **live** while it runs.
3. Read CAPE's **full visual report** (process tree, screenshots, signatures,
   network) inside the dashboard when analysis finishes.
4. **Preview the original attachment** (PDF/image/Office text) alongside the
   analysis.

This is the *viewing / reporting / recovery* layer on top of the detonation
subsystem. It does **not** rebuild the detonation pipeline.

---

## 2. What already exists (build on, do not rebuild)

| Piece | File | Role |
|---|---|---|
| CAPE REST client | `src/cape_client.py` | submit / poll / fetch / parse over `apiv2` |
| Drained-window orchestrator | `src/detonation.py` | memory-gated detonation window + fail-safe watchdog |
| Config | `src/detonation_config.py` | CAPE URL/token, timeouts, VM commands |
| In-process pause flag | `src/detonation_state.py` | pipeline pause during a window |
| Queue table | `PendingDetonation` in `src/database.py` | queued/running/done/error rows |
| Status endpoint | `GET /api/detonation/status` in `src/routers/emails.py` | queue depth + window state |

`cape_task_id` is already persisted at
`email.enrichment_result["detonation"]["cape_task_id"]` and in
`PendingDetonation.result`. No schema migration is required for this work.

### Decisions locked in during brainstorming

- **Detonation timing:** keep the **deferred drained-window queue** (do NOT
  switch to immediate submission). The RAM gating on the 16 GB host is
  deliberate. The dashboard shows "queued for detonation" immediately; the live
  view activates when the window actually runs.
- **Access path:** **proxy everything through the dashboard.** The analyst
  browser only ever talks to the dashboard origin. This keeps the strict CSP
  (`default-src 'self'`) and `X-Frame-Options: DENY` intact.
- **Live view:** **noVNC + websockify**, vendored into `static/`. Nothing
  browser-viewable currently runs on attijari (tonight used native
  SPICE/VNC over an SSH tunnel); CAPE has no built-in noVNC page in this setup,
  so we build it fresh.
- **VM recovery (spec §6):** a small **HTTP wrapper service on attijari**
  (`/vm/status`, `/vm/reset`), not backend SSH shelling.
- **Attachment preview (spec §7):** in scope, simple version (browser-native
  rendering, no new JS libraries beyond vendored noVNC).

---

## 3. Network topology (from the spec — for reference)

```
Windows host (dashboard: FastAPI)
  └─ Hyper-V VM "attijari" (Linux) — 192.168.100.10 — runs CAPE + wrapper + websockify
       └─ nested KVM VM "cuckoo2" (Windows 10 detonation machine) — 192.168.122.92
```

- attijari (`192.168.100.10`) is the only externally reachable machine.
- cuckoo2 is never targeted directly; everything routes through attijari.
- CAPE apiv2 base: `http://192.168.100.10:8000/apiv2/` (note the `/apiv2/`
  prefix — omitting it yields clean 404s).
- CAPE web report: `http://192.168.100.10:8000/analysis/<task_id>/`.

Two distinct VM lifecycles exist and must not be confused:
- **attijari VM** — managed from the Windows host by `detonation.py` (Hyper-V
  Save-VM/Start-VM) as the memory-gating drain/restore step.
- **cuckoo2 VM** — managed **only** by CAPE itself (revert → boot → run → shut
  down). We never start/stop it manually. The *only* exception is the recovery
  path when it is left stuck `running` (spec §6), performed via the attijari
  wrapper's `/vm/reset`.

---

## 4. Architecture

```
Analyst browser ──HTTPS/WSS──> Dashboard (FastAPI, Windows host)
                                   │
 report iframe ── GET /api/detonation/report/<task_id>/…  ──HTTP──> CAPE web UI (attijari:8000)
 noVNC iframe  ── WS  /ws/vnc/<task_id>            ──WS relay──> websockify (attijari:6080) ─> cuckoo2
 VM recovery   ── (backend only) ──HTTP+Bearer──> VM wrapper (attijari:<port>) ──virsh──> cuckoo2
 file preview  ── GET /api/emails/<id>/attachments/<att_id>/raw   (stored bytes, same origin)
```

Everything the browser loads is same-origin (proxied), so the existing CSP and
frame policy need no loosening for cross-origin embedding. See §8 for the one
CSP addition (`frame-src 'self'`). noVNC renders to a `<canvas>` from websocket
data rather than remote images, so no `img-src` change is needed.

---

## 5. Components

### 5.1 Attijari VM wrapper service (separate deliverable)

A standalone deployable that lives **on attijari**, not in this repo's runtime —
same operational pattern as `cape.service` / `cape-processor.service`. Delivered
as: source + a **single linear attijari setup runbook** (see §9).

- Framework: FastAPI (uvicorn) or Flask — small, one file.
- Bind: internal interface / localhost only (not the external NIC).
- Auth: `Authorization: Bearer <token>` from an env var (never hardcoded).
- Endpoints:
  - `GET /vm/status` → `{ "cuckoo2": "<virsh domstate>" }`
  - `POST /vm/reset` → `virsh destroy cuckoo2` then
    `systemctl restart cape.service`; returns success/detail.
- Runs `virsh`/`systemctl` via `sudo` with a tightly scoped sudoers entry
  (documented in the runbook).

The runbook also covers websockify + vendored-noVNC provisioning and the
**fixed VNC port** requirement (below).

### 5.2 `src/cape_vm_wrapper.py` (new, host side)

Thin HTTP client for the wrapper. Functions: `cuckoo2_state()`,
`reset_cuckoo2()`. Config (URL, token, toggle, timeout) added to
`detonation_config.py` and read from env.

`detonation.py._resume_vm()` gains a cuckoo2 pre-flight **after** the attijari
VM is up and CAPE API is ready, **before** submitting the batch: if
`cuckoo2_state() == "running"`, call `reset_cuckoo2()` and re-wait for CAPE.
This prevents `CuckooMachineError: Trying to start a virtual machine that has
not been turned off`. Wrapper unreachable → log + proceed (submission will fail
safely and escalate) — never blocks the drain window indefinitely.

### 5.3 `src/routers/detonation_proxy.py` (new router)

Mounted with `Depends(verify_auth)` like the other protected routers.

- `GET /api/detonation/report/{task_id}/{path:path}` — reverse-proxy of CAPE's
  Django report. Streams the upstream response; rewrites asset URLs so relative
  and root-relative (`/static/…`, `/analysis/…`) references route back through
  this proxy prefix. `task_id` validated as an int. Upstream errors surface as a
  clean dashboard error state, not a stack trace.
- `WS /ws/vnc/{task_id}` — bidirectional relay to `ws://attijari:6080/…`
  (websockify). Auth: JWT via `?token=` query param, reusing the exact pattern
  in `src/routers/websockets.py` (decode, revocation check, close 1008 on
  failure). Opens **only** while a detonation window is active
  (`detonation_state.is_active()`); otherwise closes with a clear reason. Binary
  frames relayed both directions until either side disconnects.
- `GET /api/emails/{id}/attachments/{att_id}/raw` — serves the stored
  attachment bytes for the preview pane. Reads from the internal `stored_path`
  (never an attacker-supplied filename — CLAUDE.md rule 6). Forces a safe
  `Content-Type`: `application/pdf` and `image/*` served `inline`; everything
  else `application/octet-stream` as an attachment with
  `X-Content-Type-Options: nosniff`. Returns 404 if the stored file is missing.

A `web_report_url` convenience field is added to `cape_client.parse_report()`
output (`.../analysis/<task_id>/`) so the frontend does not reconstruct URLs.

### 5.4 `src/dashboard/static/novnc/` (vendored)

Vendored noVNC client (self-contained JS/CSS, no CDN). Served from `'self'`,
CSP-clean. The dashboard's noVNC init points at the dashboard's own
`/ws/vnc/<task_id>` endpoint — never directly at attijari.

### 5.5 Frontend — `detail.html` + `dashboard.js`

A detonation panel with a state machine, driven by polling
`GET /api/detonation/status` plus the email's
`enrichment_result.detonation` in the detail payload:

| State | Panel |
|---|---|
| queued / running | file preview pane + live noVNC iframe + "Analyzing…" spinner |
| reported / done | embedded report iframe (`/api/detonation/report/<task_id>/`) + "Open full report" new-tab link + parsed verdict summary (malscore, signatures) |
| error | error card showing `result.error` / task `errors` + **Retry** (re-enqueue) button |

- **Manual "Open sandbox" button** (spec §5b): opens the same noVNC viewer
  on demand, independent of any submission.
- File preview: browser-native — `<iframe>`/`<embed>` for PDF and images via
  the `/raw` endpoint; extracted text (already available from the extraction
  stage) shown for Office/other types. No PDF.js or doc-preview library.

---

## 6. Data flow

1. Pipeline enqueues a `PendingDetonation` row (existing behaviour). Email
   detail shows **queued**.
2. Drained window runs (existing `process_detonation_queue`): attijari VM
   resumes → **cuckoo2 pre-flight (new)** → submit → CAPE boots cuckoo2 → poll.
   During this window the frontend shows **running** with the live noVNC view.
3. On report: `parse_report` result (now incl. `web_report_url`) is folded into
   `email.enrichment_result["detonation"]` (existing `_apply_result_to_email`).
   Frontend swaps to **reported**, embedding the proxied report.
4. On failure at any step: existing fail-safe escalates the email; frontend
   shows **error** + retry.

No new persistence. The frontend reads `cape_task_id` / `web_report_url` /
`status` straight from the email detail JSON.

---

## 7. Error handling (fail-safe, never fail-open — CLAUDE.md rule 1)

- **View / proxy / wrapper unreachable does not affect the verdict.** Live view
  and report are display-only. If they fail, the analyst sees "sandbox view
  unavailable"; the email's verdict/escalation (already computed by the backend
  fail-safe) stands.
- **cuckoo2 stuck running** → wrapper `/vm/reset` recovers it. Wrapper itself
  down → submission fails → existing `_escalate_all_queued` routes the email to
  a human. Never auto-accept.
- **VNC relay** opens only during an active detonation window; otherwise closes
  with a clear reason (avoids exposing the VM screen at rest).
- **Report proxy** upstream 5xx/timeout → dashboard error card with a retry
  link, never a raw upstream error page.
- **Attachment `/raw`** missing file → 404 + "original file no longer
  available"; content-type always forced (never trust declared type — rule 7).

---

## 8. Security notes

- CSP: add `frame-src 'self'` so the report/noVNC iframes (same-origin proxied)
  are allowed; nothing else loosened. `connect-src` already permits `ws:`/`wss:`
  for the relay. `X-Frame-Options: DENY` stays (it governs others framing *us*,
  not us framing same-origin content).
- Wrapper token and CAPE token live in `.env` only (never committed, never
  hardcoded — consistent with the credentials-exposure finding, obs 66).
- The VNC relay and report proxy both require dashboard auth; the VM screen is
  never exposed unauthenticated (spec §5 caution).
- Attachment bytes are served only to authenticated analysts, with forced
  content-type + `nosniff`, from internal storage paths only.
- All email content still stays local: CAPE runs on the local attijari VM; no
  email body/attachment is sent to any external service (CLAUDE.md core
  constraint). The proxy talks only to `192.168.100.10`.

---

## 9. Attijari setup runbook (single linear document — deliverable)

Delivered as one file (e.g. `docs/attijari-sandbox-setup.md`) covering, in
strict order, with a verify step after each:

1. Install & start the **VM wrapper service** (systemd unit, env token, scoped
   sudoers). Verify: `curl -H "Authorization: Bearer <t>" http://127.0.0.1:<port>/vm/status`.
2. **Fix the cuckoo2 VNC port** in its libvirt XML (no `autoport`). Verify:
   `virsh vncdisplay cuckoo2` returns a stable `:N` across a reboot.
3. Install & run **websockify** proxying `127.0.0.1:5900` (or the confirmed VNC
   socket) → `:6080`. Verify: `wscat -c ws://127.0.0.1:6080` connects.
4. Confirm the **vendored noVNC** assets are the ones served by the dashboard
   (no attijari-side web page needed).
5. Only after 1–4 pass, configure the dashboard `.env`
   (`CAPE_VM_WRAPPER_URL`, `CAPE_VM_WRAPPER_TOKEN`, websockify host/port) and
   test end-to-end.

Rationale: every manual step on attijari has a way of going sideways; one
linear runbook with per-step verification beats reconstructing order later.

---

## 10. Testing

- **Unit:** `cape_vm_wrapper` client (mock wrapper); report-proxy URL rewriting;
  `parse_report` `web_report_url`; `/raw` content-type forcing + path-safety
  (rejects traversal, uses `stored_path` only).
- **Integration:** a mock CAPE + mock wrapper (pytest + aiohttp/httpx) driving
  submit → queued → running → reported panel transitions; VNC relay auth
  (missing/invalid token closes 1008).
- **Manual demo checklist:** queued → live noVNC view → embedded report;
  manual "Open sandbox"; a forced-failure path showing the error card + retry.

---

## 11. Scope boundaries (YAGNI)

Explicitly **out of scope**: immediate (non-drained) submission; changing the
queue/RAM model; the screenshot-slideshow fallback (we do real noVNC); any auth
redesign (we reuse `verify_auth` + JWT-query-param); switching CAPE tokens to a
dedicated service account (flagged as later hardening, not this iteration).
