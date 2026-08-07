"""detonation_proxy.py — dashboard-side viewing layer for the CAPE sandbox.

Everything the analyst's browser needs from the detonation subsystem, served
same-origin so the strict CSP stays intact:

  - GET  /api/emails/{email_id}/attachments/{attachment_id}/raw  — stored
    attachment bytes for the preview pane, ONLY for attachments verified
    safe by CAPE (see attachments.attachment_safety_status). attachment_id
    is the Attachment row id. Content-type is forced from magic bytes — the
    declared type and filename are hostile data (rules 6+7).
  - POST /api/emails/{email_id}/attachments/{attachment_id}/insist  — analyst
    insists on opening an attachment that isn't verified safe; submits it to
    CAPE now (on-demand, not the batch queue) and starts a live VM session.
  - GET  /api/detonation/report/{task_id}/{path}  — reverse proxy of CAPE's
    Django report (path-allowlisted; never an open proxy into CAPE).
  - WS   /ws/vnc/{task_id} — relay to websockify on imania, open only
    during an active detonation window.
  - POST /api/detonation/{pending_id}/retry — re-queue a failed detonation.
  - GET  /api/detonation/queue — pending/in-flight/manual-not-yet-queued rows
    for the operator-facing Detonation Queue panel.
  - POST /api/detonation/queue/{pending_id}/priority — operator jumps a
    queued row to the front (priority=True).
  - GET  /api/detonation/vm-info — machines/primary-VM/recent-tasks snapshot
    for the Health page's VM bubble (backed by cape_client's apiv2 wrappers).
  - GET  /api/detonation/tasks/{task_id}/mitmdump — download a task's
    decrypted-TLS capture, if CAPE's mitmdump API is enabled.

Display-only layer: nothing here influences a verdict (fail-safe rule 1).
"""
from __future__ import annotations

import asyncio
import os
import re
from typing import Optional

import jwt as pyjwt
import requests
from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket
from fastapi.responses import FileResponse, HTMLResponse, Response

import detonation_config as det_cfg
from api_core import (
    require_permission, AuthenticatedUser,
    JWT_SECRET, ALGORITHM, is_token_revoked,
)

detonation_proxy_router = APIRouter()

# Separate router for the VNC relay: it does its own token-based auth
# (_ws_token_ok) since a WebSocket scope has no HTTP Request for verify_auth
# to depend on. Must be included in api.py WITHOUT the router-level
# Depends(verify_auth) that wraps detonation_proxy_router, or FastAPI raises
# "verify_auth() missing 1 required positional argument: 'request'" on connect.
detonation_ws_router = APIRouter()


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


@detonation_proxy_router.get("/api/emails/{email_id}/attachments/{attachment_id}/raw")
def api_attachment_raw(
    email_id: int, attachment_id: int,
    user: AuthenticatedUser = Depends(require_permission("emails.view")),
):
    """Serve stored attachment bytes for the detail-page preview pane —
    ONLY for attachments verified safe by CAPE detonation. Anything else
    (unverified, pending, or confirmed unsafe) is blocked here; the analyst
    must use POST .../insist to view it live in the VM instead."""
    from database import SessionLocal
    from attachments import resolve_attachment, STATUS_SAFE
    db = SessionLocal()
    try:
        resolved = resolve_attachment(db, email_id, attachment_id)
        if not resolved["found"]:
            raise HTTPException(404, "Attachment not found")
        if resolved["status"] != STATUS_SAFE:
            raise HTTPException(403, detail={"status": resolved["status"]})
        stored_path = resolved["attachment"].stored_path
    finally:
        db.close()

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
            "Content-Disposition": f'{disposition}; filename="attachment-{attachment_id}"',
            "X-Content-Type-Options": "nosniff",
        },
    )


# ---------------------------------------------------------------------------
# CAPE web-report reverse proxy (same-origin so CSP stays strict)
# ---------------------------------------------------------------------------

# CAPE's own top-level route namespaces, confirmed against a live report page
# (task 56 on attijari, 2026-07-27) via `curl .../analysis/56/` — every
# root-relative href/src/data-url in the real CAPE UI starts with one of
# these: report tabs ("analysis/load_files/<id>/behavior/",
# "analysis/<id>/pcapstream/<n>/"), the nav bar's Submit/Search/Pending
# ("submit/", "analysis/search/", "analysis/pending/"), Statistics
# ("statistics/"), Compare ("compare/"), dropped/static file downloads
# ("file/"), the JSON export link ("filereport/<id>/json/"), and the nav
# bar's "API" link itself ("apiv2/"). The proxy only ever forwards GET
# (see the router decorator below), so this can't be used to trigger CAPE's
# mutating actions (resubmit, delete, etc. are POSTs) even though their
# link targets are allow-listed here for viewing.
_REPORT_PREFIX_ALLOW = (
    "analysis/", "static/", "apiv2/", "file/", "filereport/",
    "submit/", "compare/", "statistics/",
)

# Root-relative references anywhere in CAPE's Django HTML/CSS/inline-JS get
# re-rooted onto the proxy prefix. CAPE emits these not just as
# href=/src=/action= attributes but also as jQuery `data-url="/analysis/..."`
# (behavior/network tabs, loaded via `.load(url)`) and as plain quoted string
# literals inside <script> blocks (e.g. `$.get("/analysis/56/pcapstream/"...)`
# for the PCAP viewer) — so this matches any quoted "/<prefix>" occurrence
# rather than only specific attributes.
_ROOT_REF_RE = re.compile(
    r'(["\'])/(?=(?:' + '|'.join(re.escape(p) for p in _REPORT_PREFIX_ALLOW) + r'))'
)
# Unquoted CSS `url(/static/...)` form.
_CSS_URL_RE = re.compile(
    r'url\(/(?=(?:' + '|'.join(re.escape(p) for p in _REPORT_PREFIX_ALLOW) + r'))'
)

# CAPE's report page ships its tab-switching logic (the `tabajax` click
# handler that actually fetches Behavior/Network content) as inline
# <script> blocks. The dashboard's CSP is nonce-only (no 'unsafe-inline' —
# see security_and_metrics_middleware in api.py), so any inline script
# without the per-request nonce is silently dropped by the browser: the
# click still fires (it's a plain <a href="#behavior">, so the URL fragment
# changes) but nothing runs to load the tab content. Matches <script> and
# <script type='...'> but not <script src=...>, which is same-origin after
# rewriting and already covered by script-src 'self'.
_INLINE_SCRIPT_RE = re.compile(r'<script(?![^>]*\bsrc=)([^>]*)>', re.IGNORECASE)

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
    if ".." in path:
        return None
    if path.startswith(_REPORT_PREFIX_ALLOW):
        return path
    return None


def _upstream_headers(request: Request) -> dict:
    """Headers to forward to CAPE upstream, beyond query params.

    CAPE's report tabs (behavior/network) are loaded via jQuery `.load()`,
    which auto-sends `X-Requested-With: XMLHttpRequest`; CAPE's Django views
    check that header and 403 without it (confirmed live against attijari
    task 56, 2026-07-27 — a request missing this header gets a 403, not the
    partial's HTML). We only forward what the browser actually sent for this
    request; nothing else crosses (no cookies/auth headers — this proxy uses
    its own CAPE credentials via det_cfg, never the analyst's dashboard
    session).
    """
    headers = {}
    xrw = request.headers.get("x-requested-with")
    if xrw:
        headers["X-Requested-With"] = xrw
    return headers


def _rewrite_report_html(body: str, task_id: int, nonce: str = "") -> str:
    """Re-root root-relative asset/link URLs onto this proxy's prefix, and
    (when a nonce is supplied) tag CAPE's inline <script> blocks with it so
    the dashboard's nonce-only CSP doesn't silently drop them."""
    prefix = f"/api/detonation/report/{task_id}"
    body = _ROOT_REF_RE.sub(lambda m: f"{m.group(1)}{prefix}/", body)
    body = _CSS_URL_RE.sub(lambda m: f"url({prefix}/", body)
    if nonce:
        body = _INLINE_SCRIPT_RE.sub(lambda m: f'<script nonce="{nonce}"{m.group(1)}>', body)
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
            headers=_upstream_headers(request),
        )
    except Exception:
        return HTMLResponse(_REPORT_ERROR_PAGE, status_code=502)
    if r.status_code >= 500:
        return HTMLResponse(_REPORT_ERROR_PAGE, status_code=502)

    ctype = r.headers.get("content-type", "application/octet-stream")
    base_type = ctype.split(";")[0].strip().lower()
    if base_type in ("text/html", "text/css"):
        nonce = getattr(request.state, "csp_nonce", "")
        return Response(content=_rewrite_report_html(r.text, task_id, nonce),
                        status_code=r.status_code, media_type=ctype)
    # Binary assets (images, fonts, screenshots) pass through untouched.
    # Upstream headers (incl. any X-Frame-Options) are deliberately dropped;
    # our own middleware applies the dashboard's security headers.
    return Response(content=r.content, status_code=r.status_code, media_type=ctype)


# ---------------------------------------------------------------------------
# VM bubble (Health page): a snapshot of everything cape_client's apiv2
# wrappers can tell us about the sandbox — machines, the primary VM, recent
# tasks. Any of those endpoints can come back disabled in CAPE's own
# api.conf (see cape_client._get_json) — that surfaces here as
# available=False per section rather than failing the whole panel, since
# this is a status view (fail-safe rule 1: display-only, never blocks or
# influences anything).
# ---------------------------------------------------------------------------

def _primary_machine_name(machines: Optional[list], tasks: Optional[list]) -> str:
    """The CAPE-registered detonation guest (e.g. "cuckoo2") — NOT
    det_cfg.CAPE_VM_NAME, which is the outer Hyper-V VM ("cape-ubuntu")
    hosting CAPE itself, a completely different machine. Prefer whatever
    CAPE's own machines list reports; when that's disabled (common — see
    module docstring), fall back to the most recent task's "machine" field,
    which every reported task carries regardless of the machines-list
    toggle. "cuckoo2" is the last-resort default, matching this deployment's
    documented guest name (see cape_dashboard-integration-design.md)."""
    if machines:
        name = machines[0].get("name")
        if name:
            return name
    if tasks:
        name = tasks[0].get("machine")
        if name:
            return name
    return "cuckoo2"


@detonation_proxy_router.get("/api/detonation/vm-info")
def api_detonation_vm_info(
    user: AuthenticatedUser = Depends(require_permission("health.view")),
):
    """Organized snapshot for the Health page's VM bubble: registered
    machines, the sandbox detonation guest's own detail, and recent tasks."""
    import cape_client

    machines = cape_client.list_machines()
    tasks = cape_client.list_tasks(limit=10)
    primary_name = _primary_machine_name(machines, tasks)
    primary = cape_client.view_machine(primary_name)

    return {
        "machines": {"available": machines is not None, "data": machines or []},
        "primary_machine": {
            "name": primary_name,
            "available": primary is not None,
            "data": primary,
        },
        "recent_tasks": {"available": tasks is not None, "data": tasks or []},
    }


@detonation_proxy_router.get("/api/detonation/tasks/{task_id}/mitmdump")
def api_detonation_task_mitmdump(
    task_id: int,
    user: AuthenticatedUser = Depends(require_permission("health.view")),
):
    """Download a task's decrypted-TLS capture, if CAPE's mitmdump download
    API is enabled for this deployment (it's disabled by default in CAPE's
    own api.conf on several installs, cape_client.fetch_task_mitmdump
    returns None in that case rather than the JSON error CAPE sends)."""
    import cape_client
    data = cape_client.fetch_task_mitmdump(task_id)
    if data is None:
        raise HTTPException(404, "Mitmdump capture not available for this task")
    return Response(
        content=data, media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="task-{task_id}-mitmdump.bin"'},
    )


# ---------------------------------------------------------------------------
# Live sandbox view: WS relay to websockify on imania
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


@detonation_ws_router.websocket("/ws/vnc/{task_id}")
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


# ---------------------------------------------------------------------------
# Detonation Queue panel — pending list + operator-set priority
# ---------------------------------------------------------------------------

@detonation_proxy_router.get("/api/detonation/queue")
def api_detonation_queue(
    user: AuthenticatedUser = Depends(require_permission("emails.view")),
):
    """Everything queued or about to be for the operator-facing Detonation
    Queue panel: the in-flight row, the priority-ordered queue, and manual
    (Branch-B) rows not queued yet. See database.get_detonation_queue_overview."""
    from database import SessionLocal, get_detonation_queue_overview
    db = SessionLocal()
    try:
        return get_detonation_queue_overview(db)
    finally:
        db.close()


@detonation_proxy_router.post("/api/detonation/queue/{pending_id}/priority")
def api_detonation_set_priority(
    pending_id: int,
    user: AuthenticatedUser = Depends(require_permission("emails.scan")),
):
    """Operator jumps a queued row to the front — it's picked up right after
    whatever's currently detonating finishes (never interrupts an in-flight
    run). Same permission as the Insist button, since both are operator
    overrides of the automatic detonation order."""
    from database import SessionLocal, set_detonation_priority, add_audit_entry
    db = SessionLocal()
    try:
        row = set_detonation_priority(db, pending_id)
        if row is None:
            raise HTTPException(404, "Queue entry not found")
        if row.status != "queued" or not row.priority:
            raise HTTPException(409, f"Cannot prioritize entry in status '{row.status}'")
        add_audit_entry(
            db, action="detonation_priority_set", actor=user.username,
            email_id=row.email_id,
            details={"pending_id": row.id, "sha256": row.sha256, "filename": row.filename},
        )
        return {"success": True, "id": row.id, "priority": True}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Insist on opening an unverified/unsafe attachment (on-demand, not the
# batch queue — see attachments.insist_open)
# ---------------------------------------------------------------------------

@detonation_proxy_router.post("/api/emails/{email_id}/attachments/{attachment_id}/insist")
def api_attachment_insist(
    email_id: int, attachment_id: int,
    user: AuthenticatedUser = Depends(require_permission("emails.scan")),
):
    """Analyst insists on opening an attachment that isn't verified safe —
    submits it to CAPE now and opens a live VM session. See
    attachments.insist_open for the orchestration and its audit trail."""
    from database import SessionLocal
    from attachments import resolve_attachment, insist_open
    db = SessionLocal()
    try:
        resolved = resolve_attachment(db, email_id, attachment_id)
        if not resolved["found"]:
            raise HTTPException(404, "Attachment not found")
        return insist_open(db, resolved["attachment"], user.username)
    finally:
        db.close()


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

    import detonation_config as cfg
    from detonation import process_detonation_queue
    threading.Thread(
        target=process_detonation_queue,
        kwargs={"idle_timeout_seconds": cfg.DETONATION_MANUAL_IDLE_TIMEOUT_SECONDS},
        daemon=True,
        name="manual-detonation-window",
    ).start()
    return {"status": "started"}


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
