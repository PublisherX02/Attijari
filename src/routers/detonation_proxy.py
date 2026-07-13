"""detonation_proxy.py — dashboard-side viewing layer for the CAPE sandbox.

Everything the analyst's browser needs from the detonation subsystem, served
same-origin so the strict CSP stays intact:

  - GET  /api/emails/{email_id}/attachments/{att_id}/raw  — stored attachment
    bytes for the preview pane. att_id is the PendingDetonation row id (the
    only place stored_path is persisted). Content-type is forced from magic
    bytes — the declared type and filename are hostile data (CLAUDE.md 6+7).
  - GET  /api/detonation/report/{task_id}/{path}  — reverse proxy of CAPE's
    Django report (path-allowlisted; never an open proxy into CAPE).
  - WS   /ws/vnc/{task_id} — relay to websockify on attijari, open only
    during an active detonation window.
  - POST /api/detonation/{pending_id}/retry — re-queue a failed detonation.

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
