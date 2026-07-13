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

import os
import re
from typing import Optional

import requests
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, Response

import detonation_config as det_cfg
from api_core import require_permission, AuthenticatedUser

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
