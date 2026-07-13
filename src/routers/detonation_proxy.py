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
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

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
