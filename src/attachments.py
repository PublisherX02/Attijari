"""attachments.py — safety classification for attachments shown on the email
detail page.

Fail-safe (CLAUDE.md rule 1): anything not affirmatively confirmed clean by
CAPE is treated as not-safe. Thin, hermetically-testable logic — see
manual_detonation.py for the same convention; routers/detonation_proxy.py
wraps these functions in HTTP.
"""
from __future__ import annotations

STATUS_SAFE = "safe"
STATUS_UNSAFE = "unsafe"
STATUS_PENDING = "pending"
STATUS_UNVERIFIED = "unverified"


def attachment_safety_status(db, sha256: str) -> str:
    """Classify a file by its sha256, using the most recent detonation
    outcome for that exact content across ALL emails — the same bytes carry
    the same verdict wherever they show up."""
    from database import PendingDetonation

    latest = (
        db.query(PendingDetonation)
        .filter(PendingDetonation.sha256 == sha256)
        .order_by(PendingDetonation.created_at.desc())
        .first()
    )
    if latest is None:
        return STATUS_UNVERIFIED
    if latest.status in ("queued", "running"):
        return STATUS_PENDING
    if latest.status == "done":
        import detonation_config as cfg
        malscore = (latest.result or {}).get("malscore")
        if malscore is not None and malscore < cfg.CAPE_MALSCORE_SUSPICIOUS:
            return STATUS_SAFE
        return STATUS_UNSAFE
    return STATUS_UNSAFE  # "error" or any unrecognized status — fail-safe


def resolve_attachment(db, email_id: int, attachment_id: int) -> dict:
    """Look up an attachment scoped to BOTH its id and its email_id (an
    attachment_id valid on a different email must count as not found, never
    403 — don't reveal cross-email existence) and classify its safety.

    Returns {"found": False} or
    {"found": True, "status": str, "attachment": Attachment}.
    """
    from database import Attachment

    row = (
        db.query(Attachment)
        .filter(Attachment.id == attachment_id, Attachment.email_id == email_id)
        .first()
    )
    if not row:
        return {"found": False}
    return {"found": True, "status": attachment_safety_status(db, row.sha256), "attachment": row}
