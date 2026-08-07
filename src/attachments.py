"""attachments.py — safety classification for attachments shown on the email
detail page.

Fail-safe (rule 1): anything not affirmatively confirmed clean by
CAPE is treated as not-safe. Thin, hermetically-testable logic — see
manual_detonation.py for the same convention; routers/detonation_proxy.py
wraps these functions in HTTP.
"""
from __future__ import annotations

import threading

STATUS_SAFE = "safe"
STATUS_UNSAFE = "unsafe"
STATUS_PENDING = "pending"
STATUS_UNVERIFIED = "unverified"


def attachment_safety_status(db, sha256: str, extraction_escalate: bool | None = None, occurred_at=None) -> str:
    """Classify a file by its sha256, using the most recent detonation
    outcome for that exact content across ALL emails — the same bytes carry
    the same verdict wherever they show up.

    extraction_escalate/occurred_at (this specific Attachment row's own
    static-analysis verdict and timestamp) guard against a stale
    PendingDetonation row masking a fresh escalation: a deterministic
    extraction flag (YARA match, sandbox fail-safe) on THIS occurrence must
    never be silently cleared by an older CAPE 'safe' outcome for the same
    bytes — only a detonation that happened AFTER this occurrence (an
    analyst deliberately re-submitting, e.g. via Insist) counts as a real,
    human-confirmed override. Mirrors rule 2 in CLAUDE.md: deterministic
    findings aren't overridable by a weaker/older signal."""
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
        if extraction_escalate and (occurred_at is None or latest.created_at < occurred_at):
            return STATUS_UNVERIFIED
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
    status = attachment_safety_status(
        db, row.sha256, extraction_escalate=row.extraction_escalate, occurred_at=row.created_at,
    )
    return {"found": True, "status": status, "attachment": row}


def _window_active() -> bool:
    import detonation_state
    return detonation_state.is_active()


def _start_window() -> None:
    """Analyst is watching this run live (email-detail 'Insist' button) —
    close the window on the short manual idle timeout, same as
    manual_detonation.py's _start_window, not the 5-minute
    automatic-scheduler default (which would leave the sandbox panel
    'stuck' for up to 5 more minutes after CAPE actually finishes)."""
    from detonation import process_detonation_queue
    import detonation_config as cfg
    threading.Thread(
        target=process_detonation_queue,
        kwargs={"idle_timeout_seconds": cfg.DETONATION_MANUAL_IDLE_TIMEOUT_SECONDS},
        daemon=True,
        name="attachment-insist-window",
    ).start()


def insist_open(db, attachment, username: str) -> dict:
    """Analyst explicitly chose to open an unverified/unsafe attachment.
    Always attempts a fresh submission — enqueue_detonation's existing dedup
    only blocks on an ALREADY queued/running row for this sha256, so a prior
    'done' or 'error' outcome never prevents getting a live session now.
    Audited: insisting on an unsafe file is a security-relevant decision."""
    from database import enqueue_detonation, add_audit_entry

    row = enqueue_detonation(
        db, sha256=attachment.sha256, stored_path=attachment.stored_path,
        filename=attachment.filename, email_id=attachment.email_id,
        reason="analyst_insist", priority=True, created_by=username,
    )
    add_audit_entry(
        db, action="attachment_insist_open", actor=username,
        email_id=attachment.email_id,
        details={"attachment_id": attachment.id, "sha256": attachment.sha256,
                  "filename": attachment.filename, "pending_id": row.id},
    )
    if _window_active():
        return {"id": row.id, "status": row.status, "window": "active"}
    _start_window()
    return {"id": row.id, "status": row.status, "window": "started"}
