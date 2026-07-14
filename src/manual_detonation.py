"""manual_detonation.py — operator-driven, arbitrary-file detonation.

Thin, hermetically-testable logic behind the Manual Detonation page. The
FastAPI endpoints in routers/detonation_proxy.py are thin wrappers over this.

Security (CLAUDE.md): the uploaded file is stored under an internal id (never
the attacker filename, rule 6), typed by magic bytes downstream (rule 7), and
only ever submitted to the LOCAL CAPE VM — never to any external service.
"""
from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path
from typing import Optional

import detonation_config as cfg

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
MANUAL_UPLOAD_DIR = str(_PROJECT_ROOT / "data" / "manual_detonations")
os.makedirs(MANUAL_UPLOAD_DIR, exist_ok=True)


def _real_ext(original_filename: str) -> str:
    return os.path.splitext(original_filename or "")[1].lower()


def validate_upload(size: int, original_filename: str) -> Optional[str]:
    """Return an operator-facing error string, or None if the upload is allowed."""
    if size <= 0:
        return "The uploaded file is empty."
    if size > MAX_UPLOAD_BYTES:
        return f"File is too large (max {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)."
    ext = _real_ext(original_filename)
    if ext not in cfg.CAPE_DETONABLE_EXTENSIONS:
        return (f"CAPEv2 cannot detonate '{ext or 'this'}' files. "
                f"Supported types include .exe, .dll, .pdf, Office docs, scripts, archives.")
    return None


def store_upload(content: bytes, original_filename: str) -> tuple[str, str]:
    """Persist bytes under an internal id. Returns (stored_path, sha256).

    The on-disk name is an internal UUID + the real extension only; the
    attacker-supplied filename never touches the path."""
    sha = hashlib.sha256(content).hexdigest()
    ext = _real_ext(original_filename)
    internal_name = f"{uuid.uuid4().hex}{ext}"
    stored_path = os.path.join(MANUAL_UPLOAD_DIR, internal_name)
    with open(stored_path, "wb") as fh:
        fh.write(content)
    return stored_path, sha


# ---------------------------------------------------------------------------
# Orchestration (Branch A/B) + confirm
# ---------------------------------------------------------------------------

import threading

from database import (
    SessionLocal, enqueue_detonation, add_audit_entry,
    get_pending_detonation, promote_deferred_detonations,  # noqa: F401 (promote used by main.py)
)


def _window_active() -> bool:
    import detonation_state
    return detonation_state.is_active()


def _start_window() -> None:
    from detonation import process_detonation_queue
    threading.Thread(
        target=process_detonation_queue, daemon=True,
        name="manual-detonation-window",
    ).start()


def handle_upload(content: bytes, original_filename: str, branch: str, username: str) -> dict:
    """Validate, store, enqueue, audit. branch is 'now' (Branch A) or 'queue' (Branch B)."""
    err = validate_upload(len(content or b""), original_filename)
    if err:
        return {"error": err}
    if branch not in ("now", "queue"):
        return {"error": "Unknown branch."}

    stored_path, sha = store_upload(content, original_filename)
    status = "queued" if branch == "now" else "deferred"
    priority = branch == "queue"

    db = SessionLocal()
    try:
        row = enqueue_detonation(
            db, sha256=sha, stored_path=stored_path, filename=original_filename,
            email_id=None, reason="manual upload", created_by=username,
            priority=priority, status=status,
        )
        add_audit_entry(
            db, action="detonation_manual_upload", actor=username,
            details={"pending_id": row.id, "sha256": sha,
                     "filename": original_filename, "branch": branch},
        )
    finally:
        db.close()

    if branch == "queue":
        return {"id": row.id, "status": "deferred"}

    if _window_active():
        return {"id": row.id, "status": "queued", "window": "active"}
    _start_window()
    return {"id": row.id, "status": "queued", "window": "started"}


def confirm_ready(pending_id: int, username: str) -> dict:
    """Operator pressed OK on a Branch-B 'ready' row: promote to queued + start window."""
    db = SessionLocal()
    try:
        row = get_pending_detonation(db, pending_id)
        if not row:
            return {"error": "Detonation not found."}
        if row.status != "ready":
            return {"error": f"Not awaiting confirmation (status: {row.status})."}
        row.status = "queued"
        db.commit()
        add_audit_entry(
            db, action="detonation_manual_confirm", actor=username,
            details={"pending_id": row.id, "sha256": row.sha256},
        )
    finally:
        db.close()

    if _window_active():
        return {"id": pending_id, "status": "queued", "window": "active"}
    _start_window()
    return {"id": pending_id, "status": "queued", "window": "started"}
