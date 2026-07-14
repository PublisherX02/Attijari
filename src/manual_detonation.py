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
