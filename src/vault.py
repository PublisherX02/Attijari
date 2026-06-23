"""vault.py — Encrypted quarantine vault for escalated emails.

Uses Fernet (AES-128-CBC + HMAC-SHA256) symmetric encryption.
Key is loaded from the VAULT_ENCRYPTION_KEY environment variable.

Directory structure:
  data/vault/{YYYY-MM}/{email_sha256}.enc

If the key is lost, quarantined emails are unrecoverable (by design).
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

load_dotenv()

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
VAULT_DIR = _PROJECT_ROOT / "data" / "vault"


def _get_fernet() -> Fernet:
    """Get the Fernet cipher from environment. Raises if key is missing."""
    key = os.getenv("VAULT_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError(
            "VAULT_ENCRYPTION_KEY not set. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode() if isinstance(key, str) else key)


def _vault_path(email_sha256: str) -> Path:
    """Get the vault file path for an email, organized by month."""
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    vault_month_dir = VAULT_DIR / month
    vault_month_dir.mkdir(parents=True, exist_ok=True)
    # Prevent path traversal
    safe_name = email_sha256.replace("/", "").replace("\\", "").replace("..", "")
    return vault_month_dir / f"{safe_name}.enc"


def encrypt_and_store(raw_bytes: bytes, email_sha256: str) -> Path:
    """Encrypt raw email bytes and store in the vault.

    Returns the path to the encrypted file.
    """
    f = _get_fernet()
    encrypted = f.encrypt(raw_bytes)

    path = _vault_path(email_sha256)
    path.write_bytes(encrypted)

    print(f"[VAULT] Encrypted and stored: {path.name} ({len(raw_bytes)} → {len(encrypted)} bytes)")
    return path


def decrypt_and_retrieve(email_sha256: str) -> bytes | None:
    """Decrypt and return the raw email bytes from the vault.

    Returns None if the file is not found.
    Raises InvalidToken if the key doesn't match.
    """
    # Search across all month directories
    for month_dir in sorted(VAULT_DIR.iterdir()) if VAULT_DIR.exists() else []:
        if not month_dir.is_dir():
            continue
        safe_name = email_sha256.replace("/", "").replace("\\", "").replace("..", "")
        candidate = month_dir / f"{safe_name}.enc"
        if candidate.exists():
            f = _get_fernet()
            encrypted = candidate.read_bytes()
            return f.decrypt(encrypted)

    return None


def list_quarantined() -> list[dict]:
    """List all quarantined email IDs with metadata."""
    results = []
    if not VAULT_DIR.exists():
        return results

    for month_dir in sorted(VAULT_DIR.iterdir()):
        if not month_dir.is_dir():
            continue
        for enc_file in month_dir.glob("*.enc"):
            results.append({
                "email_sha256": enc_file.stem,
                "month": month_dir.name,
                "size_bytes": enc_file.stat().st_size,
                "stored_at": datetime.fromtimestamp(
                    enc_file.stat().st_mtime, tz=timezone.utc
                ).isoformat(),
            })
    return results


def delete_from_vault(email_sha256: str) -> bool:
    """Permanently delete a quarantined email from the vault."""
    if not VAULT_DIR.exists():
        return False

    safe_name = email_sha256.replace("/", "").replace("\\", "").replace("..", "")
    for month_dir in VAULT_DIR.iterdir():
        if not month_dir.is_dir():
            continue
        candidate = month_dir / f"{safe_name}.enc"
        if candidate.exists():
            candidate.unlink()
            print(f"[VAULT] Deleted: {candidate}")
            return True
    return False
