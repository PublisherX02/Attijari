"""migrate_data.py — One-time migration from JSON ledger + text blocklist to PostgreSQL.

Reads:
  - data/processed_ledger.json  → emails table
  - data/blocked_senders.txt    → blocklist table

Idempotent — safe to run multiple times. Existing records are skipped.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from email.utils import parseaddr

# Ensure src/ is on path
_SRC_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SRC_DIR))

from database import (
    init_db,
    SessionLocal,
    Email,
    Blocklist,
    get_cached_email,
    utcnow,
)
from validators import is_valid_ip, is_valid_sha256

_PROJECT_ROOT = _SRC_DIR.parent
_LEDGER_PATH = _PROJECT_ROOT / "data" / "processed_ledger.json"
_BLOCKLIST_PATH = _PROJECT_ROOT / "data" / "blocked_senders.txt"

# Hardcoded seed blocklist from rules.py
_SEED_BLOCKLIST = {"malware-site.com", "phishing-test.xyz"}


def migrate_ledger():
    """Migrate processed_ledger.json into the emails table."""
    if not _LEDGER_PATH.exists():
        print("[MIGRATE] No ledger file found — skipping email migration.")
        return 0

    with open(_LEDGER_PATH, "r", encoding="utf-8") as f:
        ledger = json.load(f)

    if isinstance(ledger, list):
        # Old format: list of keys
        ledger = {k: {"status": "recu"} for k in ledger}

    db = SessionLocal()
    migrated = 0
    skipped = 0

    try:
        for idem_key, record in ledger.items():
            # Skip if already in DB
            if get_cached_email(db, idem_key):
                skipped += 1
                continue

            sender = record.get("from", "")
            _, addr = parseaddr(sender) if sender else ("", "")
            sender_domain = None
            if addr and "@" in addr:
                sender_domain = addr.split("@")[-1].strip().lower()

            email = Email(
                idempotency_key=idem_key,
                raw_sha256=idem_key,  # best guess — original key was SHA-based
                sender=sender,
                sender_domain=sender_domain,
                subject=record.get("subject"),
                attachment_count=record.get("attachments", 0),
                status="recu" if record.get("status") == "continuer" else record.get("status", "recu"),
                parse_errors=record.get("parse_errors"),
            )

            # Try to parse the processed_at timestamp
            pat = record.get("processed_at")
            if pat:
                try:
                    from datetime import datetime, timezone
                    email.created_at = datetime.fromisoformat(pat).replace(tzinfo=timezone.utc)
                except (ValueError, TypeError):
                    pass

            db.add(email)
            migrated += 1

        db.commit()
        print(f"[MIGRATE] Emails: {migrated} migrated, {skipped} already existed.")
    except Exception as e:
        db.rollback()
        print(f"[MIGRATE] ERROR migrating emails: {e}")
        raise
    finally:
        db.close()

    return migrated


def migrate_blocklist():
    """Migrate blocked_senders.txt + seed list into the blocklist table."""
    entries: set[str] = set(_SEED_BLOCKLIST)

    if _BLOCKLIST_PATH.exists():
        try:
            lines = _BLOCKLIST_PATH.read_text(encoding="utf-8").splitlines()
            for line in lines:
                val = line.strip().lower()
                if val:
                    entries.add(val)
        except Exception as e:
            print(f"[MIGRATE] WARNING reading blocklist file: {e}")

    db = SessionLocal()
    migrated = 0
    skipped = 0

    try:
        for entry in entries:
            # Determine type
            if "@" in entry:
                indicator_type = "email"
            elif is_valid_sha256(entry):
                indicator_type = "hash"
            elif is_valid_ip(entry):
                indicator_type = "ip"
            else:
                indicator_type = "domain"

            existing = db.query(Blocklist).filter(
                Blocklist.indicator_type == indicator_type,
                Blocklist.value == entry,
            ).first()

            if existing:
                skipped += 1
                continue

            bl = Blocklist(
                indicator_type=indicator_type,
                value=entry,
                source="auto",
                active=True,
            )
            db.add(bl)
            migrated += 1

        db.commit()
        print(f"[MIGRATE] Blocklist: {migrated} migrated, {skipped} already existed.")
    except Exception as e:
        db.rollback()
        print(f"[MIGRATE] ERROR migrating blocklist: {e}")
        raise
    finally:
        db.close()

    return migrated


def main():
    print("=" * 50)
    print("[MIGRATE] Initializing database...")
    init_db()

    print("[MIGRATE] Migrating email ledger...")
    migrate_ledger()

    print("[MIGRATE] Migrating blocklist...")
    migrate_blocklist()

    print("[MIGRATE] Migration complete.")
    print("=" * 50)


if __name__ == "__main__":
    main()
