import os
import shutil
import asyncio
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

_SRC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SRC_DIR))

from database import SessionLocal, Email, AuditLog, AnalystFeedback, Report
from vault import _get_fernet

def get_db_generator():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def data_retention_and_backup_task():
    """Runs daily to purge data older than 90 days and take an encrypted pg_dump backup (NIST CP-9)."""
    await asyncio.sleep(60) # delay on startup
    while True:
        try:
            print("[ISO 27001] Running daily data retention and backup job...")
            
            # 1. Retention Purge
            cutoff = datetime.now(timezone.utc) - timedelta(days=90)
            db = next(get_db_generator())
            
            # Delete old logs/feedback/reports first
            db.query(AuditLog).filter(AuditLog.created_at < cutoff).delete()
            db.query(AnalystFeedback).filter(AnalystFeedback.created_at < cutoff).delete()
            db.query(Report).filter(Report.created_at < cutoff).delete()
            
            # Find and delete old emails + physical files
            old_emails = db.query(Email).filter(Email.email_date < cutoff).all()
            for e in old_emails:
                try:
                    base_name = e.idempotency_key
                    eml_path = os.path.join(_SRC_DIR.parent, "data", "archive", f"{base_name}.eml")
                    if os.path.exists(eml_path):
                        os.remove(eml_path)
                    vault_path = os.path.join(_SRC_DIR.parent, "data", "quarantine_vault", f"{base_name}.enc")
                    if os.path.exists(vault_path):
                        os.remove(vault_path)
                except Exception as ex:
                    print(f"Error deleting physical files for {e.id}: {ex}")
            
            db.query(Email).filter(Email.email_date < cutoff).delete()
            db.commit()
            print(f"[ISO 27001] Purged {len(old_emails)} records older than 90 days.")
            
            # 2. Database Backup (Encrypted & Offsite for NIST CP-9)
            backup_dir = os.path.join(_SRC_DIR.parent, "data", "backups", "offsite_vault")
            os.makedirs(backup_dir, exist_ok=True)
            
            filename_base = f"attijari_db_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            backup_file = os.path.join(backup_dir, f"{filename_base}.sql")
            encrypted_file = os.path.join(backup_dir, f"{filename_base}.enc")
            
            try:
                # Parse credentials from DATABASE_URL instead of hardcoding
                from urllib.parse import urlparse
                db_url = os.getenv("DATABASE_URL", "")
                parsed_url = urlparse(db_url)
                pg_user = parsed_url.username or "postgres"
                pg_pass = parsed_url.password or ""
                pg_host = parsed_url.hostname or "localhost"
                pg_db = parsed_url.path.lstrip("/") or "attijari_db"

                env = os.environ.copy()
                env["PGPASSWORD"] = pg_pass
                subprocess.run(
                    ["pg_dump", "-U", pg_user, "-h", pg_host, "-d", pg_db, "-f", backup_file],
                    env=env, check=True, capture_output=True
                )
                
                # NIST CP-9: Encrypt the backup
                with open(backup_file, "rb") as f:
                    raw_data = f.read()
                
                fernet = _get_fernet()
                encrypted_data = fernet.encrypt(raw_data)
                
                with open(encrypted_file, "wb") as f:
                    f.write(encrypted_data)
                
                # Safely remove plaintext SQL dump
                os.remove(backup_file)
                
                print(f"[NIST CP-9] Secure off-site backup successful: {encrypted_file}")
            except FileNotFoundError:
                print("[ISO 27001] WARNING: pg_dump not found in PATH. Backup skipped.")
            except subprocess.CalledProcessError as e:
                print(f"[ISO 27001] Backup failed: {e.stderr.decode()}")
                
        except Exception as e:
            print(f"[ISO 27001] Retention/Backup task error: {e}")
            
        await asyncio.sleep(86400) # sleep 24 hours
