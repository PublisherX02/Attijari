"""routing.py — Email Routing & Action Engine.

Implements the actual Release / Quarantine / Auto-route actions:
  - release_email():    move accepted email back to INBOX
  - quarantine_email(): encrypt into vault, cascade blocklist
  - auto_route():       decide action based on pipeline verdict + confidence
"""
from __future__ import annotations

import os
import imaplib
import ssl
from email.utils import parseaddr
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from database import (
    SessionLocal,
    Email,
    add_audit_entry,
    add_blocklist_entry,
    is_whitelisted,
)
from vault import encrypt_and_store
from validators import is_valid_domain, is_valid_sha256

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_EMAILS_DIR = _PROJECT_ROOT / "data" / "raw_emails"

# Minimum confidence for auto-release (without analyst review)
AUTO_RELEASE_CONFIDENCE = float(os.getenv("AUTO_RELEASE_CONFIDENCE", "0.85"))


def release_email(email_id: int, actor: str = "analyst") -> dict:
    """Release an accepted email — mark as released in DB + audit.

    In a real deployment this would IMAP-COPY the email back to INBOX.
    For the POC, we update the status and log the action.
    """
    db = SessionLocal()
    try:
        email = db.query(Email).filter(Email.id == email_id).first()
        if not email:
            return {"success": False, "error": "email_not_found"}

        if email.status not in ("accepted", "escalated", "recu"):
            return {"success": False, "error": f"cannot_release_from_{email.status}"}

        email.status = "released"
        email.analyst_action = "release"
        add_audit_entry(
            db, action="release", actor=actor,
            email_id=email.id,
            details={"previous_status": email.status},
        )
        db.commit()

        print(f"[ROUTING] Released email {email.id}: {email.subject}")
        return {"success": True, "email_id": email.id, "status": "released"}
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def quarantine_email(email_id: int, actor: str = "analyst",
                     cascade_block: bool = True) -> dict:
    """Quarantine an escalated email — encrypt into vault + cascade blocklist.

    Steps:
      1. Read raw .eml from data/raw_emails/
      2. Encrypt and store in vault
      3. Update status to 'quarantined'
      4. Cascade blocklist: block sender email, domain, IPs, hashes
      5. Audit log
    """
    db = SessionLocal()
    try:
        email = db.query(Email).filter(Email.id == email_id).first()
        if not email:
            return {"success": False, "error": "email_not_found"}

        if email.status == "quarantined":
            return {"success": False, "error": "already_quarantined"}

        prev_status = email.status

        # Step 1: Find raw .eml file
        raw_path = RAW_EMAILS_DIR / f"{email.raw_sha256}.eml"
        vault_path = None

        if raw_path.exists():
            # Step 2: Encrypt into vault
            raw_bytes = raw_path.read_bytes()
            try:
                vault_path = encrypt_and_store(raw_bytes, email.raw_sha256)
            except RuntimeError as e:
                print(f"[ROUTING] Vault encryption skipped: {e}")
                # Continue with quarantine even if vault fails (fail-safe)
        else:
            print(f"[ROUTING] Raw email file not found: {raw_path} — quarantining without vault")

        # Step 3: Update status
        email.status = "quarantined"
        email.analyst_action = "quarantine"

        # Step 4: Cascade blocklist
        blocked_indicators = []
        if cascade_block and email.sender:
            _, sender_addr = parseaddr(email.sender)
            if sender_addr:
                # Block sender email
                if not is_whitelisted(db, "email", sender_addr):
                    if add_blocklist_entry(db, "email", sender_addr, source="cascade", confirmed_by=actor):
                        blocked_indicators.append(f"email:{sender_addr}")

                # Block sender domain
                if "@" in sender_addr:
                    domain = sender_addr.split("@")[-1].strip().lower()
                    if is_valid_domain(domain) and not is_whitelisted(db, "domain", domain):
                        if add_blocklist_entry(db, "domain", domain, source="cascade", confirmed_by=actor):
                            blocked_indicators.append(f"domain:{domain}")

            # Block attachment hashes from enrichment data
            enr = email.enrichment_result or {}
            for att_hash in _extract_hashes(enr):
                if is_valid_sha256(att_hash):
                    if add_blocklist_entry(db, "hash", att_hash, source="cascade", confirmed_by=actor):
                        blocked_indicators.append(f"hash:{att_hash[:12]}...")

        # Step 5: IMAP move to Spam
        imap_moved = False
        if email.message_id:
            try:
                ctx = ssl.create_default_context()
                conn = imaplib.IMAP4_SSL(os.getenv("IMAP_HOST"), ssl_context=ctx)
                conn.login(os.getenv("IMAP_USER"), os.getenv("IMAP_PASSWORD"))
                conn.select("INBOX")
                typ, data = conn.search(None, f'(HEADER Message-ID "{email.message_id}")')
                if data and data[0]:
                    for uid in data[0].split():
                        conn.copy(uid, "[Gmail]/Spam")
                        conn.store(uid, '+FLAGS', '\\Deleted')
                    conn.expunge()
                    imap_moved = True
                    print(f"[IMAP] Moved message {email.message_id} to Spam")
                conn.logout()
            except Exception as e:
                print(f"[IMAP] Error moving message to Spam: {e}")

        # Step 6: Audit
        add_audit_entry(
            db, action="quarantine", actor=actor,
            email_id=email.id,
            details={
                "previous_status": prev_status,
                "vault_path": str(vault_path) if vault_path else None,
                "blocked_indicators": blocked_indicators,
                "imap_moved": imap_moved,
            },
        )
        db.commit()

        print(f"[ROUTING] Quarantined email {email.id}: {email.subject}")
        if blocked_indicators:
            print(f"[ROUTING] Cascade blocked: {', '.join(blocked_indicators)}")

        return {
            "success": True,
            "email_id": email.id,
            "status": "quarantined",
            "blocked": blocked_indicators,
        }
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def override_verdict(email_id: int, new_status: str, actor: str = "analyst",
                     notes: str = "") -> dict:
    """Analyst overrides the pipeline verdict with notes."""
    if new_status not in ("accepted", "escalated", "released", "quarantined"):
        return {"success": False, "error": f"invalid_status: {new_status}"}

    db = SessionLocal()
    try:
        email = db.query(Email).filter(Email.id == email_id).first()
        if not email:
            return {"success": False, "error": "email_not_found"}

        prev_status = email.status
        email.status = new_status
        email.analyst_action = "override"
        email.analyst_notes = notes

        add_audit_entry(
            db, action="override", actor=actor,
            email_id=email.id,
            details={
                "previous_status": prev_status,
                "new_status": new_status,
                "notes": notes,
            },
        )
        db.commit()

        print(f"[ROUTING] Override email {email.id}: {prev_status} → {new_status}")
        return {"success": True, "email_id": email.id, "status": new_status}
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def auto_route(parsed: dict) -> str:
    """Decide the action after pipeline analysis.

    Returns the final status: 'accepted', 'escalated', 'released', or 'quarantined'.

    Logic:
      - escalated → auto-quarantine
      - accepted AND high confidence → auto-release
      - otherwise → leave for analyst review
    """
    status = parsed.get("status", "recu")

    # Extract LLM confidence
    llm = parsed.get("llm_analysis") or {}
    confidence = float(llm.get("confiance", llm.get("confidence", 0.0)))

    if status == "escalated":
        # Auto-quarantine escalated emails
        return "escalated"  # quarantine happens via routing after DB save

    if status == "accepted" and confidence >= AUTO_RELEASE_CONFIDENCE:
        return "accepted"  # auto-release happens via routing after DB save

    # Low confidence or ambiguous — leave for analyst
    return status


def _extract_hashes(enrichment: dict) -> list[str]:
    """Extract attachment SHA-256 hashes from enrichment data for cascading blocks."""
    hashes = []
    # From VirusTotal results
    for vt in enrichment.get("virustotal", []):
        if isinstance(vt, dict) and vt.get("sha256"):
            hashes.append(vt["sha256"])
    # From ThreatFox results
    for tf in enrichment.get("threatfox", []):
        if isinstance(tf, dict) and tf.get("indicator_type") == "hash":
            ind = tf.get("indicator") or tf.get("search_term")
            if ind:
                hashes.append(ind)
    return hashes
