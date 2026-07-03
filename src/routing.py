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
    AuditLog,
    Blocklist,
    Whitelist,
    add_audit_entry,
    add_blocklist_entry,
    is_blocked,
    is_whitelisted,
    save_feedback,
)
from vault import encrypt_and_store
from validators import is_valid_domain, is_valid_sha256
from rules import is_shared_email_domain

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_EMAILS_DIR = _PROJECT_ROOT / "data" / "raw_emails"

# Minimum confidence for auto-release (without analyst review)
AUTO_RELEASE_CONFIDENCE = float(os.getenv("AUTO_RELEASE_CONFIDENCE", "0.85"))


def release_email(email_id: int, actor: str = "analyst",
                   reason: str = "") -> dict:
    """Release an email — mark as released, whitelist domain, store feedback.

    When an analyst releases an escalated email (false positive):
      1. Mark email as released
      2. Auto-whitelist the sender domain so future emails pass
      3. Store analyst reasoning as feedback for pipeline learning
    """
    db = SessionLocal()
    try:
        email = db.query(Email).filter(Email.id == email_id).first()
        if not email:
            return {"success": False, "error": "email_not_found"}

        if email.status not in ("accepted", "escalated", "recu"):
            return {"success": False, "error": f"cannot_release_from_{email.status}"}

        prev_status = email.status
        email.status = "released"
        email.analyst_action = "release"
        email.analyst_notes = reason or None

        # Auto-whitelist sender domain on release (reward signal).
        # Guard: if the domain is already blocklisted (from a different confirmed
        # malicious sender on the same domain), do NOT whitelist the domain — that
        # would defeat the blocklist for every other sender on evil.com.
        # Instead, whitelist only the specific sender email address.
        whitelisted_domain = None
        whitelisted_email = None
        if email.sender_domain:
            domain = email.sender_domain.strip().lower()
            if is_valid_domain(domain):
                if is_blocked(db, "domain", domain):
                    # Domain is blocklisted — only whitelist the specific sender
                    print(
                        f"[ROUTING] Domain {domain} is blocklisted — "
                        f"whitelisting sender {email.sender} only (not domain)"
                    )
                    _, sender_addr = parseaddr(email.sender or "")
                    if sender_addr:
                        sender_addr = sender_addr.strip().lower()
                        existing_email = db.query(Whitelist).filter(
                            Whitelist.indicator_type == "email",
                            Whitelist.value == sender_addr,
                        ).first()
                        if existing_email:
                            if not existing_email.active:
                                existing_email.active = True
                                existing_email.reason = (
                                    f"Auto-whitelisted sender on release (domain blocklisted): {reason}"
                                    if reason else
                                    "Auto-whitelisted sender on release (domain blocklisted)"
                                )
                                whitelisted_email = sender_addr
                        else:
                            db.add(Whitelist(
                                indicator_type="email",
                                value=sender_addr,
                                reason=(
                                    f"Auto-whitelisted sender on release (domain blocklisted): {reason}"
                                    if reason else
                                    "Auto-whitelisted sender on release (domain blocklisted)"
                                ),
                                created_by=actor,
                            ))
                            whitelisted_email = sender_addr
                        if whitelisted_email:
                            print(f"[ROUTING] Auto-whitelisted email: {whitelisted_email}")
                else:
                    # Domain is not blocklisted — safe to whitelist the whole domain
                    existing = db.query(Whitelist).filter(
                        Whitelist.indicator_type == "domain",
                        Whitelist.value == domain,
                    ).first()
                    if existing:
                        if not existing.active:
                            existing.active = True
                            existing.reason = (
                                f"Auto-whitelisted on release: {reason}"
                                if reason else "Auto-whitelisted on analyst release"
                            )
                            whitelisted_domain = domain
                    else:
                        db.add(Whitelist(
                            indicator_type="domain",
                            value=domain,
                            reason=(
                                f"Auto-whitelisted on release: {reason}"
                                if reason else "Auto-whitelisted on analyst release"
                            ),
                            created_by=actor,
                        ))
                        whitelisted_domain = domain
                    if whitelisted_domain:
                        print(f"[ROUTING] Auto-whitelisted domain: {whitelisted_domain}")

        # Save analyst feedback for pipeline learning
        whitelisted_indicator = whitelisted_domain or whitelisted_email
        if reason:
            save_feedback(
                db, email_id=email.id, action="release",
                reasoning=reason, pipeline_verdict=prev_status,
                domain=email.sender_domain,
                indicator_type="whitelist" if whitelisted_indicator else None,
                indicator_value=whitelisted_indicator,
            )

        add_audit_entry(
            db, action="release", actor=actor,
            email_id=email.id,
            details={
                "previous_status": prev_status,
                "reason": reason,
                "whitelisted_domain": whitelisted_domain,
                "whitelisted_email": whitelisted_email,
            },
        )
        db.commit()

        print(f"[ROUTING] Released email {email.id}: {email.subject}")
        return {
            "success": True,
            "email_id": email.id,
            "status": "released",
            "whitelisted_domain": whitelisted_domain,
            "whitelisted_email": whitelisted_email,
        }
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def quarantine_email(email_id: int, actor: str = "analyst",
                     cascade_block: bool = True, reason: str = "") -> dict:
    """Quarantine an email — encrypt into vault + cascade blocklist + store feedback.

    Steps:
      1. Read raw .eml from data/raw_emails/
      2. Encrypt and store in vault
      3. Update status to 'quarantined'
      4. Cascade blocklist: block sender email, domain, IPs, hashes
      5. Move to Gmail Spam via IMAP
      6. Store analyst feedback for pipeline learning
      7. Audit log
    """
    db = SessionLocal()
    try:
        email = db.query(Email).filter(Email.id == email_id).first()
        if not email:
            return {"success": False, "error": "email_not_found"}

        if email.status == "quarantined":
            return {"success": False, "error": "already_quarantined"}

        prev_status = email.status
        email.analyst_notes = reason or None

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
        # Auto-cascade entries use ttl_days=90 so they self-expire if never
        # re-confirmed. Manually added entries (via API) keep the analyst's choice.
        _CASCADE_TTL = 90
        blocked_indicators = []
        if cascade_block and email.sender:
            _, sender_addr = parseaddr(email.sender)
            if sender_addr:
                # Block sender email
                if not is_whitelisted(db, "email", sender_addr):
                    if add_blocklist_entry(db, "email", sender_addr, source="cascade",
                                           confirmed_by=actor, ttl_days=_CASCADE_TTL):
                        blocked_indicators.append(f"email:{sender_addr}")

                # Block sender domain — but NOT shared/multi-tenant domains
                # (gmail.com, outlook.com, universities, etc.) where blocking
                # the domain would block ALL users, not just the attacker.
                if "@" in sender_addr:
                    domain = sender_addr.split("@")[-1].strip().lower()
                    if is_shared_email_domain(domain):
                        print(f"[CASCADE] Skipped domain {domain} — shared provider (blocked sender only)")
                    elif is_valid_domain(domain) and not is_whitelisted(db, "domain", domain):
                        if add_blocklist_entry(db, "domain", domain, source="cascade",
                                               confirmed_by=actor, ttl_days=_CASCADE_TTL):
                            blocked_indicators.append(f"domain:{domain}")

            # Block attachment hashes from enrichment data
            enr = email.enrichment_result or {}
            for att_hash in _extract_hashes(enr):
                if is_valid_sha256(att_hash):
                    if add_blocklist_entry(db, "hash", att_hash, source="cascade",
                                           confirmed_by=actor, ttl_days=_CASCADE_TTL):
                        blocked_indicators.append(f"hash:{att_hash[:12]}...")

        # Step 5: IMAP move to Spam
        imap_moved = False
        if email.message_id:
            imap_moved = _imap_move_to_spam(email.message_id)

        # Step 6: Store analyst feedback for pipeline learning
        if reason:
            save_feedback(
                db, email_id=email.id, action="quarantine",
                reasoning=reason, pipeline_verdict=prev_status,
                domain=email.sender_domain,
                indicator_type="blocklist",
                indicator_value=email.sender_domain,
            )

        # Step 7: Audit
        add_audit_entry(
            db, action="quarantine", actor=actor,
            email_id=email.id,
            details={
                "previous_status": prev_status,
                "reason": reason,
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


def revert_action(email_id: int, actor: str = "analyst") -> dict:
    """Revert the last analyst action (quarantine or release) on an email.

    Restores the email to 'escalated' status so the analyst can re-review.
    For quarantine reverts: deactivates blocklist entries created during that
    quarantine (read from the audit log's blocked_indicators field).
    For release reverts: deactivates the auto-whitelisted domain if one was
    added during that release action.
    Always adds an audit entry recording the revert.
    """
    db = SessionLocal()
    try:
        email = db.query(Email).filter(Email.id == email_id).first()
        if not email:
            return {"success": False, "error": "email_not_found"}

        if email.analyst_action not in ("quarantine", "release"):
            return {"success": False, "error": "no_revertible_action"}

        prev_action = email.analyst_action

        # Find the most recent audit entry for this action on this email
        audit_entry = (
            db.query(AuditLog)
            .filter(
                AuditLog.email_id == email_id,
                AuditLog.action == prev_action,
            )
            .order_by(AuditLog.created_at.desc())
            .first()
        )

        reverted_indicators: list[str] = []
        reverted_whitelist: str | None = None

        if prev_action == "quarantine":
            reverted_indicators = _revert_quarantine_blocklist(db, audit_entry)
        elif prev_action == "release":
            reverted_whitelist = _revert_release_whitelist(db, audit_entry)

        email.status = "escalated"
        email.analyst_action = None
        email.analyst_notes = None

        add_audit_entry(
            db, action="revert", actor=actor,
            email_id=email.id,
            details={
                "reverted_action": prev_action,
                "unblocked_indicators": reverted_indicators,
                "removed_whitelist_domain": reverted_whitelist,
            },
        )
        db.commit()

        print(f"[ROUTING] Reverted {prev_action} on email {email.id}")
        return {
            "success": True,
            "email_id": email.id,
            "status": "escalated",
            "reverted_action": prev_action,
            "unblocked_indicators": reverted_indicators,
            "removed_whitelist_domain": reverted_whitelist,
        }
    except Exception as e:
        db.rollback()
        return {"success": False, "error": str(e)}
    finally:
        db.close()


def _revert_quarantine_blocklist(db, audit_entry) -> list[str]:
    """Deactivate blocklist entries that were created by the given quarantine audit entry.

    Reads the blocked_indicators list from the audit log details. Each entry
    has the format "type:value" (e.g. "email:bad@evil.com", "domain:evil.com").
    Only deactivates entries whose source is 'cascade' to avoid touching
    manually-added entries that happen to share the same indicator.
    """
    if not audit_entry:
        return []

    details = audit_entry.details or {}
    blocked = details.get("blocked_indicators", [])
    removed: list[str] = []

    for indicator in blocked:
        if ":" not in indicator:
            continue
        itype, _, ivalue = indicator.partition(":")
        # Strip truncation marker added for hash display ("abc123..." → skip)
        if ivalue.endswith("..."):
            continue
        entry = db.query(Blocklist).filter(
            Blocklist.indicator_type == itype,
            Blocklist.value == ivalue,
            Blocklist.source == "cascade",
            Blocklist.active == True,
        ).first()
        if entry:
            entry.active = False
            removed.append(indicator)

    return removed


def _revert_release_whitelist(db, audit_entry) -> str | None:
    """Deactivate the auto-whitelisted domain added during a release action.

    Reads the whitelisted_domain from the audit log details and deactivates
    that whitelist entry only if it was auto-created (reason starts with
    'Auto-whitelisted on release').
    """
    if not audit_entry:
        return None

    details = audit_entry.details or {}
    domain = details.get("whitelisted_domain")
    if not domain:
        return None

    entry = db.query(Whitelist).filter(
        Whitelist.indicator_type == "domain",
        Whitelist.value == domain,
        Whitelist.active == True,
    ).first()

    if entry and entry.reason and entry.reason.startswith("Auto-whitelisted on release"):
        entry.active = False
        return domain

    return None


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


def _imap_move_to_spam(message_id: str) -> bool:
    """Move an email to Gmail Spam + AI_TRIAGE_SYSTEM label via IMAP.

    Tested against imap.gmail.com. Uses UID operations for reliability.
    """
    imap_host = os.getenv("IMAP_HOST")
    imap_user = os.getenv("IMAP_USER")
    imap_pass = os.getenv("IMAP_PASSWORD")

    if not all([imap_host, imap_user, imap_pass]):
        print("[IMAP] Missing IMAP credentials — skipping spam move")
        return False

    # Clean message_id
    mid = message_id.strip()

    conn = None
    try:
        ctx = ssl.create_default_context()
        conn = imaplib.IMAP4_SSL(imap_host, ssl_context=ctx)
        conn.login(imap_user, imap_pass)
        conn.select("INBOX")

        # Search by Message-ID using UID
        typ, data = conn.uid("search", None, f'HEADER Message-ID "{mid}"')
        print(f"[IMAP] UID search for {mid[:60]}... → {typ} uids={data}")

        if typ != "OK" or not data or not data[0] or not data[0].strip():
            print(f"[IMAP] Message not found in INBOX — may already be moved/deleted")
            conn.close()
            conn.logout()
            return False

        uids = data[0].split()
        print(f"[IMAP] Found {len(uids)} UID(s): {[u.decode() for u in uids]}")

        moved = False
        for uid in uids:
            # Copy to AI_TRIAGE_SYSTEM label
            typ1, _ = conn.uid("copy", uid, "AI_TRIAGE_SYSTEM")
            print(f"[IMAP] UID {uid.decode()} → AI_TRIAGE_SYSTEM: {typ1}")

            # Copy to Spam
            typ2, _ = conn.uid("copy", uid, "[Gmail]/Spam")
            print(f"[IMAP] UID {uid.decode()} → [Gmail]/Spam: {typ2}")

            if typ2 == "OK":
                # Mark deleted from inbox
                conn.uid("store", uid, "+FLAGS", "(\\Deleted)")
                moved = True

        conn.expunge()
        conn.close()
        conn.logout()
        conn = None

        if moved:
            print(f"[IMAP] Done — message in Spam + AI_TRIAGE_SYSTEM")
        return moved

    except Exception as e:
        print(f"[IMAP] Error: {e}")
        return False
    finally:
        if conn:
            try:
                conn.logout()
            except Exception:
                pass


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
