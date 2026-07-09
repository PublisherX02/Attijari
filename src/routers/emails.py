from typing import Optional
import asyncio
import csv
import io
import time
from fastapi import APIRouter, Query, HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import text
from database import (
    SessionLocal, Email, AuditLog, Alert, Blocklist, Whitelist, Report, AnalystFeedback,
    add_blocklist_entry, get_blocked_set, is_blocked, is_whitelisted, add_audit_entry, utcnow,
)
from routing import release_email, quarantine_email, override_verdict, revert_action
from rules import is_shared_email_domain
from reporting import generate_report
from fastapi import Depends
from api_core import ws_manager, mask_pii, verify_auth, require_permission, AuthenticatedUser
from metrics import db_connected, ollama_available, get_metrics_text

emails_router = APIRouter()
_scan_lock = asyncio.Lock()


def _update_gauge_metrics():
    """Refresh Prometheus gauge metrics from current DB state."""
    try:
        db = SessionLocal()
        from metrics import blocklist_size, emails_in_queue
        for itype in ("email", "domain", "ip", "hash"):
            count = db.query(Blocklist).filter(
                Blocklist.active == True, Blocklist.indicator_type == itype
            ).count()
            blocklist_size.labels(indicator_type=itype).set(count)
        pending = db.query(Email).filter(
            Email.status.in_(["escalated", "recu", "pending"])
        ).count()
        emails_in_queue.set(pending)
        db.close()
    except Exception:
        pass  # metrics are best-effort, never crash the request

def _run_pipeline_sync():
    try:
        from main import run_pipeline
        run_pipeline()
    except Exception as e:
        print(f"[POLL] Pipeline failed: {e}")

from enum import Enum as PyEnum
from pydantic import Field

class IndicatorType(str, PyEnum):
    email = "email"
    domain = "domain"
    ip = "ip"
    hash = "hash"

class BlocklistAddRequest(BaseModel):
    indicator_type: IndicatorType
    value: str = Field(..., min_length=1, max_length=512)
    reason: str = Field(default="", max_length=1000)
    # Optional TTL in days. NULL (default) means never expires.
    # Analyst-added entries keep no expiration for backward compatibility.
    ttl_days: Optional[int] = Field(default=None, ge=1, le=3650)

class WhitelistAddRequest(BaseModel):
    indicator_type: IndicatorType
    value: str = Field(..., min_length=1, max_length=512)
    reason: str = Field(default="", max_length=1000)

class ActionRequest(BaseModel):
    reason: str = Field(default="", max_length=1000)

class BulkActionRequest(BaseModel):
    email_ids: list[int] = Field(..., min_length=1, max_length=200)
    reason: str = Field(default="", max_length=1000)

class VerdictStatus(str, PyEnum):
    accepted = "accepted"
    escalated = "escalated"
    released = "released"
    quarantined = "quarantined"

class OverrideRequest(BaseModel):
    status: VerdictStatus
    notes: str = Field(default="", max_length=1000)


# ---------------------------------------------------------------------------
# Manual scan trigger
# ---------------------------------------------------------------------------

@emails_router.post("/api/scan")
async def api_trigger_scan(user: AuthenticatedUser = Depends(require_permission("emails.scan"))):
    """Manually trigger an IMAP poll + analysis pipeline run."""
    # Atomic check-and-acquire: try to get lock without racing
    if _scan_lock.locked():
        return {"success": False, "message": "Scan already in progress"}

    async def _run_scan():
        if not _scan_lock.locked():
            async with _scan_lock:
                try:
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(None, _run_pipeline_sync)
                    await ws_manager.broadcast("refresh")
                except Exception as e:
                    print(f"[SCAN] Manual scan failed: {e}")

    asyncio.create_task(_run_scan())
    return {"success": True, "message": "Scan started"}


# REST API — Email management
# ---------------------------------------------------------------------------

@emails_router.get("/api/emails")
async def api_list_emails(
    status: Optional[str] = Query(None, max_length=20),
    search: Optional[str] = Query(None, max_length=200),
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    user: AuthenticatedUser = Depends(require_permission("emails.view")),
):
    """List processed emails with pagination and filters."""
    db = SessionLocal()
    try:
        q = db.query(
            Email.id,
            Email.sender,
            Email.sender_domain,
            Email.subject,
            Email.status,
            Email.attachment_count,
            Email.analyst_action,
            Email.email_date,
            Email.created_at
        ).order_by(Email.email_date.desc().nullslast(), Email.created_at.desc())

        if status:
            q = q.filter(Email.status == status)
        if search:
            # Escape SQL LIKE wildcards to prevent pattern injection / DoS
            safe_search = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            term = f"%{safe_search}%"
            q = q.filter(
                (Email.sender.ilike(term, escape="\\")) |
                (Email.subject.ilike(term, escape="\\")) |
                (Email.sender_domain.ilike(term, escape="\\"))
            )

        total = q.count()
        emails = q.offset((page - 1) * per_page).limit(per_page).all()

        return {
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
            "emails": [
                {
                    "id": e.id,
                    "sender": mask_pii(e.sender),
                    "sender_domain": e.sender_domain,
                    "subject": e.subject,
                    "status": e.status,
                    "attachment_count": e.attachment_count,
                    "analyst_action": e.analyst_action,
                    "email_date": e.email_date.isoformat() if e.email_date else None,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in emails
            ],
        }
    finally:
        db.close()


@emails_router.get("/api/emails/{email_id}")
async def api_get_email(email_id: int, user: AuthenticatedUser = Depends(require_permission("emails.view"))):
    """Get full email details including all analysis data."""
    db = SessionLocal()
    try:
        email = db.query(Email).filter(Email.id == email_id).first()
        if not email:
            raise HTTPException(404, "Email not found")

        # Get audit history for this email
        audit = db.query(AuditLog).filter(
            AuditLog.email_id == email_id
        ).order_by(AuditLog.created_at.desc()).all()

        # Check for whitelist/blocklist conflict on the sender domain so the
        # dashboard can warn the analyst when a released email's domain is also
        # blocklisted (meaning a different confirmed-malicious sender shared it).
        _d = (email.sender_domain or "").strip().lower()
        domain_in_blocklist = is_blocked(db, "domain", _d) if _d else False
        domain_in_whitelist = is_whitelisted(db, "domain", _d) if _d else False

        return {
            "id": email.id,
            "idempotency_key": email.idempotency_key,
            "message_id": email.message_id,
            "raw_sha256": email.raw_sha256,
            "sender": mask_pii(email.sender),
            "sender_domain": email.sender_domain,
            "subject": email.subject,
            "attachment_count": email.attachment_count,
            "status": email.status,
            "rules_result": email.rules_result,
            "enrichment_result": email.enrichment_result,
            "llm_result": email.llm_result,
            "llm_reasoning": email.llm_reasoning,
            "parse_errors": email.parse_errors,
            "analyst_action": email.analyst_action,
            "analyst_notes": email.analyst_notes,
            "email_date": email.email_date.isoformat() if email.email_date else None,
            "created_at": email.created_at.isoformat() if email.created_at else None,
            "updated_at": email.updated_at.isoformat() if email.updated_at else None,
            "domain_in_blocklist": domain_in_blocklist,
            "domain_in_whitelist": domain_in_whitelist,
            "audit_history": [
                {
                    "action": a.action,
                    "actor": a.actor,
                    "details": a.details,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                }
                for a in audit
            ],
        }
    finally:
        db.close()


@emails_router.post("/api/emails/{email_id}/release")
async def api_release_email(email_id: int, body: ActionRequest = None, user: AuthenticatedUser = Depends(require_permission("emails.release"))):
    """Release an email (analyst action). Auto-whitelists sender domain."""
    actor = str(user)
    reason = body.reason if body else ""
    result = release_email(email_id, actor=actor, reason=reason)
    _update_gauge_metrics()
    if not result["success"]:
        raise HTTPException(400, result["error"])
    return result


@emails_router.post("/api/emails/{email_id}/quarantine")
async def api_quarantine_email(email_id: int, body: ActionRequest = None, user: AuthenticatedUser = Depends(require_permission("emails.quarantine"))):
    """Quarantine an email with cascading blocklist + move to Gmail Spam."""
    actor = str(user)
    reason = body.reason if body else ""
    result = quarantine_email(email_id, actor=actor, reason=reason)
    _update_gauge_metrics()
    if not result["success"]:
        raise HTTPException(400, result["error"])
    return result


@emails_router.post("/api/emails/{email_id}/override")
async def api_override_email(email_id: int, body: OverrideRequest, user: AuthenticatedUser = Depends(require_permission("emails.override"))):
    """Override the pipeline verdict (analyst action with notes)."""
    actor = str(user)
    result = override_verdict(email_id, body.status, actor=actor, notes=body.notes)
    _update_gauge_metrics()
    if not result["success"]:
        raise HTTPException(400, result["error"])
    return result


@emails_router.post("/api/emails/{email_id}/revert")
async def api_revert_action(email_id: int, user: AuthenticatedUser = Depends(require_permission("emails.revert"))):
    """Revert the last analyst action (quarantine or release) on an email.

    Restores the email to 'escalated' status for re-review. If the original
    action was a quarantine, cascade-blocked indicators from that action are
    deactivated. If it was a release, the auto-whitelisted domain is removed.
    """
    actor = str(user)
    result = revert_action(email_id, actor=actor)
    _update_gauge_metrics()
    if not result["success"]:
        raise HTTPException(400, result["error"])
    return result


@emails_router.post("/api/emails/bulk/release")
async def api_bulk_release(body: BulkActionRequest, user: AuthenticatedUser = Depends(require_permission("emails.bulk"))):
    """Release multiple emails at once."""
    actor = str(user)
    results = []
    for email_id in body.email_ids:
        result = release_email(email_id, actor=actor, reason=body.reason)
        results.append({"email_id": email_id, "success": result["success"],
                        "error": result.get("error")})
    _update_gauge_metrics()
    succeeded = sum(1 for r in results if r["success"])
    return {"succeeded": succeeded, "failed": len(results) - succeeded, "results": results}


@emails_router.post("/api/emails/bulk/quarantine")
async def api_bulk_quarantine(body: BulkActionRequest, user: AuthenticatedUser = Depends(require_permission("emails.bulk"))):
    """Quarantine multiple emails at once."""
    actor = str(user)
    results = []
    for email_id in body.email_ids:
        result = quarantine_email(email_id, actor=actor, reason=body.reason)
        results.append({"email_id": email_id, "success": result["success"],
                        "error": result.get("error")})
    _update_gauge_metrics()
    succeeded = sum(1 for r in results if r["success"])
    return {"succeeded": succeeded, "failed": len(results) - succeeded, "results": results}


# ---------------------------------------------------------------------------
# REST API — Blocklist
# ---------------------------------------------------------------------------

@emails_router.get("/api/blocklist")
async def api_list_blocklist(
    indicator_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_permission("blocklist.view")),
):
    """List active blocklist entries."""
    db = SessionLocal()
    try:
        q = db.query(Blocklist).filter(Blocklist.active == True)
        if indicator_type:
            q = q.filter(Blocklist.indicator_type == indicator_type)

        total = q.count()
        entries = q.order_by(Blocklist.created_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()

        return {
            "total": total,
            "page": page,
            "entries": [
                {
                    "id": e.id,
                    "indicator_type": e.indicator_type,
                    "value": e.value,
                    "source": e.source,
                    "confirmed_by": e.confirmed_by,
                    "expires_at": e.expires_at.isoformat() if e.expires_at else None,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in entries
            ],
        }
    finally:
        db.close()


@emails_router.post("/api/blocklist")
async def api_add_blocklist(body: BlocklistAddRequest, user: AuthenticatedUser = Depends(require_permission("blocklist.manage"))):
    """Add an indicator to the blocklist.

    ttl_days is optional. Omit it (or pass null) for a permanent entry.
    Analyst-added entries default to no expiration for backward compatibility.
    """
    actor = str(user)
    if body.indicator_type == "domain" and is_shared_email_domain(body.value):
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{body.value}' is a shared multi-tenant domain. "
                "Blocking it would affect all users on that provider. "
                "Block the specific sender email address instead."
            ),
        )
    db = SessionLocal()
    try:
        added = add_blocklist_entry(
            db, body.indicator_type, body.value,
            source="manual", confirmed_by=actor,
            ttl_days=body.ttl_days,
        )
        if added:
            add_audit_entry(
                db, action="blocklist_add", actor=actor,
                details={
                    "indicator_type": body.indicator_type,
                    "value": body.value,
                    "reason": body.reason,
                    "ttl_days": body.ttl_days,
                },
            )
            _update_gauge_metrics()
            return {"success": True, "message": f"Added {body.indicator_type}:{body.value}"}
        return {"success": False, "message": "Already blocked or whitelisted"}
    finally:
        db.close()


@emails_router.delete("/api/blocklist/{entry_id}")
async def api_remove_blocklist(entry_id: int, user: AuthenticatedUser = Depends(require_permission("blocklist.manage"))):
    """Deactivate a blocklist entry."""
    actor = str(user)
    db = SessionLocal()
    try:
        entry = db.query(Blocklist).filter(Blocklist.id == entry_id).first()
        if not entry:
            raise HTTPException(404, "Blocklist entry not found")

        entry.active = False
        add_audit_entry(
            db, action="blocklist_remove", actor=actor,
            details={"indicator_type": entry.indicator_type, "value": entry.value},
        )
        db.commit()
        _update_gauge_metrics()
        return {"success": True, "message": f"Deactivated {entry.indicator_type}:{entry.value}"}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# REST API — Whitelist
# ---------------------------------------------------------------------------

@emails_router.get("/api/whitelist")
async def api_list_whitelist(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_permission("whitelist.view")),
):
    """List active whitelist entries."""
    db = SessionLocal()
    try:
        q = db.query(Whitelist).filter(Whitelist.active == True)
        total = q.count()
        entries = q.order_by(Whitelist.created_at.desc()).offset(
            (page - 1) * per_page
        ).limit(per_page).all()

        return {
            "total": total,
            "page": page,
            "entries": [
                {
                    "id": e.id,
                    "indicator_type": e.indicator_type,
                    "value": e.value,
                    "reason": e.reason,
                    "created_by": e.created_by,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in entries
            ],
        }
    finally:
        db.close()


@emails_router.post("/api/whitelist")
async def api_add_whitelist(body: WhitelistAddRequest, user: AuthenticatedUser = Depends(require_permission("whitelist.manage"))):
    """Add an indicator to the whitelist."""
    actor = str(user)
    db = SessionLocal()
    try:
        val = body.value.strip().lower()
        existing = db.query(Whitelist).filter(
            Whitelist.indicator_type == body.indicator_type,
            Whitelist.value == val,
        ).first()

        if existing:
            if not existing.active:
                existing.active = True
                db.commit()
                return {"success": True, "message": f"Reactivated {body.indicator_type}:{val}"}
            return {"success": False, "message": "Already whitelisted"}

        entry = Whitelist(
            indicator_type=body.indicator_type,
            value=val,
            reason=body.reason,
            created_by=actor,
        )
        db.add(entry)
        add_audit_entry(
            db, action="whitelist_add", actor=actor,
            details={"indicator_type": body.indicator_type, "value": val, "reason": body.reason},
        )
        db.commit()
        return {"success": True, "message": f"Added {body.indicator_type}:{val}"}
    finally:
        db.close()


@emails_router.delete("/api/whitelist/{entry_id}")
async def api_remove_whitelist(entry_id: int, user: AuthenticatedUser = Depends(require_permission("whitelist.manage"))):
    """Deactivate a whitelist entry."""
    actor = str(user)
    db = SessionLocal()
    try:
        entry = db.query(Whitelist).filter(Whitelist.id == entry_id).first()
        if not entry:
            raise HTTPException(404, "Whitelist entry not found")

        entry.active = False
        add_audit_entry(
            db, action="whitelist_remove", actor=actor,
            details={"indicator_type": entry.indicator_type, "value": entry.value},
        )
        db.commit()
        return {"success": True, "message": f"Deactivated {entry.indicator_type}:{entry.value}"}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# REST API — Stats & Reports
# ---------------------------------------------------------------------------

def _safe_divide(numerator: int, denominator: int) -> float:
    """Return numerator/denominator rounded to 4 dp, or 0.0 when denominator is zero."""
    return round(numerator / denominator, 4) if denominator else 0.0


def _csv_sanitize(value: object) -> str:
    """Prevent CSV formula injection: prefix cells starting with =, +, -, @ with a quote."""
    s = "" if value is None else str(value)
    if s and s[0] in ("=", "+", "-", "@"):
        s = "'" + s
    return s


@emails_router.get("/api/stats")
async def api_stats(user: AuthenticatedUser = Depends(require_permission("emails.view"))):
    """Dashboard summary statistics including compliance metrics (last 30 days)."""
    db = SessionLocal()
    try:
        from sqlalchemy import func
        from datetime import timedelta

        # All-time counts per status (for the overview cards)
        status_counts = dict(
            db.query(Email.status, func.count(Email.id))
            .group_by(Email.status).all()
        )
        total = sum(status_counts.values())

        # Recent activity — last 24 h
        cutoff_24h = utcnow() - timedelta(hours=24)
        recent = db.query(Email).filter(Email.created_at >= cutoff_24h).count()

        # --- Compliance metrics: rolling 30-day window ---
        cutoff_30d = utcnow() - timedelta(days=30)
        base_q = db.query(Email).filter(Email.created_at >= cutoff_30d)

        # Emails ever flagged (still escalated, or resolved as released/quarantined)
        total_escalated_30d = base_q.filter(
            Email.status.in_(["escalated", "released", "quarantined"])
        ).count()

        # False positives: analyst released an escalated email (pipeline was overcautious)
        false_positive_count = base_q.filter(
            Email.status == "released",
            Email.analyst_action == "release",
        ).count()

        # True positives: analyst confirmed quarantine (pipeline correctly flagged)
        true_positive_count = base_q.filter(
            Email.status == "quarantined",
            Email.analyst_action == "quarantine",
        ).count()

        # Auto-quarantined by rules/blocklist — no analyst action recorded yet
        auto_quarantine_count = base_q.filter(
            Email.status == "quarantined",
            Email.analyst_action.is_(None),
        ).count()

        # Average LLM confidence — requires llm_result JSONB with 'confiance' key
        avg_conf_row = db.execute(
            text(
                "SELECT AVG((llm_result->>'confiance')::float) "
                "FROM emails "
                "WHERE created_at >= :cutoff "
                "AND llm_result IS NOT NULL "
                "AND llm_result->>'confiance' IS NOT NULL"
            ),
            {"cutoff": cutoff_30d},
        ).scalar()
        avg_confidence = round(float(avg_conf_row), 4) if avg_conf_row is not None else None

        # Pipeline accuracy: (auto-accepted + confirmed auto-quarantines) / total 30d
        correct_auto_accepts = base_q.filter(
            Email.status == "accepted",
            Email.analyst_action.is_(None),
        ).count()
        total_30d = base_q.count()
        pipeline_accuracy = _safe_divide(
            correct_auto_accepts + auto_quarantine_count, total_30d
        )

        return {
            "total_emails": total,
            "by_status": status_counts,
            "recent_24h": recent,
            "pending_review": (
                status_counts.get("escalated", 0)
                + status_counts.get("recu", 0)
                + status_counts.get("pending", 0)
            ),
            # Compliance metrics — 30-day rolling window
            "compliance_30d": {
                "false_positive_rate": _safe_divide(false_positive_count, total_escalated_30d),
                "true_positive_rate": _safe_divide(true_positive_count, total_escalated_30d),
                "auto_quarantine_count": auto_quarantine_count,
                "avg_confidence": avg_confidence,
                "pipeline_accuracy": pipeline_accuracy,
                "total_escalated": total_escalated_30d,
                "false_positive_count": false_positive_count,
                "true_positive_count": true_positive_count,
            },
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# CSV Export
# ---------------------------------------------------------------------------

_CSV_COLUMNS = [
    "id", "date", "sender", "subject", "status",
    "analyst_action", "confidence", "risk_score",
]


def _build_csv_row(email: Email) -> list:
    """Extract one sanitized CSV row from an Email ORM instance."""
    confidence = None
    risk_score = None
    if email.llm_result:
        confidence = email.llm_result.get("confiance")
        risk_score = email.llm_result.get("score_risque")

    date_val = (
        email.email_date.isoformat() if email.email_date
        else email.created_at.isoformat() if email.created_at
        else ""
    )
    return [
        _csv_sanitize(email.id),
        _csv_sanitize(date_val),
        _csv_sanitize(email.sender),
        _csv_sanitize(email.subject),
        _csv_sanitize(email.status),
        _csv_sanitize(email.analyst_action),
        _csv_sanitize(confidence),
        _csv_sanitize(risk_score),
    ]


@emails_router.get("/api/emails/export")
async def api_export_emails(
    status: Optional[str] = Query(None, max_length=20),
    days: int = Query(30, ge=1, le=365),
    user: AuthenticatedUser = Depends(require_permission("export.csv")),
):
    """Export emails as a compliance CSV (max 10 000 rows, filtered by status and date range)."""
    from datetime import timedelta

    db = SessionLocal()
    try:
        cutoff = utcnow() - timedelta(days=days)
        q = db.query(Email).filter(Email.created_at >= cutoff).order_by(Email.created_at.desc())

        if status:
            q = q.filter(Email.status == status)

        emails = q.limit(10_000).all()

        buf = io.StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
        writer.writerow(_CSV_COLUMNS)
        for email in emails:
            writer.writerow(_build_csv_row(email))

        slug = f"attijari_emails_{days}d"
        if status:
            slug += f"_{status}"
        filename = slug + ".csv"

        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    finally:
        db.close()


@emails_router.get("/api/reports")
async def api_list_reports(limit: int = Query(20, ge=1, le=100), user: AuthenticatedUser = Depends(require_permission("reports.view"))):
    """List generated reports."""
    db = SessionLocal()
    try:
        reports = db.query(Report).order_by(
            Report.created_at.desc()
        ).limit(limit).all()

        return {
            "reports": [
                {
                    "id": r.id,
                    "report_type": r.report_type,
                    "period_start": r.period_start.isoformat() if r.period_start else None,
                    "period_end": r.period_end.isoformat() if r.period_end else None,
                    "data": r.data,
                    "delivered_via": r.delivered_via,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in reports
            ]
        }
    finally:
        db.close()


@emails_router.get("/api/health")
async def api_health(user: AuthenticatedUser = Depends(require_permission("health.view"))):
    """System health check."""
    health = {
        "status": "ok",
        "timestamp": utcnow().isoformat(),
        "components": {},
    }

    # Database
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        health["components"]["database"] = {"status": "ok"}
        db_connected.set(1)
        db.close()
    except Exception as e:
        health["components"]["database"] = {"status": "error", "error": "connection_failed"}
        health["status"] = "degraded"
        db_connected.set(0)
        print(f"[HEALTH] Database check failed: {e}")  # full error only in server logs

    # Ollama
    try:
        from urllib.request import urlopen
        resp = urlopen("http://localhost:11434/api/tags", timeout=3)
        if resp.status == 200:
            health["components"]["ollama"] = {"status": "ok"}
            ollama_available.set(1)
        else:
            health["components"]["ollama"] = {"status": "error"}
            ollama_available.set(0)
    except Exception:
        health["components"]["ollama"] = {"status": "unavailable"}
        ollama_available.set(0)

    # Threat feeds
    from threat_feeds import _OPENPHISH_PATH, _URLHAUS_PATH
    for name, path in [("openphish", _OPENPHISH_PATH), ("urlhaus", _URLHAUS_PATH)]:
        if path.exists():
            age_h = (time.time() - path.stat().st_mtime) / 3600
            health["components"][f"feed_{name}"] = {
                "status": "ok" if age_h < 48 else "stale",
                "age_hours": round(age_h, 1),
            }
        else:
            health["components"][f"feed_{name}"] = {"status": "missing"}

    return health


# ---------------------------------------------------------------------------
# REST API — Per-tool health monitoring (admin audit)
# ---------------------------------------------------------------------------

@emails_router.get("/api/health/tools")
async def api_health_tools(user: AuthenticatedUser = Depends(require_permission("health.view"))):
    """Per-tool performance overview for admin maintenance dashboard."""
    from health import get_monitor
    return get_monitor().get_all_health()


@emails_router.get("/api/health/tools/{tool_name}")
async def api_health_tool_detail(tool_name: str, user: AuthenticatedUser = Depends(require_permission("health.view"))):
    """Detailed health stats for a single tool."""
    from health import get_monitor
    data = get_monitor().get_tool_health(tool_name)
    if data is None:
        raise HTTPException(404, f"Unknown tool: {tool_name}")
    return data


@emails_router.get("/api/health/alerts")
async def api_health_alerts(limit: int = Query(50, ge=1, le=500), user: AuthenticatedUser = Depends(require_permission("alerts.view"))):
    """Recent maintenance alerts (newest first)."""
    from health import get_monitor
    return {"alerts": get_monitor().get_recent_alerts(limit=limit)}


# ---------------------------------------------------------------------------
# REST API — Analyst Feedback (pipeline learning)
# ---------------------------------------------------------------------------

@emails_router.get("/api/feedback")
async def api_list_feedback(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_permission("audit.view")),
):
    """List analyst feedback entries for pipeline learning review."""
    db = SessionLocal()
    try:
        q = db.query(AnalystFeedback).order_by(AnalystFeedback.created_at.desc())
        total = q.count()
        entries = q.offset((page - 1) * per_page).limit(per_page).all()

        return {
            "total": total,
            "page": page,
            "entries": [
                {
                    "id": fb.id,
                    "email_id": fb.email_id,
                    "action": fb.action,
                    "pipeline_verdict": fb.pipeline_verdict,
                    "analyst_verdict": fb.analyst_verdict,
                    "reasoning": fb.reasoning,
                    "domain": fb.domain,
                    "indicator_type": fb.indicator_type,
                    "indicator_value": fb.indicator_value,
                    "created_at": fb.created_at.isoformat() if fb.created_at else None,
                }
                for fb in entries
            ],
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# REST API — Action History (analyst activity feed)
# ---------------------------------------------------------------------------

@emails_router.get("/api/history")
async def api_action_history(
    actor: Optional[str] = Query(None, max_length=100),
    action: Optional[str] = Query(None, max_length=50),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_permission("audit.view")),
):
    """Full action history with actor names, email context, and notes."""
    db = SessionLocal()
    try:
        q = db.query(AuditLog).order_by(AuditLog.created_at.desc())

        if actor:
            q = q.filter(AuditLog.actor == actor)
        if action:
            q = q.filter(AuditLog.action == action)

        total = q.count()
        entries = q.offset((page - 1) * per_page).limit(per_page).all()

        # Batch-fetch linked emails for context
        email_ids = [e.email_id for e in entries if e.email_id]
        emails_map = {}
        if email_ids:
            email_rows = db.query(
                Email.id, Email.sender, Email.sender_domain, Email.subject
            ).filter(Email.id.in_(email_ids)).all()
            emails_map = {r.id: {"sender": mask_pii(r.sender), "sender_domain": r.sender_domain, "subject": r.subject} for r in email_rows}

        # Collect unique actor names for the filter dropdown
        actors = [r[0] for r in db.query(AuditLog.actor).distinct().all()]

        return {
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": (total + per_page - 1) // per_page,
            "actors": sorted(actors),
            "entries": [
                {
                    "id": e.id,
                    "action": e.action,
                    "actor": e.actor,
                    "email_id": e.email_id,
                    "email_context": emails_map.get(e.email_id),
                    "details": e.details,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in entries
            ],
        }
    finally:
        db.close()


@emails_router.get("/api/audit/errors")
async def api_audit_errors(
    tool: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    user: AuthenticatedUser = Depends(require_permission("audit.view")),
):
    """Get component error history with error codes for admin audit panel."""
    from health import get_monitor
    monitor = get_monitor()

    result = {"errors": [], "tool_summary": {}}

    # Per-tool summary
    all_health = monitor.get_all_health()
    for name, stats in all_health.get("tools", {}).items():
        if tool and name != tool:
            continue
        result["tool_summary"][name] = {
            "status": stats["status"],
            "total_calls": stats["total_calls"],
            "success_count": stats["success_count"],
            "failure_count": stats["failure_count"],
            "error_rate": stats["error_rate"],
            "consecutive_failures": stats["consecutive_failures"],
            "avg_latency_s": stats["avg_latency_s"],
            "p95_latency_s": stats["p95_latency_s"],
            "last_error": stats["last_error"],
            "recent_errors": stats["recent_errors"],
        }

    # Alerts from file
    alerts = monitor.get_recent_alerts(limit=limit)
    if tool:
        alerts = [a for a in alerts if a.get("tool") == tool]
    result["alerts"] = alerts

    return result


# ---------------------------------------------------------------------------
# Prometheus metrics endpoint
# ---------------------------------------------------------------------------

@emails_router.get("/metrics")
async def prometheus_metrics():
    """Expose metrics in Prometheus text format."""
    _update_gauge_metrics()
    body, content_type = get_metrics_text()
    return Response(content=body, media_type=content_type if isinstance(content_type, str) else "text/plain")


# ---------------------------------------------------------------------------
# REST API — Security Alerts
# ---------------------------------------------------------------------------

@emails_router.get("/api/alerts")
async def api_list_alerts(
    level: Optional[str] = Query(None, max_length=20),
    acknowledged: Optional[bool] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    user: AuthenticatedUser = Depends(require_permission("alerts.view")),
):
    """List recent security alerts, newest first."""
    db = SessionLocal()
    try:
        q = db.query(Alert).order_by(Alert.created_at.desc())
        if level:
            q = q.filter(Alert.level == level.lower())
        if acknowledged is not None:
            q = q.filter(Alert.acknowledged == acknowledged)
        entries = q.limit(limit).all()
        return {
            "total": len(entries),
            "alerts": [
                {
                    "id": a.id,
                    "level": a.level,
                    "title": a.title,
                    "details": a.details,
                    "source": a.source,
                    "acknowledged": a.acknowledged,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                }
                for a in entries
            ],
        }
    finally:
        db.close()


@emails_router.post("/api/alerts/{alert_id}/acknowledge")
async def api_acknowledge_alert(alert_id: int, user: AuthenticatedUser = Depends(require_permission("alerts.acknowledge"))):
    """Mark an alert as acknowledged by an analyst."""
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            raise HTTPException(404, "Alert not found")
        alert.acknowledged = True
        db.commit()
        return {"success": True, "alert_id": alert_id, "acknowledged_by": str(user)}
    finally:
        db.close()
