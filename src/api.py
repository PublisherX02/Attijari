"""api.py — FastAPI application for the Attijari SOC Dashboard.

Serves:
  - REST API for email review, blocklist/whitelist management, reports
  - Jinja2-templated dashboard pages
  - Prometheus /metrics endpoint
  - System health checks

Start with:  uvicorn src.api:app --host 0.0.0.0 --port 8000
Or via main: python src/main.py --serve
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Ensure src/ on path
_SRC_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SRC_DIR))

load_dotenv()

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from database import (
    init_db,
    SessionLocal,
    Email,
    Blocklist,
    Whitelist,
    AuditLog,
    Report,
    add_audit_entry,
    add_blocklist_entry,
    get_blocked_set,
    is_whitelisted,
    utcnow,
)
from routing import release_email, quarantine_email, override_verdict
from reporting import generate_report
from metrics import (
    get_metrics_text,
    api_requests_total,
    api_request_duration_seconds,
    emails_in_queue,
    blocklist_size,
    db_connected,
    ollama_available,
)

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------


class ConnectionManager:
    def __init__(self):
        self.active_connections = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        try:
            self.active_connections.remove(websocket)
        except ValueError:
            pass

    async def broadcast(self, message: str):
        for connection in list(self.active_connections):
            try:
                await connection.send_text(message)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

app = FastAPI(
    title="Attijari SOC Dashboard",
    description="Email security triage system — analyst review interface",
    version="2.0.0",
)

# Templates & static files
_DASHBOARD_DIR = _SRC_DIR / "dashboard"
_TEMPLATES_DIR = _DASHBOARD_DIR / "templates"
_STATIC_DIR = _DASHBOARD_DIR / "static"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# Mount static files
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")


# ---------------------------------------------------------------------------
# Middleware — metrics tracking
# ---------------------------------------------------------------------------

@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    t0 = time.time()
    response = await call_next(request)
    elapsed = time.time() - t0

    # Track metrics (skip /metrics and /static to avoid noise)
    path = request.url.path
    if not path.startswith("/static") and path != "/metrics":
        api_requests_total.labels(
            method=request.method,
            endpoint=path,
            status_code=response.status_code,
        ).inc()
        api_request_duration_seconds.labels(
            method=request.method,
            endpoint=path,
        ).observe(elapsed)

    return response


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup():
    init_db()
    _update_gauge_metrics()


def _update_gauge_metrics():
    """Refresh gauge metrics from DB state."""
    try:
        db = SessionLocal()
        # Emails pending review
        pending = db.query(Email).filter(
            Email.status.in_(["escalated", "recu"])
        ).count()
        emails_in_queue.set(pending)

        # Blocklist sizes
        for itype in ("email", "domain", "ip", "hash"):
            count = db.query(Blocklist).filter(
                Blocklist.indicator_type == itype,
                Blocklist.active == True,
            ).count()
            blocklist_size.labels(indicator_type=itype).set(count)

        db_connected.set(1)
        db.close()
    except Exception:
        db_connected.set(0)


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------

class BlocklistAddRequest(BaseModel):
    indicator_type: str  # email, domain, ip, hash
    value: str
    reason: str = ""

class WhitelistAddRequest(BaseModel):
    indicator_type: str
    value: str
    reason: str = ""

class OverrideRequest(BaseModel):
    status: str  # accepted, escalated, released, quarantined
    notes: str = ""


# ---------------------------------------------------------------------------
# Dashboard pages (Jinja2 HTML)
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    return templates.TemplateResponse(request, "inbox.html", {"request": request})


@app.get("/email/{email_id}", response_class=HTMLResponse)
async def dashboard_email_detail(request: Request, email_id: int):
    return templates.TemplateResponse(request, "detail.html", {"request": request, "email_id": email_id})


@app.get("/blocklist", response_class=HTMLResponse)
async def dashboard_blocklist(request: Request):
    return templates.TemplateResponse(request, "blocklist.html", {"request": request})


@app.get("/whitelist", response_class=HTMLResponse)
async def dashboard_whitelist(request: Request):
    return templates.TemplateResponse(request, "whitelist.html", {"request": request})


@app.get("/reports", response_class=HTMLResponse)
async def dashboard_reports(request: Request):
    return templates.TemplateResponse(request, "reports.html", {"request": request})


@app.get("/health", response_class=HTMLResponse)
async def dashboard_health(request: Request):
    return templates.TemplateResponse(request, "health.html", {"request": request})


# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

@app.post("/api/internal/notify")
async def api_internal_notify():
    await ws_manager.broadcast("refresh")
    return {"status": "ok"}


# REST API — Email management
# ---------------------------------------------------------------------------

@app.get("/api/emails")
async def api_list_emails(
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
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
            Email.created_at
        ).order_by(Email.created_at.desc())

        if status:
            q = q.filter(Email.status == status)
        if search:
            term = f"%{search}%"
            q = q.filter(
                (Email.sender.ilike(term)) |
                (Email.subject.ilike(term)) |
                (Email.sender_domain.ilike(term))
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
                    "sender": e.sender,
                    "sender_domain": e.sender_domain,
                    "subject": e.subject,
                    "status": e.status,
                    "attachment_count": e.attachment_count,
                    "analyst_action": e.analyst_action,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in emails
            ],
        }
    finally:
        db.close()


@app.get("/api/emails/{email_id}")
async def api_get_email(email_id: int):
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

        return {
            "id": email.id,
            "idempotency_key": email.idempotency_key,
            "message_id": email.message_id,
            "raw_sha256": email.raw_sha256,
            "sender": email.sender,
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
            "created_at": email.created_at.isoformat() if email.created_at else None,
            "updated_at": email.updated_at.isoformat() if email.updated_at else None,
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


@app.post("/api/emails/{email_id}/release")
async def api_release_email(email_id: int):
    """Release an email (analyst action)."""
    result = release_email(email_id, actor="analyst")
    _update_gauge_metrics()
    if not result["success"]:
        raise HTTPException(400, result["error"])
    return result


@app.post("/api/emails/{email_id}/quarantine")
async def api_quarantine_email(email_id: int):
    """Quarantine an email with cascading blocklist (analyst action)."""
    result = quarantine_email(email_id, actor="analyst")
    _update_gauge_metrics()
    if not result["success"]:
        raise HTTPException(400, result["error"])
    return result


@app.post("/api/emails/{email_id}/override")
async def api_override_email(email_id: int, body: OverrideRequest):
    """Override the pipeline verdict (analyst action with notes)."""
    result = override_verdict(email_id, body.status, actor="analyst", notes=body.notes)
    _update_gauge_metrics()
    if not result["success"]:
        raise HTTPException(400, result["error"])
    return result


# ---------------------------------------------------------------------------
# REST API — Blocklist
# ---------------------------------------------------------------------------

@app.get("/api/blocklist")
async def api_list_blocklist(
    indicator_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
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
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in entries
            ],
        }
    finally:
        db.close()


@app.post("/api/blocklist")
async def api_add_blocklist(body: BlocklistAddRequest):
    """Add an indicator to the blocklist."""
    db = SessionLocal()
    try:
        added = add_blocklist_entry(
            db, body.indicator_type, body.value,
            source="manual", confirmed_by="analyst",
        )
        if added:
            add_audit_entry(
                db, action="blocklist_add", actor="analyst",
                details={"indicator_type": body.indicator_type, "value": body.value, "reason": body.reason},
            )
            _update_gauge_metrics()
            return {"success": True, "message": f"Added {body.indicator_type}:{body.value}"}
        return {"success": False, "message": "Already blocked or whitelisted"}
    finally:
        db.close()


@app.delete("/api/blocklist/{entry_id}")
async def api_remove_blocklist(entry_id: int):
    """Deactivate a blocklist entry."""
    db = SessionLocal()
    try:
        entry = db.query(Blocklist).filter(Blocklist.id == entry_id).first()
        if not entry:
            raise HTTPException(404, "Blocklist entry not found")

        entry.active = False
        add_audit_entry(
            db, action="blocklist_remove", actor="analyst",
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

@app.get("/api/whitelist")
async def api_list_whitelist(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
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


@app.post("/api/whitelist")
async def api_add_whitelist(body: WhitelistAddRequest):
    """Add an indicator to the whitelist."""
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
            created_by="analyst",
        )
        db.add(entry)
        add_audit_entry(
            db, action="whitelist_add", actor="analyst",
            details={"indicator_type": body.indicator_type, "value": val, "reason": body.reason},
        )
        db.commit()
        return {"success": True, "message": f"Added {body.indicator_type}:{val}"}
    finally:
        db.close()


@app.delete("/api/whitelist/{entry_id}")
async def api_remove_whitelist(entry_id: int):
    """Deactivate a whitelist entry."""
    db = SessionLocal()
    try:
        entry = db.query(Whitelist).filter(Whitelist.id == entry_id).first()
        if not entry:
            raise HTTPException(404, "Whitelist entry not found")

        entry.active = False
        add_audit_entry(
            db, action="whitelist_remove", actor="analyst",
            details={"indicator_type": entry.indicator_type, "value": entry.value},
        )
        db.commit()
        return {"success": True, "message": f"Deactivated {entry.indicator_type}:{entry.value}"}
    finally:
        db.close()


# ---------------------------------------------------------------------------
# REST API — Stats & Reports
# ---------------------------------------------------------------------------

@app.get("/api/stats")
async def api_stats():
    """Dashboard summary statistics."""
    db = SessionLocal()
    try:
        from sqlalchemy import func

        # Count by status
        status_counts = dict(
            db.query(Email.status, func.count(Email.id))
            .group_by(Email.status).all()
        )

        total = sum(status_counts.values())

        # Recent activity (last 24h)
        from datetime import timedelta
        cutoff = utcnow() - timedelta(hours=24)
        recent = db.query(Email).filter(Email.created_at >= cutoff).count()

        return {
            "total_emails": total,
            "by_status": status_counts,
            "recent_24h": recent,
            "pending_review": status_counts.get("escalated", 0) + status_counts.get("recu", 0),
        }
    finally:
        db.close()


@app.get("/api/reports")
async def api_list_reports(limit: int = Query(20, ge=1, le=100)):
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


@app.get("/api/health")
async def api_health():
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
        health["components"]["database"] = {"status": "error", "error": str(e)}
        health["status"] = "degraded"
        db_connected.set(0)

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
# Prometheus metrics endpoint
# ---------------------------------------------------------------------------

@app.get("/metrics")
async def prometheus_metrics():
    """Expose metrics in Prometheus text format."""
    _update_gauge_metrics()
    body, content_type = get_metrics_text()
    return Response(content=body, media_type=content_type)


# Need this import for the health check SQL
from sqlalchemy import text
