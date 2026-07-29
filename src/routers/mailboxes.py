"""mailboxes.py router — admin-only dashboard mailbox management.

All endpoints require the mailboxes.manage permission (admin by default,
see database.ALL_PERMISSIONS). Passwords are never returned in any response.
"""
import os
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional
from slowapi import Limiter

from api_core import require_permission, AuthenticatedUser
from database import SessionLocal, add_audit_entry
import mailboxes

mailboxes_router = APIRouter()
_admin_dep = require_permission("mailboxes.manage")


def _get_real_client_ip(request: Request) -> str:
    """Extract client IP ignoring X-Forwarded-For unless from trusted proxy.
    Mirrors routers/auth.py's helper of the same name."""
    trusted_proxies = os.getenv("TRUSTED_PROXIES", "127.0.0.1").split(",")
    trusted_proxies = {p.strip() for p in trusted_proxies if p.strip()}
    client_ip = request.client.host if request.client else "unknown"
    if client_ip in trusted_proxies:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return client_ip


# These three endpoints open a real outbound IMAP/POP3/SSL connection to an
# admin-supplied host:port — rate-limited so a hijacked admin session can't
# use them to port-scan/timing-probe internal hosts or exhaust connections.
_limiter = Limiter(key_func=_get_real_client_ip)


class TestMailboxRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    provider: str = Field(..., pattern=r"^(gmail|outlook|custom)$")
    password: str = Field(..., min_length=1, max_length=512)
    host: Optional[str] = Field(default=None, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    protocol: str = Field(default="imap", pattern=r"^(imap|pop3)$")


class OutboundSmtpRequest(BaseModel):
    host: Optional[str] = Field(default=None, max_length=255)
    port: Optional[int] = Field(default=465, ge=1, le=65535)
    user: Optional[str] = Field(default=None, max_length=320)
    password: Optional[str] = Field(default=None, max_length=512)


def _serialize(row) -> dict:
    return {
        "id": row.id,
        "email": row.email,
        "provider": row.provider,
        "protocol": row.protocol,
        "imap_host": row.imap_host,
        "imap_port": row.imap_port,
        "status": row.status,
        "last_test_error": row.last_test_error,
        "last_tested_at": row.last_tested_at.isoformat() if row.last_tested_at else None,
        "is_active": row.is_active,
        "added_by": row.added_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "smtp_out_host": row.smtp_out_host,
        "smtp_out_port": row.smtp_out_port,
        "smtp_out_user": row.smtp_out_user,
    }


@mailboxes_router.post("/api/mailboxes/test")
@_limiter.limit("10/minute")
async def api_test_mailbox(request: Request, body: TestMailboxRequest, admin: AuthenticatedUser = Depends(_admin_dep)):
    try:
        host, port = mailboxes.resolve_host_port(body.provider, body.host, body.port, body.protocol)
    except ValueError as e:
        raise HTTPException(400, str(e))
    ok, error = mailboxes.test_connection(host, body.email, body.password, port, body.protocol)
    return {"ok": ok, "error": error}


@mailboxes_router.post("/api/mailboxes")
@_limiter.limit("10/minute")
async def api_add_mailbox(request: Request, body: TestMailboxRequest, admin: AuthenticatedUser = Depends(_admin_dep)):
    db = SessionLocal()
    try:
        try:
            row = mailboxes.add_and_test_mailbox(
                db, email=body.email, provider=body.provider, password=body.password,
                host=body.host, port=body.port, added_by=admin.username, protocol=body.protocol,
            )
        except ValueError as e:
            raise HTTPException(400, str(e))

        add_audit_entry(
            db, action="mailbox_add", actor=admin.username,
            details={"email": row.email, "provider": row.provider, "protocol": row.protocol},
        )
        return {"success": True, "mailbox": _serialize(row)}
    finally:
        db.close()


@mailboxes_router.get("/api/mailboxes")
async def api_list_mailboxes(admin: AuthenticatedUser = Depends(_admin_dep)):
    db = SessionLocal()
    try:
        from database import list_mailbox_accounts
        rows = list_mailbox_accounts(db)
        return {"mailboxes": [_serialize(r) for r in rows]}
    finally:
        db.close()


@mailboxes_router.post("/api/mailboxes/{mailbox_id}/retest")
@_limiter.limit("10/minute")
async def api_retest_mailbox(request: Request, mailbox_id: int, admin: AuthenticatedUser = Depends(_admin_dep)):
    db = SessionLocal()
    try:
        try:
            row = mailboxes.retest_mailbox(db, mailbox_id)
        except ValueError as e:
            raise HTTPException(404, str(e))
        return {"success": True, "mailbox": _serialize(row)}
    finally:
        db.close()


@mailboxes_router.post("/api/mailboxes/{mailbox_id}/activate")
async def api_activate_mailbox(mailbox_id: int, admin: AuthenticatedUser = Depends(_admin_dep)):
    db = SessionLocal()
    try:
        try:
            row = mailboxes.activate_mailbox(db, mailbox_id)
        except ValueError as e:
            raise HTTPException(404, str(e))

        add_audit_entry(
            db, action="mailbox_activate", actor=admin.username,
            details={"email": row.email, "mailbox_id": mailbox_id},
        )
        return {"success": True, "mailbox": _serialize(row)}
    finally:
        db.close()


@mailboxes_router.post("/api/mailboxes/deactivate")
async def api_deactivate_mailbox(admin: AuthenticatedUser = Depends(_admin_dep)):
    """Clear the active mailbox, restoring the .env IMAP_* fallback."""
    db = SessionLocal()
    try:
        mailboxes.deactivate_mailbox(db)
        add_audit_entry(db, action="mailbox_deactivate", actor=admin.username, details={})
        return {"success": True}
    finally:
        db.close()


@mailboxes_router.post("/api/mailboxes/{mailbox_id}/outbound-smtp")
async def api_set_outbound_smtp(mailbox_id: int, body: OutboundSmtpRequest,
                                admin: AuthenticatedUser = Depends(_admin_dep)):
    db = SessionLocal()
    try:
        try:
            row = mailboxes.update_mailbox_outbound_smtp(
                db, mailbox_id, host=body.host, port=body.port, user=body.user, password=body.password,
            )
        except ValueError as e:
            raise HTTPException(404, str(e))

        add_audit_entry(
            db, action="mailbox_outbound_smtp_update", actor=admin.username,
            details={"mailbox_id": mailbox_id, "configured": bool(body.host)},
        )
        return {"success": True, "mailbox": _serialize(row)}
    finally:
        db.close()


@mailboxes_router.delete("/api/mailboxes/{mailbox_id}")
async def api_delete_mailbox(mailbox_id: int, admin: AuthenticatedUser = Depends(_admin_dep)):
    db = SessionLocal()
    try:
        try:
            deleted = mailboxes.remove_mailbox(db, mailbox_id)
        except ValueError as e:
            raise HTTPException(400, str(e))
        if not deleted:
            raise HTTPException(404, "Mailbox not found")

        add_audit_entry(
            db, action="mailbox_delete", actor=admin.username,
            details={"mailbox_id": mailbox_id},
        )
        return {"success": True}
    finally:
        db.close()
