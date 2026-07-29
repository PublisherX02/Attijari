"""mailboxes.py router — admin-only dashboard mailbox management.

All endpoints require the mailboxes.manage permission (admin by default,
see database.ALL_PERMISSIONS). Passwords are never returned in any response.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from typing import Optional

from api_core import require_permission, AuthenticatedUser
from database import SessionLocal, add_audit_entry
import mailboxes

mailboxes_router = APIRouter()
_admin_dep = require_permission("mailboxes.manage")


class TestMailboxRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    provider: str = Field(..., pattern=r"^(gmail|outlook|custom)$")
    password: str = Field(..., min_length=1, max_length=512)
    host: Optional[str] = Field(default=None, max_length=255)
    port: Optional[int] = Field(default=None, ge=1, le=65535)


def _serialize(row) -> dict:
    return {
        "id": row.id,
        "email": row.email,
        "provider": row.provider,
        "imap_host": row.imap_host,
        "imap_port": row.imap_port,
        "status": row.status,
        "last_test_error": row.last_test_error,
        "last_tested_at": row.last_tested_at.isoformat() if row.last_tested_at else None,
        "is_active": row.is_active,
        "added_by": row.added_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@mailboxes_router.post("/api/mailboxes/test")
async def api_test_mailbox(body: TestMailboxRequest, admin: AuthenticatedUser = Depends(_admin_dep)):
    try:
        host, port = mailboxes.resolve_host_port(body.provider, body.host, body.port)
    except ValueError as e:
        raise HTTPException(400, str(e))
    ok, error = mailboxes.test_connection(host, body.email, body.password, port)
    return {"ok": ok, "error": error}


@mailboxes_router.post("/api/mailboxes")
async def api_add_mailbox(body: TestMailboxRequest, admin: AuthenticatedUser = Depends(_admin_dep)):
    db = SessionLocal()
    try:
        try:
            row = mailboxes.add_and_test_mailbox(
                db, email=body.email, provider=body.provider, password=body.password,
                host=body.host, port=body.port, added_by=admin.username,
            )
        except ValueError as e:
            raise HTTPException(400, str(e))

        add_audit_entry(
            db, action="mailbox_add", actor=admin.username,
            details={"email": row.email, "provider": row.provider},
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
async def api_retest_mailbox(mailbox_id: int, admin: AuthenticatedUser = Depends(_admin_dep)):
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
