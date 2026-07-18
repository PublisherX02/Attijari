"""User management API — admin only.

Provides CRUD for user accounts, TOTP provisioning, password resets,
and permission assignment. All endpoints require the `users.manage` permission.
"""

import bcrypt
import pyotp
import secrets
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional

from sqlalchemy.orm.attributes import flag_modified

from api_core import require_permission, AuthenticatedUser
from database import (
    SessionLocal, User, add_audit_entry, utcnow,
    ALL_PERMISSIONS, ROLE_DEFAULTS, ANALYST_PERMISSIONS, VIEWER_PERMISSIONS,
)

users_router = APIRouter()

_admin_dep = require_permission("users.manage")


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9._-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="analyst", pattern=r"^(admin|analyst|viewer|insurance_operator)$")
    permissions: Optional[dict] = None  # if None, use role defaults


class UpdateUserRequest(BaseModel):
    role: Optional[str] = Field(default=None, pattern=r"^(admin|analyst|viewer|insurance_operator)$")
    permissions: Optional[dict] = None
    is_active: Optional[bool] = None


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=8, max_length=128)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@users_router.get("/api/users")
async def api_list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    admin: AuthenticatedUser = Depends(_admin_dep),
):
    """List all user accounts with their roles and permissions."""
    db = SessionLocal()
    try:
        q = db.query(User).order_by(User.created_at.desc())
        total = q.count()
        users = q.offset((page - 1) * per_page).limit(per_page).all()

        return {
            "total": total,
            "page": page,
            "permission_catalog": list(ALL_PERMISSIONS.keys()),
            "role_defaults": ROLE_DEFAULTS,
            "users": [
                {
                    "id": u.id,
                    "username": u.username,
                    "role": u.role,
                    "permissions": u.permissions,
                    "is_active": u.is_active,
                    "created_by": u.created_by,
                    "last_login": u.last_login.isoformat() if u.last_login else None,
                    "created_at": u.created_at.isoformat() if u.created_at else None,
                }
                for u in users
            ],
        }
    finally:
        db.close()


@users_router.post("/api/users")
async def api_create_user(
    body: CreateUserRequest,
    admin: AuthenticatedUser = Depends(_admin_dep),
):
    """Create a new user account. Returns TOTP provisioning URI for QR code setup."""
    db = SessionLocal()
    try:
        # Check for duplicate username
        existing = db.query(User).filter(User.username == body.username).first()
        if existing:
            raise HTTPException(400, f"Username '{body.username}' already exists")

        # Hash password
        hashed = bcrypt.hashpw(
            body.password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        # Generate TOTP secret
        totp_secret = pyotp.random_base32()
        totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(
            name=body.username, issuer_name="ImaniIA"
        )

        # Determine permissions
        if body.permissions is not None:
            # Admin explicitly set permissions — validate keys
            perms = {k: bool(v) for k, v in body.permissions.items() if k in ALL_PERMISSIONS}
        else:
            perms = ROLE_DEFAULTS.get(body.role, VIEWER_PERMISSIONS).copy()

        # Admin role always gets all permissions
        if body.role == "admin":
            perms = ALL_PERMISSIONS.copy()

        user = User(
            username=body.username,
            password_hash=hashed,
            totp_secret=totp_secret,
            role=body.role,
            permissions=perms,
            created_by=admin.username,
        )
        db.add(user)
        db.flush()  # get user.id before audit

        add_audit_entry(
            db, action="user_create", actor=admin.username,
            details={
                "target_user": body.username,
                "role": body.role,
                "permissions": perms,
            },
        )
        db.commit()

        return {
            "success": True,
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role,
                "permissions": user.permissions,
            },
            "totp_uri": totp_uri,
            "totp_secret": totp_secret,
            "message": (
                f"User '{body.username}' created. "
                "Have them scan the QR code (totp_uri) in their authenticator app."
            ),
        }
    finally:
        db.close()


@users_router.put("/api/users/{user_id}")
async def api_update_user(
    user_id: int,
    body: UpdateUserRequest,
    admin: AuthenticatedUser = Depends(_admin_dep),
):
    """Update a user's role, permissions, or active status."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(404, "User not found")

        # Prevent admin from deactivating themselves
        if user.username == admin.username and body.is_active is False:
            raise HTTPException(400, "Cannot deactivate your own account")

        changes = {}

        if body.role is not None and body.role != user.role:
            old_role = user.role
            user.role = body.role
            changes["role"] = {"from": old_role, "to": body.role}
            # If role changes and no explicit permissions given, apply role defaults
            if body.permissions is None:
                if body.role == "admin":
                    user.permissions = ALL_PERMISSIONS.copy()
                else:
                    user.permissions = ROLE_DEFAULTS.get(body.role, VIEWER_PERMISSIONS).copy()
                flag_modified(user, "permissions")
                changes["permissions"] = "reset to role defaults"

        if body.permissions is not None:
            perms = {k: bool(v) for k, v in body.permissions.items() if k in ALL_PERMISSIONS}
            # Admin always gets all permissions regardless
            if (body.role or user.role) == "admin":
                perms = ALL_PERMISSIONS.copy()
            user.permissions = perms
            flag_modified(user, "permissions")
            changes["permissions"] = perms

        if body.is_active is not None and body.is_active != user.is_active:
            user.is_active = body.is_active
            changes["is_active"] = body.is_active

        if not changes:
            return {"success": True, "message": "No changes made"}

        add_audit_entry(
            db, action="user_update", actor=admin.username,
            details={"target_user": user.username, "target_id": user_id, "changes": changes},
        )
        db.commit()

        return {
            "success": True,
            "message": f"User '{user.username}' updated",
            "changes": changes,
        }
    finally:
        db.close()


@users_router.post("/api/users/{user_id}/reset-password")
async def api_reset_password(
    user_id: int,
    body: ResetPasswordRequest,
    admin: AuthenticatedUser = Depends(_admin_dep),
):
    """Reset a user's password (admin action)."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(404, "User not found")

        hashed = bcrypt.hashpw(
            body.new_password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        user.password_hash = hashed

        add_audit_entry(
            db, action="user_password_reset", actor=admin.username,
            details={"target_user": user.username, "target_id": user_id},
        )
        db.commit()

        return {"success": True, "message": f"Password reset for '{user.username}'"}
    finally:
        db.close()


@users_router.post("/api/users/{user_id}/reset-totp")
async def api_reset_totp(
    user_id: int,
    admin: AuthenticatedUser = Depends(_admin_dep),
):
    """Regenerate a user's TOTP secret (admin action). Returns new provisioning URI."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(404, "User not found")

        new_secret = pyotp.random_base32()
        totp_uri = pyotp.TOTP(new_secret).provisioning_uri(
            name=user.username, issuer_name="ImaniIA"
        )
        user.totp_secret = new_secret

        add_audit_entry(
            db, action="user_totp_reset", actor=admin.username,
            details={"target_user": user.username, "target_id": user_id},
        )
        db.commit()

        return {
            "success": True,
            "totp_uri": totp_uri,
            "totp_secret": new_secret,
            "message": f"TOTP reset for '{user.username}'. Have them scan the new QR code.",
        }
    finally:
        db.close()


@users_router.delete("/api/users/{user_id}")
async def api_delete_user(
    user_id: int,
    admin: AuthenticatedUser = Depends(_admin_dep),
):
    """Deactivate a user account (soft delete — preserves audit trail)."""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(404, "User not found")

        if user.username == admin.username:
            raise HTTPException(400, "Cannot deactivate your own account")

        # Count remaining active admins
        if user.role == "admin":
            active_admins = db.query(User).filter(
                User.role == "admin", User.is_active == True, User.id != user_id
            ).count()
            if active_admins == 0:
                raise HTTPException(400, "Cannot deactivate the last admin account")

        user.is_active = False

        add_audit_entry(
            db, action="user_deactivate", actor=admin.username,
            details={"target_user": user.username, "target_id": user_id},
        )
        db.commit()

        return {"success": True, "message": f"User '{user.username}' deactivated"}
    finally:
        db.close()
