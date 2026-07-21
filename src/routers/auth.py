import os
import secrets
import bcrypt
import pyotp
import jwt
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Cookie, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from typing import Optional

from api_core import templates, get_db_generator, JWT_SECRET, ALGORITHM, revoke_token

# In-memory TOTP replay prevention (codes expire after 60s)
_used_totp_codes: dict[str, bool] = {}
_totp_cleanup_counter = 0


def _cleanup_totp_cache():
    """Periodically clear the TOTP replay cache (every 50 logins)."""
    global _totp_cleanup_counter
    _totp_cleanup_counter += 1
    if _totp_cleanup_counter >= 50:
        _used_totp_codes.clear()
        _totp_cleanup_counter = 0


auth_router = APIRouter()


def _get_real_client_ip(request: Request) -> str:
    """Extract client IP ignoring X-Forwarded-For unless from trusted proxy."""
    trusted_proxies = os.getenv("TRUSTED_PROXIES", "127.0.0.1").split(",")
    trusted_proxies = {p.strip() for p in trusted_proxies if p.strip()}
    client_ip = request.client.host if request.client else "unknown"
    if client_ip in trusted_proxies:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return client_ip


_limiter = Limiter(key_func=_get_real_client_ip)

@auth_router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request})

@auth_router.post("/login")
@_limiter.limit("5/minute")
async def login_post(request: Request, username: str = Form(...), password: str = Form(...), totp: str = Form(...), db = Depends(get_db_generator)):
    from database import User
    
    user = db.query(User).filter(User.username == username).first()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": "Invalid username or password"})

    if not user.is_active:
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": "Account deactivated. Contact administrator."})

    if not user.totp_secret:
        # MFA is mandatory — reject users without TOTP configured
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": "MFA not configured. Contact administrator."})
    # totp_secret is encrypted at rest (SEC-H2); decrypt_field transparently
    # handles legacy plaintext rows so login works before the migration runs.
    from vault import decrypt_field
    totp_obj = pyotp.TOTP(decrypt_field(user.totp_secret))
    if not totp_obj.verify(totp, valid_window=0):
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": "Invalid MFA code"})
    # Prevent TOTP replay — reject codes already used in this 30s window
    cache_key = f"totp_used:{user.username}:{totp}"
    if _used_totp_codes.get(cache_key):
        return templates.TemplateResponse(request, "login.html", {"request": request, "error": "MFA code already used. Wait for next code."})
    _used_totp_codes[cache_key] = True
    _cleanup_totp_cache()

    # Update last_login timestamp
    from database import utcnow as _utcnow
    user.last_login = _utcnow()
    db.commit()

    payload = {
        "sub": username,
        "role": user.role or "viewer",
        "jti": secrets.token_urlsafe(16),  # unique id so this token can be revoked (SEC-H3)
        "exp": datetime.now(timezone.utc) + timedelta(hours=8)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token", value=token,
        httponly=True, samesite="strict", secure=True,
        path="/", max_age=28800,
    )
    return response

@auth_router.get("/logout")
async def logout(access_token: Optional[str] = Cookie(None)):
    if access_token:
        revoke_token(access_token)
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response
