from fastapi import APIRouter, Request, Cookie
from fastapi.responses import HTMLResponse
from typing import Optional
import jwt

from api_core import templates, JWT_SECRET, ALGORITHM

dashboard_router = APIRouter()


def _get_user_context(access_token: Optional[str]) -> dict:
    """Extract username and role from JWT cookie."""
    if not access_token:
        return {"username": None, "role": None, "permissions": {}}
    try:
        payload = jwt.decode(access_token, JWT_SECRET, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role", "viewer")
        # Load full permissions from DB for template rendering
        from database import SessionLocal, User
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.username == username, User.is_active == True).first()
            if user:
                perms = user.permissions or {}
                return {"username": username, "role": user.role or role, "permissions": perms}
        finally:
            db.close()
        return {"username": username, "role": role, "permissions": {}}
    except jwt.PyJWTError:
        return {"username": None, "role": None, "permissions": {}}


def _has_perm(user_ctx: dict, permission: str) -> bool:
    """Check if user context has a permission (admin bypasses)."""
    if user_ctx.get("role") == "admin":
        return True
    return bool(user_ctx.get("permissions", {}).get(permission, False))


def _ctx(request: Request, active_page: str, extra: dict = None) -> dict:
    """Build template context with username, role, and permissions from JWT cookie."""
    user_ctx = _get_user_context(request.cookies.get("access_token"))
    ctx = {
        "request": request,
        "username": user_ctx["username"],
        "role": user_ctx["role"],
        "permissions": user_ctx["permissions"],
        "active_page": active_page,
    }
    if extra:
        ctx.update(extra)
    return ctx


@dashboard_router.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    return templates.TemplateResponse(request, "inbox.html", _ctx(request, "inbox"))

@dashboard_router.get("/email/{email_id}", response_class=HTMLResponse)
async def dashboard_email_detail(request: Request, email_id: int):
    return templates.TemplateResponse(request, "detail.html", _ctx(request, "inbox", {"email_id": email_id}))

@dashboard_router.get("/blocklist", response_class=HTMLResponse)
async def dashboard_blocklist(request: Request):
    return templates.TemplateResponse(request, "blocklist.html", _ctx(request, "blocklist"))

@dashboard_router.get("/whitelist", response_class=HTMLResponse)
async def dashboard_whitelist(request: Request):
    return templates.TemplateResponse(request, "whitelist.html", _ctx(request, "whitelist"))

@dashboard_router.get("/audit", response_class=HTMLResponse)
async def dashboard_audit(request: Request):
    return templates.TemplateResponse(request, "audit.html", _ctx(request, "audit"))

@dashboard_router.get("/reports", response_class=HTMLResponse)
async def dashboard_reports(request: Request):
    return templates.TemplateResponse(request, "reports.html", _ctx(request, "reports"))

@dashboard_router.get("/health", response_class=HTMLResponse)
async def dashboard_health(request: Request):
    return templates.TemplateResponse(request, "health.html", _ctx(request, "health"))

@dashboard_router.get("/history", response_class=HTMLResponse)
async def dashboard_history(request: Request):
    return templates.TemplateResponse(request, "history.html", _ctx(request, "history"))

@dashboard_router.get("/admin", response_class=HTMLResponse)
async def dashboard_admin(request: Request):
    ctx = _ctx(request, "admin")
    # Only admins can access the admin page
    if ctx.get("role") != "admin":
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "admin.html", ctx)

@dashboard_router.get("/manual-detonation", response_class=HTMLResponse)
async def dashboard_manual_detonation(request: Request):
    ctx = _ctx(request, "manual_detonation")
    if not _has_perm(ctx, "detonation.manual"):
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request, "manual_detonation.html", ctx)
