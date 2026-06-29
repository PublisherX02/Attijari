from fastapi import APIRouter, Request, Cookie
from fastapi.responses import HTMLResponse
from typing import Optional
import jwt

from api_core import templates, JWT_SECRET, ALGORITHM

dashboard_router = APIRouter()


def _get_username(access_token: Optional[str]) -> Optional[str]:
    """Extract username from JWT cookie, return None if invalid/missing."""
    if not access_token:
        return None
    try:
        payload = jwt.decode(access_token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None


def _ctx(request: Request, active_page: str, extra: dict = None) -> dict:
    """Build template context with username from JWT cookie."""
    username = _get_username(request.cookies.get("access_token"))
    ctx = {"request": request, "username": username, "active_page": active_page}
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
