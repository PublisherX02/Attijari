from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from api_core import templates

dashboard_router = APIRouter()

@dashboard_router.get("/", response_class=HTMLResponse)
async def dashboard_home(request: Request):
    return templates.TemplateResponse(request, "inbox.html", {"request": request})

@dashboard_router.get("/email/{email_id}", response_class=HTMLResponse)
async def dashboard_email_detail(request: Request, email_id: int):
    return templates.TemplateResponse(request, "detail.html", {"request": request, "email_id": email_id})

@dashboard_router.get("/blocklist", response_class=HTMLResponse)
async def dashboard_blocklist(request: Request):
    return templates.TemplateResponse(request, "blocklist.html", {"request": request})

@dashboard_router.get("/whitelist", response_class=HTMLResponse)
async def dashboard_whitelist(request: Request):
    return templates.TemplateResponse(request, "whitelist.html", {"request": request})

@dashboard_router.get("/audit", response_class=HTMLResponse)
async def dashboard_audit(request: Request):
    return templates.TemplateResponse(request, "audit.html", {"request": request})

@dashboard_router.get("/reports", response_class=HTMLResponse)
async def dashboard_reports(request: Request):
    return templates.TemplateResponse(request, "reports.html", {"request": request})

@dashboard_router.get("/health", response_class=HTMLResponse)
async def dashboard_health(request: Request):
    return templates.TemplateResponse(request, "health.html", {"request": request})
