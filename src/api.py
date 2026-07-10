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
import asyncio
import secrets
from pathlib import Path

from dotenv import load_dotenv

# Ensure src/ on path
_SRC_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SRC_DIR))

load_dotenv()

from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from database import init_db
from metrics import api_requests_total, api_request_duration_seconds
from api_core import verify_auth, NotAuthenticatedException


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


# Rate limiter — keyed by real client IP (not spoofable X-Forwarded-For)
limiter = Limiter(key_func=_get_real_client_ip, default_limits=["200/minute"])

from routers.auth import auth_router
from routers.dashboard import dashboard_router
from routers.websockets import ws_router
from routers.emails import emails_router
from routers.users import users_router
from tasks.background import data_retention_and_backup_task
from routers.emails import _run_pipeline_sync
from api_core import ws_manager

app = FastAPI(
    title="Attijari SOC Dashboard",
    description="Email security triage system — analyst review interface",
    version="2.0.0",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.exception_handler(NotAuthenticatedException)
async def auth_exception_handler(request: Request, exc: NotAuthenticatedException):
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=401, content={"detail": "Not authenticated. Log in via the MFA login flow to obtain a session."})
    return RedirectResponse(url="/login", status_code=303)

_STATIC_DIR = _SRC_DIR / "dashboard" / "static"
if _STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

@app.middleware("http")
async def security_and_metrics_middleware(request: Request, call_next):
    t0 = time.time()
    # Generate per-request nonce for inline scripts
    nonce = secrets.token_urlsafe(16)
    request.state.csp_nonce = nonce
    response = await call_next(request)
    elapsed = time.time() - t0

    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        # Scripts must carry the per-request nonce — no 'unsafe-inline', so an
        # injected inline <script> without the nonce is blocked (XSS defense).
        f"script-src 'self' 'nonce-{nonce}'; "
        # style-src keeps 'unsafe-inline': inline style="" attributes cannot use
        # a nonce, and inline styles are not the injection risk scripts are.
        f"style-src 'self' 'unsafe-inline'; "
        f"connect-src 'self' ws: wss:; "
        f"font-src 'self' https://fonts.gstatic.com"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

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

# Background polling
_poll_task = None
_retention_task = None
_scan_lock = asyncio.Lock()
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SECONDS", "60"))

async def _background_poll():
    await asyncio.sleep(5)
    import detonation_state
    while True:
        try:
            if detonation_state.is_active():
                # A drained detonation window is running; skip this tick so we
                # don't reload Ollama/Docker and blow the memory budget.
                print("[POLL] Detonation active — skipping this poll tick")
            else:
                async with _scan_lock:
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(None, _run_pipeline_sync)
                    await ws_manager.broadcast("refresh")
        except Exception as e:
            print(f"[POLL] Pipeline error: {e}")
        await asyncio.sleep(POLL_INTERVAL)

def _update_gauge_metrics():
    # Placeholder to update metrics at startup
    pass

@app.on_event("startup")
async def startup():
    global _poll_task, _retention_task
    init_db()
    _update_gauge_metrics()
    _poll_task = asyncio.create_task(_background_poll())
    _retention_task = asyncio.create_task(data_retention_and_backup_task())
    print(f"[POLL] Background IMAP polling started (every {POLL_INTERVAL}s)")

@app.on_event("shutdown")
async def shutdown():
    global _poll_task, _retention_task
    if _poll_task:
        _poll_task.cancel()
    if _retention_task:
        _retention_task.cancel()

# Include Routers
app.include_router(auth_router)
app.include_router(dashboard_router, dependencies=[Depends(verify_auth)])
app.include_router(ws_router)
app.include_router(emails_router, dependencies=[Depends(verify_auth)])
app.include_router(users_router, dependencies=[Depends(verify_auth)])

# Import metrics endpoint locally to avoid circular dependencies if it exists
try:
    from fastapi.responses import PlainTextResponse
    from metrics import get_metrics_text
    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics_endpoint():
        return get_metrics_text()
except ImportError:
    pass
