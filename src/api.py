"""api.py — FastAPI application for the Attijari Security Dashboard.

Serves:
  - REST API for email review, blocklist/whitelist management, reports
  - Jinja2-templated dashboard pages
  - Prometheus /metrics endpoint
  - System health checks

Start with:  uvicorn src.api:app --host 127.0.0.1 --port 8000
Or via main: python src/main.py --serve
(Bind to loopback and front with a TLS reverse proxy; never expose 0.0.0.0
plain-HTTP on an untrusted network.)
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

from redis_async_lock import RedisAsyncLock

from fastapi import FastAPI, Request, Depends
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from database import init_db
from metrics import api_requests_total, api_request_duration_seconds
from api_core import verify_auth, NotAuthenticatedException, limiter

from routers.auth import auth_router
from routers.dashboard import dashboard_router
from routers.websockets import ws_router
from routers.emails import emails_router
from routers.users import users_router
from routers.mailboxes import mailboxes_router
from routers.detonation_proxy import detonation_proxy_router, detonation_ws_router
from tasks.background import data_retention_and_backup_task
from routers.emails import _run_pipeline_sync
from api_core import ws_manager

app = FastAPI(
    title="Attijari Security Dashboard",
    description="AI-assisted email security triage — analyst review interface",
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
    # The two framed surfaces (proxied CAPE report, attachment preview) must
    # allow same-origin framing; XFO is evaluated on the FRAMED response, so
    # DENY there would block our own iframes. Everything else stays DENY.
    _p = request.url.path
    _frameable = _p.startswith("/api/detonation/report/") or (
        _p.startswith("/api/emails/") and _p.endswith("/raw")
    )
    response.headers["X-Frame-Options"] = "SAMEORIGIN" if _frameable else "DENY"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        # Nonce-based policy for scripts (SEC-M1). Inline handlers were
        # refactored to data-action delegation and every remaining inline
        # <script> carries the same per-request nonce set above. We omit the
        # unsafe-inline keyword deliberately: naming a nonce makes browsers
        # ignore it anyway, and dropping it means an injected inline script
        # without the nonce will not run.
        f"script-src 'self' 'nonce-{nonce}'; "
        # style-src keeps 'unsafe-inline': inline style="" attributes cannot use
        # a nonce, and inline styles are not the injection risk scripts are.
        f"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        f"connect-src 'self' ws: wss:; "
        # Same-origin iframes only: the proxied CAPE report and the /raw
        # attachment preview. Nothing cross-origin is ever framed.
        f"frame-src 'self'; "
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
_gmail_bridge_task = None
_pop3_bridge_task = None
_scan_lock = RedisAsyncLock("pipeline_scan", timeout=600)
_smtp_controller = None
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL_SECONDS", "60"))

# Bridges real Gmail mail into the local SMTP receiver (see
# src/gmail_smtp_bridge.py) — restores the personal-Gmail demo path that the
# 2026-07-24 SMTP-only ingestion change otherwise left with no real mail
# source. Disable if you only want the swaks/smtplib test-client path the
# SMTP ingestion spec originally described.
GMAIL_BRIDGE_ENABLED = os.getenv("GMAIL_BRIDGE_ENABLED", "1") != "0"
GMAIL_BRIDGE_INTERVAL = int(os.getenv("GMAIL_BRIDGE_INTERVAL_SECONDS", "60"))

async def _gmail_bridge_poll():
    await asyncio.sleep(5)
    from gmail_smtp_bridge import run_once as _bridge_run_once
    while True:
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _bridge_run_once)
        except Exception as e:
            print(f"[GMAIL-BRIDGE] Tick error: {e}")
        await asyncio.sleep(GMAIL_BRIDGE_INTERVAL)

POP3_BRIDGE_ENABLED = os.getenv("POP3_BRIDGE_ENABLED", "1") != "0"
POP3_BRIDGE_INTERVAL = int(os.getenv("POP3_BRIDGE_INTERVAL_SECONDS", "60"))

async def _pop3_bridge_poll():
    await asyncio.sleep(5)
    from pop3_smtp_bridge import run_once as _pop3_bridge_run_once
    while True:
        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _pop3_bridge_run_once)
        except Exception as e:
            print(f"[POP3-BRIDGE] Tick error: {e}")
        await asyncio.sleep(POP3_BRIDGE_INTERVAL)

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
    global _poll_task, _retention_task, _smtp_controller, _gmail_bridge_task, _pop3_bridge_task
    init_db()
    _update_gauge_metrics()
    _poll_task = asyncio.create_task(_background_poll())
    _retention_task = asyncio.create_task(data_retention_and_backup_task())
    print(f"[POLL] Background pipeline tick started (every {POLL_INTERVAL}s)")

    from smtp_receiver import build_controller
    _smtp_controller = build_controller()
    _smtp_controller.start()
    print(f"[SMTP] Inbound receiver listening on "
          f"{_smtp_controller.hostname}:{_smtp_controller.port}")

    if GMAIL_BRIDGE_ENABLED:
        _gmail_bridge_task = asyncio.create_task(_gmail_bridge_poll())
        print(f"[GMAIL-BRIDGE] Started (every {GMAIL_BRIDGE_INTERVAL}s)")

    if POP3_BRIDGE_ENABLED:
        _pop3_bridge_task = asyncio.create_task(_pop3_bridge_poll())
        print(f"[POP3-BRIDGE] Started (every {POP3_BRIDGE_INTERVAL}s)")

@app.on_event("shutdown")
async def shutdown():
    global _poll_task, _retention_task, _smtp_controller, _gmail_bridge_task, _pop3_bridge_task
    if _poll_task:
        _poll_task.cancel()
    if _retention_task:
        _retention_task.cancel()
    if _gmail_bridge_task:
        _gmail_bridge_task.cancel()
    if _pop3_bridge_task:
        _pop3_bridge_task.cancel()
    if _smtp_controller:
        _smtp_controller.stop()
        print("[SMTP] Inbound receiver stopped")

# Include Routers
app.include_router(auth_router)
app.include_router(dashboard_router, dependencies=[Depends(verify_auth)])
app.include_router(ws_router)
app.include_router(emails_router, dependencies=[Depends(verify_auth)])
app.include_router(users_router, dependencies=[Depends(verify_auth)])
app.include_router(mailboxes_router, dependencies=[Depends(verify_auth)])
app.include_router(detonation_proxy_router, dependencies=[Depends(verify_auth)])
# No verify_auth here: the WS route does its own token-based auth (_ws_token_ok) —
# a WebSocket scope has no HTTP Request for verify_auth to depend on.
app.include_router(detonation_ws_router)

# Import metrics endpoint locally to avoid circular dependencies if it exists
try:
    from fastapi.responses import PlainTextResponse
    from metrics import get_metrics_text
    @app.get("/metrics", response_class=PlainTextResponse)
    async def metrics_endpoint():
        return get_metrics_text()
except ImportError:
    pass
