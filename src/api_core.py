import os
from pathlib import Path
from fastapi.templating import Jinja2Templates
from fastapi import WebSocket, Request, Cookie
from typing import Optional
from database import SessionLocal
import jwt
import bcrypt

_SRC_DIR = Path(__file__).resolve().parent
_DASHBOARD_DIR = _SRC_DIR / "dashboard"
_TEMPLATES_DIR = _DASHBOARD_DIR / "templates"

_jinja_templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


def _generate_ws_token(username: str) -> str:
    """Generate a short-lived token for WebSocket authentication only."""
    from datetime import datetime, timedelta, timezone
    payload = {
        "sub": username,
        "purpose": "ws",
        "exp": datetime.now(timezone.utc) + timedelta(hours=8),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


class _NonceTemplates:
    """Wrapper that auto-injects CSP nonce and WS token into every TemplateResponse."""

    def __getattr__(self, name):
        return getattr(_jinja_templates, name)

    def TemplateResponse(self, request_or_name, *args, **kwargs):
        # Detect the calling convention used
        if isinstance(request_or_name, Request):
            request = request_or_name
        else:
            # Positional: (name, context_dict) — extract request from context
            ctx = args[0] if args else kwargs.get("context", {})
            request = ctx.get("request")

        # Inject nonce and WS token into context
        if request:
            nonce = getattr(request.state, "csp_nonce", "")
            username = getattr(request.state, "authenticated_user", None)
            ws_token = _generate_ws_token(username) if username else ""

            def _inject(d):
                d.setdefault("csp_nonce", nonce)
                d.setdefault("ws_token", ws_token)

            if args:
                for a in args:
                    if isinstance(a, dict):
                        _inject(a)
                        break
            if "context" in kwargs and isinstance(kwargs["context"], dict):
                _inject(kwargs["context"])

        return _jinja_templates.TemplateResponse(request_or_name, *args, **kwargs)


templates = _NonceTemplates()

# ISO 27001 Data Masking (A.8.11)
def mask_pii(email: str):
    if not email or "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if len(local) > 2:
        local = local[0] + "***" + local[-1]
    else:
        local = "***"
    return f"{local}@{domain}"

templates.env.filters["mask_pii"] = mask_pii


# --- Static asset cache-busting -------------------------------------------
# Append ?v=<file mtime> to static URLs so browsers ALWAYS fetch the current
# JS/CSS after a deploy. Without this, a stale cached dashboard.js can render
# UI (e.g. action buttons) the current RBAC gating would otherwise hide.
_STATIC_ROOT = _DASHBOARD_DIR / "static"


def static_v(path: str) -> str:
    try:
        v = int((_STATIC_ROOT / path).stat().st_mtime)
    except Exception:
        v = 0
    return f"/static/{path}?v={v}"


_jinja_templates.env.globals["static_v"] = static_v

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

class NotAuthenticatedException(Exception):
    pass

_jwt_secret = os.getenv("JWT_SECRET") or os.getenv("VAULT_ENCRYPTION_KEY")
if not _jwt_secret:
    raise RuntimeError(
        "JWT_SECRET is not set. "
        "The API refuses to start without a secure JWT signing key. "
        "Set JWT_SECRET in your .env file (must differ from VAULT_ENCRYPTION_KEY)."
    )
if _jwt_secret == os.getenv("VAULT_ENCRYPTION_KEY"):
    import warnings
    warnings.warn(
        "JWT_SECRET is the same as VAULT_ENCRYPTION_KEY. "
        "Set a separate JWT_SECRET in .env for defense-in-depth.",
        stacklevel=1,
    )
JWT_SECRET = _jwt_secret
ALGORITHM = "HS256"

# --- Token revocation blacklist (in-memory, survives until restart) ---
_revoked_tokens: set[str] = set()

def revoke_token(token: str) -> None:
    _revoked_tokens.add(token)

def is_token_revoked(token: str) -> bool:
    return token in _revoked_tokens

def get_db_generator():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class AuthenticatedUser:
    """Lightweight wrapper carrying identity + RBAC context through requests."""
    __slots__ = ("username", "role", "permissions", "user_id")

    def __init__(self, username: str, role: str = "viewer",
                 permissions: dict = None, user_id: int = None):
        self.username = username
        self.role = role
        self.permissions = permissions or {}
        self.user_id = user_id

    def has(self, permission: str) -> bool:
        if self.role == "admin":
            return True
        return bool(self.permissions.get(permission, False))

    def __str__(self):
        return self.username


def _load_user_context(username: str) -> Optional["AuthenticatedUser"]:
    """Load full RBAC context from DB for an authenticated username."""
    from database import User
    db = next(get_db_generator())
    try:
        user = db.query(User).filter(User.username == username, User.is_active == True).first()
        if not user:
            return None
        return AuthenticatedUser(
            username=user.username,
            role=user.role or "viewer",
            permissions=user.permissions or {},
            user_id=user.id,
        )
    finally:
        db.close()


async def verify_auth(request: Request, access_token: Optional[str] = Cookie(None)):
    if request.url.path in ["/login", "/api/login"] or request.url.path.startswith("/static"):
        return None

    username = None

    # HTTP Basic Auth was REMOVED: it authenticated with username+password only,
    # bypassing the mandatory TOTP second factor, and had no rate limiting — an
    # unthrottled, MFA-less brute-force surface. All access now requires a JWT
    # session cookie, which can only be obtained through the MFA login flow.
    if not access_token:
        raise NotAuthenticatedException()

    try:
        if is_token_revoked(access_token):
            raise NotAuthenticatedException()
        payload = jwt.decode(access_token, JWT_SECRET, algorithms=[ALGORITHM])
        username = payload.get("sub")
    except jwt.PyJWTError:
        raise NotAuthenticatedException()

    # Load full RBAC context
    auth_user = _load_user_context(username)
    if not auth_user:
        raise NotAuthenticatedException()

    request.state.authenticated_user = auth_user.username
    request.state.auth_user = auth_user
    return auth_user


def require_permission(permission: str):
    """FastAPI dependency that checks a specific permission after authentication.

    Usage:
        @router.post("/api/blocklist")
        async def add_blocklist(user: AuthenticatedUser = Depends(require_permission("blocklist.manage"))):
            ...
    """
    from fastapi import Depends, HTTPException

    async def _check(user: AuthenticatedUser = Depends(verify_auth)):
        if user is None:
            raise NotAuthenticatedException()
        if not user.has(permission):
            raise HTTPException(
                status_code=403,
                detail=f"Permission denied: {permission} required",
            )
        return user

    return _check
