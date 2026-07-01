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

async def verify_auth(request: Request, access_token: Optional[str] = Cookie(None)):
    if request.url.path in ["/login", "/api/login"] or request.url.path.startswith("/static"):
        return None

    if not access_token:
        # For API clients without cookies, fallback to Basic Auth
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Basic "):
            import base64
            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                username, password = decoded.split(":", 1)
                db = next(get_db_generator())
                from database import User
                user = db.query(User).filter(User.username == username).first()
                # Always call bcrypt to prevent timing-based username enumeration
                _dummy_hash = "$2b$12$LJ3m4ys3Lg2F55HBz6E6ceRzNKPRtTBBBfUvKXFLT7gaBMvHy1jCe"
                hash_to_check = user.password_hash if user else _dummy_hash
                password_valid = bcrypt.checkpw(password.encode("utf-8"), hash_to_check.encode("utf-8"))
                if user and password_valid:
                    request.state.authenticated_user = username
                    return username
            except Exception:
                pass
        raise NotAuthenticatedException()

    try:
        if is_token_revoked(access_token):
            raise NotAuthenticatedException()
        payload = jwt.decode(access_token, JWT_SECRET, algorithms=[ALGORITHM])
        username = payload.get("sub")
        request.state.authenticated_user = username
        return username
    except jwt.PyJWTError:
        raise NotAuthenticatedException()
