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

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

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

JWT_SECRET = os.getenv("VAULT_ENCRYPTION_KEY", "fallback_secret_change_me")
ALGORITHM = "HS256"

def get_db_generator():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def verify_auth(request: Request, access_token: Optional[str] = Cookie(None)):
    if request.url.path in ["/login", "/api/login", "/api/internal/notify"] or request.url.path.startswith("/static"):
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
                if user and bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
                    return username
            except Exception:
                pass
        raise NotAuthenticatedException()

    try:
        payload = jwt.decode(access_token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload.get("sub")
    except jwt.PyJWTError:
        raise NotAuthenticatedException()
