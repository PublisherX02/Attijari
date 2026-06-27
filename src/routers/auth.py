import os
import bcrypt
import pyotp
import jwt
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from api_core import templates, get_db_generator, JWT_SECRET, ALGORITHM

auth_router = APIRouter()
_limiter = Limiter(key_func=get_remote_address)

@auth_router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@auth_router.post("/login")
@_limiter.limit("5/minute")
async def login_post(request: Request, username: str = Form(...), password: str = Form(...), totp: str = Form(...), db = Depends(get_db_generator)):
    from database import User
    
    user = db.query(User).filter(User.username == username).first()
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        return templates.TemplateResponse("login.html", {"request": {}, "error": "Invalid username or password"})
        
    if user.totp_secret:
        totp_obj = pyotp.TOTP(user.totp_secret)
        if not totp_obj.verify(totp):
            return templates.TemplateResponse("login.html", {"request": {}, "error": "Invalid MFA code"})
            
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(hours=8)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)
    
    response = RedirectResponse(url="/", status_code=303)
    is_https = os.getenv("FORCE_HTTPS", "").lower() in ("1", "true", "yes")
    response.set_cookie(
        key="access_token", value=token,
        httponly=True, samesite="strict", secure=is_https,
        path="/", max_age=28800,
    )
    return response

@auth_router.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response
