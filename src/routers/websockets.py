from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from typing import Optional
import jwt as pyjwt
from api_core import ws_manager, verify_auth, JWT_SECRET, ALGORITHM, is_token_revoked

ws_router = APIRouter()

@ws_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = Query(None)):
    # Authenticate WebSocket via token query parameter
    if not token or is_token_revoked(token):
        await websocket.close(code=1008, reason="Unauthorized")
        return
    try:
        pyjwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except pyjwt.PyJWTError:
        await websocket.close(code=1008, reason="Invalid token")
        return

    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

@ws_router.post("/api/internal/notify", dependencies=[Depends(verify_auth)])
async def api_internal_notify():
    await ws_manager.broadcast("refresh")
    return {"status": "ok"}
