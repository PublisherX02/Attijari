from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from api_core import ws_manager

ws_router = APIRouter()

@ws_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

@ws_router.post("/api/internal/notify")
async def api_internal_notify():
    await ws_manager.broadcast("refresh")
    return {"status": "ok"}
