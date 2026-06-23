import re

with open('src/api.py', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Add WebSocket imports
text = text.replace(
    'from fastapi import FastAPI, HTTPException, Query, Request',
    'from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect'
)

# 2. Add WebSocket manager
ws_manager_code = """
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
"""
text = text.replace(
    'app = FastAPI(',
    ws_manager_code + '\napp = FastAPI('
)

# 3. Add websocket endpoints
ws_endpoints = """
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

@app.post("/api/internal/notify")
async def api_internal_notify():
    await ws_manager.broadcast("refresh")
    return {"status": "ok"}

"""
text = text.replace(
    '# REST API — Email management',
    ws_endpoints + '\n# REST API — Email management'
)

with open('src/api.py', 'w', encoding='utf-8') as f:
    f.write(text)

print("WebSockets patched in api.py")
