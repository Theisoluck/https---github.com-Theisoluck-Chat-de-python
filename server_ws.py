# server_ws.py
import asyncio
import json
from datetime import datetime
import websockets
from crypto_utils import derive_key, encrypt_json, decrypt_json

HOST = "0.0.0.0"
PORT = 8765
HISTORY_MAX = 50

SECRET_PASSWORD = "mi-clave-secreta-chat-lan-2024"
key = derive_key(SECRET_PASSWORD)

clients = set()
history = []

async def broadcast(payload: dict):
    if not clients:
        return
    encrypted_msg = encrypt_json(payload, key)
    await asyncio.gather(*(ws.send(encrypted_msg) for ws in list(clients)), return_exceptions=True)

async def register(ws):
    clients.add(ws)

async def unregister(ws):
    clients.discard(ws)

def now_ts():
    return datetime.now().strftime("%H:%M:%S")

async def handler(ws):
    await register(ws)
    try:
        # Enviar historial al nuevo cliente
        if history:
            await ws.send(encrypt_json({"type": "history", "items": history}, key))

        async for encrypted_raw in ws:
            try:
                data = decrypt_json(encrypted_raw, key)
            except Exception as e:
                await ws.send(encrypt_json({"type": "error", "text": f"Error de descifrado: {e}"}, key))
                continue

            mtype = data.get("type")
            user = data.get("user", "Anon")

            if mtype == "join":
                event = {"type": "system", "text": f"🟢 {user} se unió", "time": now_ts()}
            elif mtype == "msg":
                text = data.get("text", "").strip()
                if not text:
                    continue
                event = {"type": "msg", "user": user, "text": text, "time": now_ts()}
            elif mtype == "leave":
                event = {"type": "system", "text": f"🔴 {user} salió", "time": now_ts()}
            else:
                await ws.send(encrypt_json({"type": "error", "text": "Tipo no soportado"}, key))
                continue

            history.append(event)
            history[:] = history[-HISTORY_MAX:]
            await broadcast(event)

    finally:
        await unregister(ws)

async def main():
    print(f"🔐 Servidor escuchando en ws://{HOST}:{PORT}")
    async with websockets.serve(handler, HOST, PORT, ping_interval=20, ping_timeout=20):
        await asyncio.Future()  # Mantener servidor activo

if __name__ == "__main__":
    asyncio.run(main())
