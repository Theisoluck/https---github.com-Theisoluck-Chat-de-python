"""server_ws.py

Lightweight WebSocket chat server with LAN presence broadcasting.
The server broadcasts a small UDP presence packet periodically so clients
can discover it automatically on the LAN. Secret/password is read from the
environment variable `CHAT_SECRET` (falls back to the previous default for
backwards compatibility).
"""

import asyncio
import json
import os
import socket
from datetime import datetime
import websockets
from crypto_utils import derive_key, encrypt_json, decrypt_json

# Configurable via environment variables to avoid hard-coded values
HOST = os.getenv("SERVER_HOST", "0.0.0.0")
PORT = int(os.getenv("SERVER_PORT", "8765"))
HISTORY_MAX = int(os.getenv("HISTORY_MAX", "50"))

# Secret can be supplied through environment variable CHAT_SECRET
# For quick testing this falls back to the original hard-coded value,
# but storing the secret in env is recommended instead of editing source.
SECRET_PASSWORD = os.getenv("CHAT_SECRET", "mi-clave-secreta-chat-lan-2024")
key = derive_key(SECRET_PASSWORD)

clients = set()
history = []

# UDP broadcast settings for presence discovery
BROADCAST_PORT = int(os.getenv("CHAT_BROADCAST_PORT", "9999"))
BROADCAST_INTERVAL = float(os.getenv("CHAT_BROADCAST_INTERVAL", "2.0"))
DISCOVERY_TOKEN = "chat_lan_v1"

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

    # Start presence broadcaster task so clients can discover this server
    async def presence_broadcaster():
        try:
            # Determine a reasonable local IP to advertise
            def get_local_ip():
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    # doesn't need to be reachable; used to get local interface IP
                    s.connect(("8.8.8.8", 80))
                    return s.getsockname()[0]
                except Exception:
                    return "127.0.0.1"
                finally:
                    s.close()

            local_ip = get_local_ip()
            payload = json.dumps({"token": DISCOVERY_TOKEN, "host": local_ip, "port": PORT})

            # Create a UDP socket for broadcasting
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            while True:
                try:
                    sock.sendto(payload.encode(), ("<broadcast>", BROADCAST_PORT))
                except Exception:
                    # ignore transient network errors
                    pass
                await asyncio.sleep(BROADCAST_INTERVAL)
        except asyncio.CancelledError:
            return

    broadcaster_task = asyncio.create_task(presence_broadcaster())

    try:
        async with websockets.serve(handler, HOST, PORT, ping_interval=20, ping_timeout=20):
            await asyncio.Future()  # Mantener servidor activo
    finally:
        broadcaster_task.cancel()

if __name__ == "__main__":
    asyncio.run(main())
