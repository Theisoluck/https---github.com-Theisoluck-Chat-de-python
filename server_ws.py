import asyncio
import json
import os
import socket
from datetime import datetime
import websockets
from crypto_utils import derive_key, encrypt_json, decrypt_json

# =============================
# Configuración sin hard coding
# =============================
HOST = os.getenv("SERVER_HOST", "0.0.0.0")
PORT = int(os.getenv("SERVER_PORT", "8765"))
HISTORY_MAX = int(os.getenv("HISTORY_MAX", "50"))
BROADCAST_PORT = int(os.getenv("CHAT_BROADCAST_PORT", "9999"))
BROADCAST_INTERVAL = float(os.getenv("CHAT_BROADCAST_INTERVAL", "2.0"))
DISCOVERY_TOKEN = os.getenv("CHAT_DISCOVERY_TOKEN")
SECRET_PASSWORD = os.getenv("CHAT_SECRET")

if not SECRET_PASSWORD:
    raise RuntimeError("❌ CHAT_SECRET no está definido.")
if not DISCOVERY_TOKEN:
    raise RuntimeError("❌ CHAT_DISCOVERY_TOKEN no está definido.")

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

    async def presence_broadcaster():
        def get_local_ip():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
            except Exception:
                return "127.0.0.1"
            finally:
                s.close()

        local_ip = get_local_ip()
        payload = json.dumps({"token": DISCOVERY_TOKEN, "host": local_ip, "port": PORT})

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        while True:
            try:
                sock.sendto(payload.encode(), ("<broadcast>", BROADCAST_PORT))
            except Exception:
                pass
            await asyncio.sleep(BROADCAST_INTERVAL)

    broadcaster_task = asyncio.create_task(presence_broadcaster())

    try:
        async with websockets.serve(handler, HOST, PORT, ping_interval=20, ping_timeout=20):
            await asyncio.Future()
    finally:
        broadcaster_task.cancel()


if __name__ == "__main__":
    asyncio.run(main())
