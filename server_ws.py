# server_ws.py
# Servidor WebSocket de chat LAN (sala única)
# Requisitos: pip install websockets

import asyncio
import json
from datetime import datetime
import websockets

HOST = "0.0.0.0"   # Escucha en todas las interfaces LAN
PORT = 8765
HISTORY_MAX = 50

# Conjunto de websockets conectados
clients = set()
# Historial básico en memoria
history = []


async def broadcast(payload: dict):
    """Enviar payload (dict) a todos los clientes como texto JSON."""
    if not clients:
        return
    msg = json.dumps(payload, ensure_ascii=False)
    await asyncio.gather(*[ws.send(msg) for ws in list(clients)], return_exceptions=True)


async def register(ws):
    clients.add(ws)


async def unregister(ws):
    clients.discard(ws)


def now_ts():
    return datetime.now().strftime("%H:%M:%S")


async def handler(ws):
    await register(ws)
    try:
        # Al conectar, enviar historial reciente
        if history:
            await ws.send(json.dumps({"type": "history", "items": history}, ensure_ascii=False))

        async for raw in ws:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                # Mensaje no-JSON: lo descartamos o lo envolvemos
                data = {"type": "msg", "user": "Desconocido", "text": raw}

            mtype = data.get("type", "msg")

            if mtype == "join":
                user = data.get("user", "Anon")
                event = {"type": "system", "text": f"🟢 {user} se unió", "time": now_ts()}
                history.append(event)
                history[:] = history[-HISTORY_MAX:]
                await broadcast(event)

            elif mtype == "msg":
                user = data.get("user", "Anon")
                text = data.get("text", "").strip()
                if not text:
                    continue
                event = {"type": "msg", "user": user, "text": text, "time": now_ts()}
                history.append(event)
                history[:] = history[-HISTORY_MAX:]
                await broadcast(event)

            elif mtype == "leave":
                user = data.get("user", "Anon")
                event = {"type": "system", "text": f"🔴 {user} salió", "time": now_ts()}
                history.append(event)
                history[:] = history[-HISTORY_MAX:]
                await broadcast(event)

            else:
                # Tipos no soportados
                await ws.send(json.dumps(
                    {"type": "error", "text": "tipo no soportado"},
                    ensure_ascii=False
                ))
    finally:
        await unregister(ws)


async def main():
    stop = asyncio.Future()
    async with websockets.serve(handler, HOST, PORT, ping_interval=20, ping_timeout=20):
        print(f"Servidor WebSocket escuchando en ws://{HOST}:{PORT}")
        await stop  # quedará pendiente hasta que lo canceles manualmente con Ctrl+C


if __name__ == "__main__":
    asyncio.run(main())
