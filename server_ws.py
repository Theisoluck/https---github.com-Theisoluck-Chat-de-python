# server_ws.py
# Servidor WebSocket de chat LAN (sala única) CON CIFRADO
# Requisitos: pip install websockets pycryptodome

import asyncio
import json
from datetime import datetime
import websockets

# Importar utilidades de cifrado
from crypto_utils import derive_key, encrypt_json, decrypt_json

HOST = "0.0.0.0"   # Escucha en todas las interfaces LAN
PORT = 8765
HISTORY_MAX = 50

# Clave compartida para el cifrado (DEBE SER LA MISMA EN CLIENTE Y SERVIDOR)
SECRET_PASSWORD = "mi-clave-secreta-chat-lan-2024"
key, salt = derive_key(SECRET_PASSWORD)

# Conjunto de websockets conectados
clients = set()
# Historial básico en memoria
history = []


async def broadcast(payload: dict):
    """Enviar payload (dict) cifrado a todos los clientes."""
    if not clients:
        return
    # Cifrar el mensaje antes de enviarlo
    encrypted_msg = encrypt_json(payload, key)
    await asyncio.gather(*[ws.send(encrypted_msg) for ws in list(clients)], return_exceptions=True)


async def register(ws):
    clients.add(ws)


async def unregister(ws):
    clients.discard(ws)


def now_ts():
    return datetime.now().strftime("%H:%M:%S")


async def handler(ws):
    await register(ws)
    try:
        # Al conectar, enviar historial reciente CIFRADO
        if history:
            encrypted_history = encrypt_json({"type": "history", "items": history}, key)
            await ws.send(encrypted_history)

        async for encrypted_raw in ws:
            try:
                # Descifrar el mensaje recibido
                data = decrypt_json(encrypted_raw, key)
            except (json.JSONDecodeError, ValueError) as e:
                # Mensaje no válido o error de descifrado
                error_msg = encrypt_json({"type": "error", "text": f"Error de descifrado: {e}"}, key)
                await ws.send(error_msg)
                continue

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
                error_response = encrypt_json(
                    {"type": "error", "text": "tipo no soportado"},
                    key
                )
                await ws.send(error_response)
    finally:
        await unregister(ws)


async def main():
    stop = asyncio.Future()
    print(f"🔐 Servidor WebSocket CON CIFRADO escuchando en ws://{HOST}:{PORT}")
    print(f"📝 Usando cifrado AES-GCM con clave derivada de contraseña")
    async with websockets.serve(handler, HOST, PORT, ping_interval=20, ping_timeout=20):
        await stop  # quedará pendiente hasta que lo canceles manualmente con Ctrl+C


if __name__ == "__main__":
    asyncio.run(main())