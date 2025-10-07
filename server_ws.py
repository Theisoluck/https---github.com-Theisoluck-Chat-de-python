import asyncio
import json
from datetime import datetime
import websockets
# Importar solo las funciones RSA
from crypto_utils import generate_rsa_key_pair, encrypt_rsa_message, decrypt_rsa_message, MAX_PLAINTEXT_BYTES

# --- Configuración y Claves ---
HOST = "192.168.0.104"
PORT = 8765
HISTORY_MAX = 50

# Generar claves RSA del servidor una sola vez
SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = generate_rsa_key_pair()

# Almacenamiento
clients = set()
# Diccionario para almacenar la clave pública de CADA cliente
client_public_keys = {}
history = []

# --- Funciones de Utilidad ---

async def broadcast(payload: dict):
    """
    Envía un payload a todos los clientes, cifrando individualmente 
    con la clave pública RSA de CADA cliente.
    """
    if not clients:
        return
    
    send_tasks = []
    
    # Cifrar el mensaje individualmente para cada cliente
    for ws in list(clients):
        # SOLO enviar si el cliente ya completó el handshake (tiene una clave pública asignada)
        if ws in client_public_keys:
            client_pub_key = client_public_keys[ws]
            
            try:
                # El servidor cifra con la CLAVE PÚBLICA del cliente (solo el cliente puede descifrar)
                encrypted_msg = encrypt_rsa_message(payload, client_pub_key)
                send_tasks.append(ws.send(encrypted_msg))
            except ValueError as e:
                # Esto sucederá si el mensaje de broadcast es demasiado largo
                print(f"⚠️ Error de cifrado RSA para broadcast: {e}")
            except Exception as e:
                print(f"Error al cifrar broadcast: {e}")
            
    if send_tasks:
        await asyncio.gather(*send_tasks, return_exceptions=True)

async def register(ws):
    clients.add(ws)

async def unregister(ws):
    clients.discard(ws)
    if ws in client_public_keys:
        del client_public_keys[ws] # Eliminar clave pública al desconectar

def now_ts():
    return datetime.now().strftime("%H:%M:%S")

# --- Lógica de Handshake RSA ---

async def handle_key_exchange(ws):
    """
    Paso 1: Servidor envía su clave pública RSA.
    Paso 2: Servidor espera la clave pública RSA del cliente y la almacena.
    """
    # 1. Enviar clave pública RSA del servidor al cliente (sin cifrar)
    public_key_payload_server = json.dumps({
        "type": "server_public_key", 
        "key": SERVER_PUBLIC_KEY.decode()
    })
    await ws.send(public_key_payload_server)
    
    # 2. Esperar el primer mensaje del cliente (debe contener su clave pública)
    client_pub_key_raw = await ws.recv()
    
    try:
        key_exchange_data = json.loads(client_pub_key_raw)
        
        if key_exchange_data.get("type") != "client_public_key":
            print("Error: El cliente no envió su clave pública.")
            return False
            
        client_pub_key = key_exchange_data["key"].encode()
        
        # Almacenar la clave pública del cliente para futuras respuestas (broadcast)
        client_public_keys[ws] = client_pub_key
        print(f"🔐 Clave pública del cliente almacenada: {ws.id}")
        return True
        
    except Exception as e:
        print(f"⚠️ Error en la recepción de la clave pública del cliente: {e}")
        return False


async def handler(ws):
    await register(ws)
    
    # 1. Ejecutar intercambio de claves (HANDSHAKE)
    if not await handle_key_exchange(ws):
        await unregister(ws)
        return

    # Obtener la clave pública del cliente para enviar el mensaje inicial cifrado
    client_pub_key = client_public_keys[ws]

    try:
        # Enviar mensaje de confirmación de cifrado (cifrado con la clave pública del cliente)
        initial_msg = {"type": "system", "text": f"✅ Cifrado RSA Asimétrico iniciado. Limite de mensaje: {MAX_PLAINTEXT_BYTES} bytes."}
        await ws.send(encrypt_rsa_message(initial_msg, client_pub_key))


        async for encrypted_raw in ws:
            try:
                # Descifrar el mensaje con la CLAVE PRIVADA del servidor
                data = decrypt_rsa_message(encrypted_raw, SERVER_PRIVATE_KEY)
            except ValueError as e:
                # Error de longitud de mensaje o padding
                error_payload = {"type": "error", "text": f"Error: {e}. El mensaje es demasiado largo para RSA."}
                await ws.send(encrypt_rsa_message(error_payload, client_pub_key))
                continue
            except Exception as e:
                error_payload = {"type": "error", "text": f"Error de descifrado RSA (datos corruptos): {e}"}
                await ws.send(encrypt_rsa_message(error_payload, client_pub_key))
                continue

            # --- Lógica de Chat ---
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
                error_payload = {"type": "error", "text": "Tipo de mensaje no soportado"}
                await ws.send(encrypt_rsa_message(error_payload, client_pub_key))
                continue

            history.append(event)
            history[:] = history[-HISTORY_MAX:]
            await broadcast(event)

    finally:
        await unregister(ws)


async def main():
    print(f"🔑 Servidor RSA iniciado.")
    print(f"⚠️ ADVERTENCIA: Este modo es solo RSA. Los mensajes tienen un límite estricto de {MAX_PLAINTEXT_BYTES} bytes.")
    print(f"🔐 Servidor escuchando en ws://{HOST}:{PORT}")
    async with websockets.serve(handler, HOST, PORT, ping_interval=20, ping_timeout=20):
        await asyncio.Future() 

if __name__ == "__main__":
    asyncio.run(main())
