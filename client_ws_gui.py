import asyncio
import json
import threading
import queue
import tkinter as tk
from tkinter import simpledialog, scrolledtext
import websockets
from crypto_utils import generate_rsa_key_pair, encrypt_rsa_message, decrypt_rsa_message, MAX_PLAINTEXT_BYTES

SERVER_HOST = "192.168.111.230"
SERVER_PORT = 8765

class WSClientThread(threading.Thread):
    def __init__(self, username, server_url, inbound_q, outbound_q, on_disconnect):
        super().__init__(daemon=True)
        self.username = username
        self.server_url = server_url
        self.inbound_q = inbound_q
        self.outbound_q = outbound_q
        self.on_disconnect = on_disconnect
        self.stop_flag = threading.Event()
        
        # Claves RSA del cliente: Privada (para descifrar) y Pública (para el servidor)
        self.client_private_key, self.client_public_key = generate_rsa_key_pair()
        
        # Clave pública RSA del servidor (se recibe en el handshake, para cifrar)
        self.server_public_key = None 

    def stop(self):
        self.stop_flag.set()

    async def ws_loop(self):
        try:
            async with websockets.connect(self.server_url) as ws:
                
                # --- PASO 1: Handshake RSA (Intercambio de Claves) ---
                if not await self.handle_key_exchange(ws):
                    self.inbound_q.put({"type": "error", "text": "Falló la negociación de claves RSA."})
                    return

                # Si el handshake fue exitoso, notificar la conexión
                self.inbound_q.put({"type": "system", "text": f"Conectado a {self.server_url} como {self.username}"})
                self.inbound_q.put({"type": "system", "text": f"🔐 Cifrado RSA exclusivo activo. Límite de mensaje: {MAX_PLAINTEXT_BYTES} bytes."})

                # Enviar mensaje de JOIN cifrado con la clave pública del servidor
                join_msg = encrypt_rsa_message({"type": "join", "user": self.username}, self.server_public_key)
                await ws.send(join_msg)

                # Tareas de envío y recepción
                await asyncio.gather(self.recv_task(ws), self.send_task(ws))
                
        except Exception as e:
            self.inbound_q.put({"type": "system", "text": f"Desconectado del servidor: {e}"})
        finally:
            self.on_disconnect()

    async def handle_key_exchange(self, ws):
        """Recibe la clave pública RSA del servidor y envía la del cliente."""
        
        # 1. Recibir la clave pública RSA del servidor
        initial_response = await ws.recv()
        data = json.loads(initial_response)
        
        if data.get("type") != "server_public_key":
            return False

        self.server_public_key = data["key"].encode()

        # 2. Enviar nuestra clave pública al servidor
        key_exchange_payload = json.dumps({
            "type": "client_public_key", 
            "key": self.client_public_key.decode()
        })
        await ws.send(key_exchange_payload)
        
        return True

    async def recv_task(self, ws):
        async for encrypted_raw in ws:
            try:
                # Descifrar con la CLAVE PRIVADA del cliente
                data = decrypt_rsa_message(encrypted_raw, self.client_private_key)
            except Exception as e:
                # Si el mensaje no se puede descifrar, puede ser un error, o un mensaje no destinado a nosotros.
                data = {"type": "error", "text": f"Error descifrando mensaje RSA (privada de cliente): {e}"}
            self.inbound_q.put(data)

    async def send_task(self, ws):
        while not self.stop_flag.is_set():
            try:
                # Recibir payload cifrado de la GUI (Cola de salida)
                encrypted_item = await asyncio.get_event_loop().run_in_executor(None, self.outbound_q.get)
                if encrypted_item is None:
                    break
                await ws.send(encrypted_item)
            except Exception:
                break

    def run(self):
        asyncio.run(self.ws_loop())

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat LAN RSA Exclusivo 🔐")

        # --- Configuración de la GUI (omito por brevedad, es igual) ---
        top = tk.Frame(root)
        top.pack(fill="both", expand=True, padx=10, pady=10)

        self.txt = scrolledtext.ScrolledText(top, state="disabled", wrap="word", height=20)
        self.txt.pack(fill="both", expand=True)

        entry_frame = tk.Frame(top)
        entry_frame.pack(fill="x", pady=(8, 0))

        self.entry = tk.Entry(entry_frame)
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<Return>", self.send_msg)

        self.btn = tk.Button(entry_frame, text="Enviar (RSA) 🔒", command=self.send_msg)
        self.btn.pack(side="left", padx=(6, 0))
        
        # --- Configuración de Conexión ---
        self.username = simpledialog.askstring("Nombre", "Introduce tu nombre:", parent=self.root) or "Anon"
        server_ip = simpledialog.askstring("Servidor", "IP del servidor:", parent=self.root) or SERVER_HOST
        self.server_url = f"ws://{server_ip}:{SERVER_PORT}"

        self.inbound_q = queue.Queue()
        self.outbound_q = queue.Queue()

        self.ws_thread = WSClientThread(self.username, self.server_url, self.inbound_q, self.outbound_q, self.on_disconnect)
        self.ws_thread.start()

        self.root.after(100, self.process_inbound)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def append_text(self, text):
        self.txt.configure(state="normal")
        self.txt.insert("end", text + "\n")
        self.txt.see("end")
        self.txt.configure(state="disabled")

    def process_inbound(self):
        try:
            while True:
                data = self.inbound_q.get_nowait()
                self.render_item(data)
        except queue.Empty:
            pass
        self.root.after(100, self.process_inbound)

    def render_item(self, item):
        t = item.get("time", "--:--:--")
        dtype = item.get("type")
        if dtype == "msg":
            self.append_text(f"[{t}] {item.get('user', 'Anon')}: {item.get('text', '')}")
        elif dtype == "system":
            self.append_text(f"[{t}] {item.get('text', '')}")
        elif dtype == "error":
            self.append_text(f"⚠️ Error: {item.get('text', '')}")
        else:
            self.append_text(str(item))

    def send_msg(self, event=None):
        text = self.entry.get().strip()
        if not text:
            return
            
        # El cliente cifra con la clave pública del SERVIDOR
        server_pub_key = self.ws_thread.server_public_key
        if not server_pub_key:
             self.append_text(f"⚠️ Error: Aún no se recibe la clave pública del servidor.")
             return

        payload = {"type": "msg", "user": self.username, "text": text}
        
        try:
            # Cifrar con la clave pública del SERVIDOR
            encrypted_payload = encrypt_rsa_message(payload, server_pub_key) 
            self.outbound_q.put(encrypted_payload)
            self.entry.delete(0, "end")
        except ValueError as e:
            # Capturar error de longitud antes de enviarlo
            self.append_text(f"❌ FALLO DE CIFRADO: {e}")
            
    def on_disconnect(self):
        pass

    def on_close(self):
        try:
            # Enviar mensaje de salida cifrado (si el servidor ya compartió su clave)
            if self.ws_thread.server_public_key:
                leave_msg = encrypt_rsa_message({"type": "leave", "user": self.username}, self.ws_thread.server_public_key)
                self.outbound_q.put(leave_msg)
            
            self.outbound_q.put(None)
            self.ws_thread.stop()
        except:
            pass
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatApp(root)
    root.mainloop()
