# client_ws_gui.py
# Cliente GUI Tkinter para chat LAN vía WebSockets
# Requisitos: pip install websockets eres gay

import asyncio
import json
import threading
import queue
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox
import websockets

# Importar utilidades de cifrado
from crypto_utils import derive_key, encrypt_json, decrypt_json

SERVER_HOST = "192.168.110.10"  # Cambia a la IP del servidor en la LAN
SERVER_PORT = 8765

# Clave compartida para el cifrado (DEBE SER LA MISMA EN CLIENTE Y SERVIDOR)
SECRET_PASSWORD = "mi-clave-secreta-chat-lan-2024"
key, salt = derive_key(SECRET_PASSWORD)

class WSClientThread(threading.Thread):
    def __init__(self, username, server_url, inbound_q: queue.Queue, outbound_q: queue.Queue, on_disconnect):
        super().__init__(daemon=True)
        self.username = username
        self.server_url = server_url
        self.inbound_q = inbound_q   # GUI <- WS
        self.outbound_q = outbound_q # GUI -> WS
        self.on_disconnect = on_disconnect
        self.stop_flag = threading.Event()

    def stop(self):
        self.stop_flag.set()

    async def ws_loop(self):
        try:
            async with websockets.connect(self.server_url) as ws:
                # Anunciar ingreso (CIFRADO)
                join_msg = encrypt_json({"type": "join", "user": self.username}, key)
                await ws.send(join_msg)
                self.inbound_q.put({"type": "system", "text": f"Conectado a {self.server_url} como {self.username}"})
                self.inbound_q.put({"type": "system", "text": "🔐 Comunicación cifrada activa"})

                async def recv_task():
                    async for encrypted_raw in ws:
                        try:
                            # Descifrar mensaje recibido
                            data = decrypt_json(encrypted_raw, key)
                        except (json.JSONDecodeError, ValueError) as e:
                            data = {"type": "error", "text": f"Error descifrando mensaje: {e}"}
                        self.inbound_q.put(data)

                async def send_task():
                    while not self.stop_flag.is_set():
                        try:
                            # Obtener mensaje para enviar (ya cifrado desde la GUI)
                            encrypted_item = await asyncio.get_event_loop().run_in_executor(None, self.outbound_q.get)
                        except Exception:
                            continue
                        if encrypted_item is None:
                            break
                        # El mensaje ya viene cifrado, solo enviar
                        await ws.send(encrypted_item)

                await asyncio.gather(recv_task(), send_task())
        except Exception as e:
            self.inbound_q.put({"type": "system", "text": f"Desconectado: {e}"})
        finally:
            self.on_disconnect()

    def run(self):
        asyncio.run(self.ws_loop())

class ChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat LAN (WebSocket) 🔐")

        # --- UI ---
        top = tk.Frame(root)
        top.pack(fill="both", expand=True, padx=10, pady=10)

        self.txt = scrolledtext.ScrolledText(top, state="disabled", wrap="word", height=20)
        self.txt.pack(fill="both", expand=True)

        entry_frame = tk.Frame(top)
        entry_frame.pack(fill="x", pady=(8, 0))

        self.entry = tk.Entry(entry_frame)
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<Return>", self.send_msg)

        self.btn = tk.Button(entry_frame, text="Enviar 🔒", command=self.send_msg)
        self.btn.pack(side="left", padx=(6, 0))

        # --- estado ---
        self.username = simpledialog.askstring("Nombre", "Introduce tu nombre:", parent=self.root) or "Anon"
        server_ip = simpledialog.askstring("Servidor", "IP del servidor (ej. 192.168.1.50):", parent=self.root)
        if not server_ip:
            server_ip = SERVER_HOST
        self.server_url = f"ws://{server_ip}:{SERVER_PORT}"

        # --- colas para comunicación con el hilo WS ---
        self.inbound_q = queue.Queue()
        self.outbound_q = queue.Queue()

        # --- hilo cliente WS ---
        self.ws_thread = WSClientThread(
            username=self.username,
            server_url=self.server_url,
            inbound_q=self.inbound_q,
            outbound_q=self.outbound_q,
            on_disconnect=self.on_disconnect
        )
        self.ws_thread.start()

        # loop de GUI para vaciar cola entrante
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
                dtype = data.get("type")
                if dtype == "history":
                    for item in data.get("items", []):
                        self.render_item(item)
                else:
                    self.render_item(data)
        except queue.Empty:
            pass
        # Reprogramar
        self.root.after(100, self.process_inbound)

    def render_item(self, item):
        dtype = item.get("type")
        if dtype == "msg":
            user = item.get("user", "Anon")
            text = item.get("text", "")
            t = item.get("time", "")
            self.append_text(f"[{t}] {user}: {text}")
        elif dtype == "system":
            text = item.get("text", "")
            t = item.get("time", "")
            self.append_text(f"[{t or '--:--:--'}] {text}")
        elif dtype == "error":
            self.append_text(f"⚠️ Error: {item.get('text')}")
        else:
            self.append_text(str(item))

    def send_msg(self, event=None):
        text = self.entry.get().strip()
        if not text:
            return
        
        # Cifrar el mensaje antes de ponerlo en la cola
        payload = {"type": "msg", "user": self.username, "text": text}
        encrypted_payload = encrypt_json(payload, key)
        self.outbound_q.put(encrypted_payload)
        self.entry.delete(0, "end")

    def on_disconnect(self):
        # Aviso en GUI (ya llega un mensaje "Desconectado: ...")
        pass

    def on_close(self):
        try:
            # Notificar salida (CIFRADO) y cerrar hilo
            leave_msg = encrypt_json({"type": "leave", "user": self.username}, key)
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