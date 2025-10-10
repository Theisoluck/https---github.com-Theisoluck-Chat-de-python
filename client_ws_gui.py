# client_ws_gui.py
import asyncio
import json
import threading
import queue
import tkinter as tk
from tkinter import simpledialog, scrolledtext
import websockets
from crypto_utils import derive_key, encrypt_json, decrypt_json, hash_sha256


SERVER_HOST = "192.168.108.180"
SERVER_PORT = 8765
SECRET_PASSWORD = "mi-clave-secreta-chat-lan-2024"
key = derive_key(SECRET_PASSWORD)

class WSClientThread(threading.Thread):
    def __init__(self, username, server_url, inbound_q, outbound_q, on_disconnect):
        super().__init__(daemon=True)
        self.username = username
        self.server_url = server_url
        self.inbound_q = inbound_q
        self.outbound_q = outbound_q
        self.on_disconnect = on_disconnect
        self.stop_flag = threading.Event()

    def stop(self):
        self.stop_flag.set()

    async def ws_loop(self):
        try:
            async with websockets.connect(self.server_url) as ws:
                join_msg = encrypt_json({"type": "join", "user": self.username}, key)
                await ws.send(join_msg)
                self.inbound_q.put({"type": "system", "text": f"Conectado a {self.server_url} como {self.username}"})
                self.inbound_q.put({"type": "system", "text": "Comunicacion con cifrado"})

                async def recv_task():
                    async for encrypted_raw in ws:
                        try:
                            data = decrypt_json(encrypted_raw, key)
                        except Exception as e:
                            data = {"type": "error", "text": f"Error descifrando mensaje: {e}"}
                        self.inbound_q.put(data)

                async def send_task():
                    while not self.stop_flag.is_set():
                        try:
                            encrypted_item = await asyncio.get_event_loop().run_in_executor(None, self.outbound_q.get)
                            if encrypted_item is None:
                                break
                            await ws.send(encrypted_item)
                        except Exception:
                            break

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
        self.root.title("Chat local")

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
            text = item.get('text', '')
            user = item.get('user', 'Anon')
            
            # Verificar integridad si hay un hash disponible
            integrity_hash = item.get('integrity_hash')
            if integrity_hash:
                calculated_hash = hash_sha256(text)
                if calculated_hash != integrity_hash:
                    self.append_text(f"El mensaje de {user} ha sido alterado, favor de no compartir información sensible.")
                
            self.append_text(f"[{t}] {user}: {text}")
        elif dtype == "system":
            self.append_text(f"[{t}] {item.get('text', '')}")
        elif dtype == "error":
            self.append_text(f"Error: {item.get('text', '')}")
        else:
            self.append_text(str(item))

    def send_msg(self, event=None):
        text = self.entry.get().strip()
        if not text:
            return
        # Calcular hash SHA-256 del texto del mensaje para verificación de integridad
        text_hash = hash_sha256(text)
        # Incluir el hash en el payload
        payload = {"type": "msg", "user": self.username, "text": text, "integrity_hash": text_hash}
        encrypted_payload = encrypt_json(payload, key)
        self.outbound_q.put(encrypted_payload)
        self.entry.delete(0, "end")

    def on_disconnect(self):
        pass

    def on_close(self):
        try:
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

