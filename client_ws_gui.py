# client_ws_gui.py
import asyncio
import json
import threading
import queue
import tkinter as tk
from tkinter import simpledialog, scrolledtext
import websockets
import os
import socket
import time
from crypto_utils import derive_key, encrypt_json, decrypt_json

# Read configuration from environment where possible to avoid hard-coded values
SERVER_PORT = int(os.getenv("SERVER_PORT", "8765"))
BROADCAST_PORT = int(os.getenv("CHAT_BROADCAST_PORT", "9999"))
DISCOVERY_TOKEN = os.getenv("CHAT_DISCOVERY_TOKEN", "chat_lan_v1")

# Secret can be provided through environment variable CHAT_SECRET for
# better separation of config and code. Falls back to the original for
# compatibility/testing.
SECRET_PASSWORD = os.getenv("CHAT_SECRET", "mi-clave-secreta-chat-lan-2024")
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
                self.inbound_q.put({"type": "system", "text": "🔐 Comunicación cifrada activa"})

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
        self.root.title("Chat LAN 🔐")

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

        # Only ask for the username. Server IP is discovered automatically
        # via a small UDP broadcast from the server. If discovery fails we
        # will fall back to an environment-provided SERVER_IP or localhost.
        self.username = simpledialog.askstring("Nombre", "Introduce tu nombre:", parent=self.root) or "Anon"

        def discover_server(timeout=3.0):
            """Listen for a UDP presence broadcast from the server for `timeout` seconds.
            Returns (host, port) or None on timeout.
            """
            end = time.time() + timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # On Windows bind to '' to receive broadcasts
                sock.bind(("", BROADCAST_PORT))
                sock.settimeout(0.5)
                while time.time() < end:
                    try:
                        data, addr = sock.recvfrom(4096)
                        try:
                            obj = json.loads(data.decode())
                        except Exception:
                            continue
                        if obj.get("token") == DISCOVERY_TOKEN:
                            host = obj.get("host") or addr[0]
                            port = int(obj.get("port", SERVER_PORT))
                            return host, port
                    except socket.timeout:
                        continue
                    except Exception:
                        continue
            finally:
                sock.close()
            return None

        discovered = discover_server(timeout=3.0)
        if discovered:
            server_ip, server_port = discovered
        else:
            # Fallbacks: env SERVER_IP (if set) or localhost
            server_ip = os.getenv("SERVER_IP", "127.0.0.1")
            server_port = SERVER_PORT

        self.server_url = f"ws://{server_ip}:{server_port}"

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
        payload = {"type": "msg", "user": self.username, "text": text}
        
        # Calculate and display SHA-256 hash before encryption
        from crypto_utils import calculate_sha256
        msg_hash = calculate_sha256(payload)
        print(f"\n🔒 Enviando mensaje con SHA-256: {msg_hash}")
        print(f"📧 Mensaje original: {payload}")
        
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

