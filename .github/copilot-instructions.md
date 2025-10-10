## Quick orientation for Copilot / AI coding agents

This repository is a small LAN chat using WebSockets with application-level encryption.
Keep edits conservative: the client and server share a simple encrypted JSON wire protocol — changing one side requires mirroring the change on the other.

### Big picture
- Components:
  - `server_ws.py` — asyncio WebSocket server that registers clients, keeps a short `history` (HISTORY_MAX), and broadcasts encrypted JSON messages to all connected clients.
  - `client_ws_gui.py` — Tkinter GUI client that runs a background `WSClientThread` (thread + asyncio) and communicates with the server via two queues (`inbound_q`, `outbound_q`).
  - `crypto_utils.py` — helper functions for deriving keys and encrypting/decrypting JSON payloads (AES-GCM helpers: `derive_key`, `encrypt_json`, `decrypt_json`, `verify_encryption`).
  - `README.md` — contains example client variants (AES and RSA examples). Use it for reference but prefer the actual source files when changing behavior.

### Wire protocol (discoverable patterns)
- Messages are JSON objects with a `type` field. Common types: `join`, `msg`, `leave`, `history`, `error`, `system`.
- Server and clients exchange encrypted JSON strings (not plain JSON). Use `encrypt_json(payload, key)` before sending and `decrypt_json(encrypted, key)` after receiving.
- Time is added by the server using `now_ts()` and included as `time` in events of type `msg` and `system`.
- When adding a new message `type`, update both `server_ws.py` handler logic and `client_ws_gui.py`'s `render_item`.

### Encryption & shared secrets
- Current scheme: AES-GCM with a key derived via `scrypt` from `SECRET_PASSWORD` and a repository-wide `FIXED_SALT`.
  - Server: `SECRET_PASSWORD` in `server_ws.py` and `derive_key(SECRET_PASSWORD)` in global `key`.
  - Client: `SECRET_PASSWORD` and `derive_key` usage in `client_ws_gui.py` (must match server).
- Critical constraint: `FIXED_SALT` in `crypto_utils.py` must remain identical between client and server. Do not change salt without updating every instance and coordinating secrets.
- README contains an RSA handshake variant (examples only). If you implement RSA in code, keep protocol differences isolated and document the handshake messages (`server_public_key`, `client_public_key`).

### Developer workflows (commands you can run)
- Install runtime deps (needed for tests/dev):

```powershell
python -m pip install websockets pycryptodome
```

- Run server locally:

```powershell
python server_ws.py
```

- Run client GUI locally:

```powershell
python client_ws_gui.py
```

- Quick encryption sanity check:

```powershell
python -c "from crypto_utils import verify_encryption; print(verify_encryption('mi-clave-secreta-chat-lan-2024'))"
```

### Project-specific conventions & patterns
- Use the `encrypt_json` / `decrypt_json` helpers; do not inline AES code across files — centralize crypto in `crypto_utils.py`.
- Client uses a background thread (`WSClientThread`) that runs asyncio loop via `asyncio.run(...)` and communicates with GUI via `queue.Queue()`; follow the same pattern when adding long-running networking code to avoid blocking Tkinter's mainloop.
- Server broadcasts encrypted payloads via `broadcast(payload)` which encrypts once and sends to all `clients`.
- History is capped by `HISTORY_MAX` in `server_ws.py`; keep that behavior when editing retention.

### Integration & change guidance for AI edits
- When changing message fields or message types:
  1. Update `server_ws.py` handler and ensure `history` contains the same shape the clients expect.
  2. Update `client_ws_gui.py`'s `render_item` and `process_inbound`.
  3. Preserve encryption helpers usage: call `encrypt_json` before send and `decrypt_json` on receive.
- When touching crypto:
  - Do not alter `FIXED_SALT` without confirming both sides and updating README.
  - Prefer adding new helper functions to `crypto_utils.py` rather than duplicating logic.

### Debugging tips
- Enable more verbose logs by editing `logging.basicConfig(level=logging.INFO)` in `crypto_utils.py` (or set to DEBUG for deeper insight).
- If messages fail decryption, you'll see errors pushed back as `{type: 'error', text: ...}` — trace by checking `decrypt_json` exceptions in `server_ws.py` and `client` recv loops.

### Files to inspect when making changes
- `server_ws.py` — broadcast, handler, history, SECRET_PASSWORD usage
- `client_ws_gui.py` — WSClientThread, send_task/recv_task, GUI render_item
- `crypto_utils.py` — key derivation, AES-GCM helpers, `verify_encryption`
- `README.md` — examples and RSA variant for reference

If anything above is unclear or you want me to add examples for a specific change (e.g., adding a new message type, switching to RSA, or adding tests), tell me which area to expand and I will iterate.
