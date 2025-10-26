# Chat LAN — Proyecto de ejemplo (versión segura)

Chat LAN es un sistema de chat local cifrado con WebSockets y cifrado simétrico (AES).  
Esta versión implementa mejoras de seguridad, eliminando hardcoding y usando variables de entorno para claves y configuración.

## Archivos principales

- `server_ws.py` — Servidor WebSocket. Mantiene historial y anuncia su presencia en la red local (UDP Discovery).  
- `client_ws_gui.py` — Cliente con interfaz gráfica (Tkinter). Pide nombre, descubre automáticamente al servidor y establece conexión segura.  
- `crypto_utils.py` — Módulo de cifrado: derivación de clave con scrypt, cifrado simétrico (AES) y verificación de integridad (SHA-256).

## Variables de entorno requeridas

Para evitar hardcoding, las claves y configuraciones se cargan desde el entorno:

| Variable | Descripción |
|----------|-------------|
| `CHAT_SECRET` | Clave secreta para derivar la clave de cifrado (obligatoria). |
| `CHAT_SALT_BASE64` | Sal codificada en base64 para derivar la clave. |
| `CHAT_DISCOVERY_TOKEN` | Token de validación para el descubrimiento LAN. |
| `SERVER_PORT` | Puerto del servidor WebSocket (por defecto `8765`). |
| `CHAT_BROADCAST_PORT` | Puerto UDP para descubrimiento (por defecto `9999`). |
| `SERVER_IP` | Dirección de respaldo si no se encuentra el servidor automáticamente. |

## Configuración rápida (Windows PowerShell)

1. Definir variables de entorno:
   powershell
   setx CHAT_SECRET "una-clave-segura"
   setx CHAT_SALT_BASE64 "U29tZVNhbHRIYXNoZWRCYXNlNjQ="
   setx CHAT_DISCOVERY_TOKEN "chat_lan_v1"
