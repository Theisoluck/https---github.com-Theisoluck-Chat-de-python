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
| `USE_SSL` | Habilitar SSL/TLS (`true` o `false`, por defecto `true`). |
| `SSL_VERIFY` | Verificar certificados SSL (`true` o `false`, por defecto `false` para LAN). |
| `SSL_CERT_FILE` | Ruta del certificado SSL (por defecto `server.crt`). |
| `SSL_KEY_FILE` | Ruta de la llave privada SSL (por defecto `server.key`). |

## Configuración rápida (Windows PowerShell)

1. Definir variables de entorno:
   ```powershell
   setx CHAT_SECRET "una-clave-segura"
   setx CHAT_SALT_BASE64 "U29tZVNhbHRIYXNoZWRCYXNlNjQ="
   setx CHAT_DISCOVERY_TOKEN "chat_lan_v1"
   setx USE_SSL "true"
   setx SSL_VERIFY "false"
   ```

2. Generar certificados SSL (obligatorio si USE_SSL=true):
   ```powershell
   python generate_ssl_cert.py
   ```
   
   Esto creará:
   - `server.crt` — Certificado SSL (válido por 1 año)
   - `server.key` — Llave privada

3. Iniciar el servidor:
   ```powershell
   python server_ws.py
   ```
   
   Verás algo como:
   ```
   🔐 Servidor escuchando en wss://0.0.0.0:8765
   ✅ SSL/TLS habilitado
      📄 Certificado: server.crt
      🔑 Llave: server.key
   ```

4. Iniciar el cliente (en otra terminal o computadora):
   ```powershell
   python client_ws_gui.py
   ```

## Implementación SSL/TLS (WebSocket Secure - WSS)

### ¿Qué es SSL/TLS y por qué es necesario?

**SSL/TLS** cifra la **conexión completa** entre cliente y servidor, protegiendo:
- Los datos de los mensajes
- Los metadatos de la conexión
- Las credenciales durante el handshake
- Contra ataques Man-in-the-Middle (MITM)

Aunque este proyecto ya cifra los mensajes con **AES-256**, SSL/TLS añade una capa adicional de seguridad al nivel de transporte.

### Diferencias: WS vs WSS

| Característica | WS (sin SSL) | WSS (con SSL/TLS) |
|----------------|--------------|-------------------|
| Protocolo | `ws://` | `wss://` |
| Cifrado de transporte | ❌ No | ✅ Sí |
| Certificado requerido | No | Sí |
| Puerto estándar | 80 | 443 |
| Recomendado para | Desarrollo local | Producción/LAN segura |

### Generación de certificados SSL

El proyecto incluye `generate_ssl_cert.py` para crear certificados **autofirmados**:

```powershell
python generate_ssl_cert.py
```

**Nota:** Los certificados autofirmados son válidos para:
- ✅ Desarrollo local
- ✅ Redes LAN privadas
- ❌ **NO** para Internet público (usa Let's Encrypt o CA comercial)

### Requisitos para SSL/TLS

**Windows:**
- OpenSSL debe estar instalado
- Opciones de instalación:
  1. Instalar Git (incluye OpenSSL)
  2. Descargar desde: https://slproweb.com/products/Win32OpenSSL.html
  3. Instalar vía Chocolatey: `choco install openssl`

**Verificar instalación:**
```powershell
openssl version
```

### Configuración de variables SSL

```powershell
# Habilitar SSL/TLS
setx USE_SSL "true"

# No verificar certificados (para autofirmados en LAN)
setx SSL_VERIFY "false"

# Rutas personalizadas (opcional)
setx SSL_CERT_FILE "mi_certificado.crt"
setx SSL_KEY_FILE "mi_llave.key"
```

### Arquitectura de seguridad en capas

Este proyecto implementa **defensa en profundidad**:

1. **Capa de Transporte (SSL/TLS):**
   - Cifra toda la conexión WebSocket
   - Autenticación del servidor
   - Protección contra MITM

2. **Capa de Aplicación (AES-256-GCM):**
   - Cifrado simétrico de mensajes
   - Derivación de clave con scrypt
   - Verificación de integridad con SHA-256

3. **Capa de Validación:**
   - Token de descubrimiento compartido
   - Verificación de hash en cada mensaje

### Troubleshooting SSL/TLS

**Error: "Certificados SSL no encontrados"**
```
❌ ERROR: Archivos SSL no encontrados:
   Certificado: server.crt
   Llave: server.key
```
**Solución:** Ejecuta `python generate_ssl_cert.py`

**Error: "certificate verify failed"**
```
ssl.SSLCertVerificationError: certificate verify failed
```
**Solución:** Establece `SSL_VERIFY=false` para certificados autofirmados en LAN

**Error: "OpenSSL no está instalado"**
```
❌ ERROR: OpenSSL no está instalado o no está en el PATH
```
**Solución:** Instala OpenSSL (ver sección "Requisitos para SSL/TLS")

### Desactivar SSL/TLS (solo para pruebas)

Si necesitas desactivar SSL temporalmente:

```powershell
setx USE_SSL "false"
```

El sistema volverá a usar `ws://` (sin cifrado de transporte).

⚠️ **Advertencia:** Sin SSL/TLS, aunque los mensajes están cifrados con AES, los metadatos de conexión viajan en claro.

MD5 Hashes de Control de Cambios
--------------------------------
Los siguientes hashes MD5 representan el estado actual de los archivos fuente:

Add SHA-256 hash

| Archivo            |             MD5 Hash             |
|--------------------|----------------------------------|
| client_ws_gui.py   | 581e272cea079160950846dedf1fa6f2 |
| crypto_utils.py    | 853c5e68ab93c4920f72289c1f5ae777 |
| server_ws.py       | 8244eee7dbb6298e5019fe69be3027e1 |

Revome the ´HardCoding´

| Archivo            |             MD5 Hash             |
|--------------------|----------------------------------|
| client_ws_gui.py   | 4061d8ad323cc6b681f8a9984d24719c |
| crypto_utils.py    | 683b53584a93cc565921130c31b13254 |
| server_ws.py       | c4db766b13aa37213b0ac5ecd8b566f9 |

| Archivo                |             MD5 Hash             |
|------------------------|----------------------------------|
| client_ws_gui.py       | 48d55f5923e01dbd323bf7d11ee95e4f |
| crypto_utils.py        | 683b53584a93cc565921130c31b13254 |
| generate_ssl_cert.py   | 5fa10a2980a85ee8ba2223b123b8d819 |
| server_ws.py           | 0866e811485cf3d9e953904879a9aed9 |

**Cambios recientes:**
- ✅ Implementación SSL/TLS (WSS - WebSocket Secure)
- ✅ Agregado SHA-256 para verificación de integridad
- ✅ Removido Hard Coding (configuración por variables de entorno)

| Archivo            |             MD5 Hash             |
|--------------------|----------------------------------|
| client_ws_gui.py   | 4061d8ad323cc6b681f8a9984d24719c |
| crypto_utils.py    | 683b53584a93cc565921130c31b13254 |
| server_ws.py       | c4db766b13aa37213b0ac5ecd8b566f9 |

*Nota: Estos hashes se utilizan para control de versiones y verificación de integridad de los archivos fuente.*

Visualización de hashes SHA-256 en consola
----------------------------------------