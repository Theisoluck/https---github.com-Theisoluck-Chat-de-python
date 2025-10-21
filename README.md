Chat LAN - Proyecto de ejemplo (readme)

Resumen
-------
Esta pequeña colección de scripts implementa un chat LAN cifrado usando WebSockets y cifrado simétrico (AES-GCM). El proyecto contiene:

- `server_ws.py`: servidor WebSocket que mantiene el historial y retransmite mensajes cifrados a todos los clientes conectados.
- `client_ws_gui.py`: cliente con interfaz gráfica (Tkinter) que se conecta al servidor, envía/recibe mensajes cifrados y muestra notificaciones del sistema.
- `crypto_utils.py`: utilidades de cifrado (derivación de clave con scrypt, cifrado/descifrado con AES-GCM) y funciones de verificación.

Requisitos
----------
- Python 3.10+ (probado con 3.11/3.12)
- PyCryptodome (para AES/GCM y scrypt)
- websockets (para WebSocket server/client)
- tkinter (incluido con la mayoría de instalaciones de Python en Windows)

Instalación (Windows - PowerShell)
---------------------------------
# Crear un entorno virtual (opcional, recomendado)
python -m venv .venv; .\.venv\Scripts\Activate.ps1

# Instalar dependencias
python -m pip install --upgrade pip; python -m pip install pycryptodome websockets

Archivos y responsabilidades
----------------------------
1) `crypto_utils.py`
   - Deriva una clave AES de 32 bytes desde una contraseña usando `scrypt` y una SAL fija (`FIXED_SALT`).
   - `calculate_sha256(data)`: calcula un hash SHA-256 para verificar la integridad de los mensajes.
   - `encrypt_json(data, key)`: cifra un diccionario serializado a JSON usando AES-GCM y añade un hash SHA-256 para verificación de integridad. Devuelve un JSON con `nonce`, `tag` y `data` (todo en base64).
   - `decrypt_json(encrypted_json, key)`: valida el hash SHA-256, descifra el JSON cifrado, y devuelve el diccionario original.
   - `verify_encryption(password)`: función de prueba que cifra/descifra un mensaje de test y verifica el hash SHA-256.
   - `get_file_md5(file_path)`: calcula el hash MD5 de un archivo para control de cambios.

   Nota de seguridad: la SAL (`FIXED_SALT`) actualmente está codificada en el código y debe ser la misma en cliente y servidor. Para producción, usar una sal por usuario/instancia y canales seguros para intercambio de parámetros.

2) `server_ws.py`
   - Ejecuta un servidor WebSocket en `HOST:PORT` (por defecto `0.0.0.0:8765`).
   - Al conectar un cliente envía el historial reciente (últimos 50 eventos) cifrado.
   - Maneja tipos de mensajes: `join`, `msg`, `leave` y retransmite eventos a todos los clientes (usando `encrypt_json`).
   - Mantiene `history` (lista) y `clients` (set de websockets).

3) `client_ws_gui.py`
   - Interfaz gráfica Tkinter: cuadro de texto con desplazamiento, campo de entrada y botón "Enviar".
   - `WSClientThread` se encarga de la conexión websocket en un hilo aparte; usa `queue.Queue` para comunicar inbound/outbound con el hilo de la GUI.
   - Al iniciar se pide nombre de usuario e IP del servidor; construye `ws://<ip>:8765`.
   - Los mensajes se cifran con `encrypt_json` antes de enviarse y se descifran con `decrypt_json` al recibir.
   - Manejo de cierre: envía un mensaje `leave` y marca la cola con `None` para terminar el hilo de envío.

Cómo ejecutar
-------------
1) Ejecutar el servidor en la máquina que actuará como host (ejecutar en PowerShell):
python server_ws.py

2) Ejecutar el cliente en cualquier equipo de la LAN que pueda alcanzar al servidor:
python client_ws_gui.py

Nota: al abrir el cliente se solicitará "Nombre" y "IP del servidor". Introduce la IP LAN del host donde corre `server_ws.py`.

Verificaciones rápidas
----------------------
- Probar `crypto_utils.verify_encryption("mi-clave-secreta-chat-lan-2024")` en un REPL para validar cifrado/descifrado.
- Conectar múltiples clientes al servidor y enviar mensajes; verificar que todos reciben los mensajes y el historial al conectar.

Problemas comunes y soluciones
------------------------------
- Error de importación `Crypto.Cipher` o `Crypto.Protocol.KDF`: asegúrate de tener `pycryptodome` instalado (no `pycrypto`).
- `PermissionError` al abrir puerto: Windows puede bloquear puertos con firewall; permitir la aplicación o usar un puerto alto (>1024) o ejecutar PowerShell como administrador para pruebas.
- Mensajes "Error descifrando mensaje": esto ocurre si la contraseña/clave no coincide entre cliente y servidor. Asegúrate de usar la misma `SECRET_PASSWORD` o deriva la clave con la misma sal y parámetros.
- Problemas con salt fija: compartir la SAL en claro y la contraseña por canales inseguros puede exponer el sistema. Considera usar intercambio de claves o TLS para producción.

Implementación de SHA-256 para integridad de mensajes
----------------------------------------------------
La aplicación ahora incluye verificación de integridad mediante SHA-256:

1. **¿Cómo funciona?**
   - Cuando se envía un mensaje, se calcula un hash SHA-256 del contenido original
   - Este hash se añade al mensaje antes del cifrado AES-GCM
   - Al recibir, primero se descifra y luego se verifica el hash SHA-256
   - Si el hash no coincide, se rechaza el mensaje como posiblemente manipulado

2. **Beneficios de seguridad:**
   - Detección de manipulación de mensajes durante la transmisión
   - Verificación adicional de integridad (complementa el tag de autenticación GCM)
   - Protección contra ataques de replay modificados

3. **Verificación:**
   - La función `verify_encryption()` ahora también comprueba la integridad SHA-256
   - Los mensajes modificados generarán errores de validación de hash
   - Los hashes SHA-256 se muestran en la consola al enviar y recibir mensajes para depuración

MD5 Hashes de Control de Cambios
--------------------------------
Los siguientes hashes MD5 representan el estado actual de los archivos fuente:

| Archivo            |             MD5 Hash             |
|--------------------|----------------------------------|
| client_ws_gui.py   | 581e272cea079160950846dedf1fa6f2 |
| crypto_utils.py    | 853c5e68ab93c4920f72289c1f5ae777 |
| server_ws.py       | 8244eee7dbb6298e5019fe69be3027e1 |

*Nota: Estos hashes se utilizan para control de versiones y verificación de integridad de los archivos fuente.*

Visualización de hashes SHA-256 en consola
----------------------------------------
Para ayudar en el desarrollo y depuración, el sistema ahora muestra los hashes SHA-256 en la consola:

1. **Al enviar mensajes:**
   - Se muestra el hash SHA-256 calculado para el mensaje original
   - Se imprime el contenido del mensaje que se va a cifrar
   
2. **Al recibir mensajes:**
   - Se muestra el hash SHA-256 recibido en el mensaje
   - Se muestra el hash SHA-256 calculado localmente
   - Se indica si la verificación fue exitosa o falló

Esto permite verificar visualmente la integridad de los mensajes durante el desarrollo y pruebas.

Mejoras sugeridas (próximos pasos)
----------------------------------
- Reemplazar `FIXED_SALT` por una sal dinámica y negociar parámetros con TLS o un canal seguro.
- Añadir autenticación (usuarios/contraseñas) y control de acceso.
- Proteger el servidor con TLS (wss://) para evitar MITM en la negociación de WebSocket.
- Añadir tests unitarios para `crypto_utils.py`.

Licencia y atribuciones
-----------------------
Código de ejemplo para uso educativo. Recomendado revisar requisitos legales y de seguridad antes de desplegar en producción.

Contacto
--------
Repositorio original: https://github.com/Theisoluck/Chat-de-python

---
Generado automáticamente: descripción y guía de uso para los archivos actuales del proyecto.
