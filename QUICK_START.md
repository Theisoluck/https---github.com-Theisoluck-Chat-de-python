#!/bin/bash
# ============================================================================
# GUÍA RÁPIDA: Iniciar Chat LAN Seguro con SSL/TLS
# ============================================================================
# Este archivo documenta cómo ejecutar el sistema completo

# ============================================================================
# PASO 1: Generar certificados SSL (solo la primera vez)
# ============================================================================

echo "📋 PASO 1: Generar certificados SSL"
echo "======================================"
echo ""
echo "Ejecuta SOLO UNA VEZ:"
echo "  cd c:\Users\angel\OneDrive\Desktop\Seguridas\https---github.com-Theisoluck-Chat-de-python"
echo "  .\.venv\Scripts\python.exe generate_ssl_cert.py"
echo ""
echo "Esto creará:"
echo "  ✅ server.crt  (certificado SSL)"
echo "  ✅ server.key  (llave privada)"
echo ""

# ============================================================================
# PASO 2: TERMINAL 1 - Iniciar el servidor
# ============================================================================

echo "📋 PASO 2: TERMINAL 1 - Iniciar el servidor"
echo "============================================="
echo ""
echo "Abre una terminal PowerShell y ejecuta:"
echo ""
echo "  cd c:\Users\angel\OneDrive\Desktop\Seguridas\https---github.com-Theisoluck-Chat-de-python"
echo "  .\.venv\Scripts\python.exe server_ws.py"
echo ""
echo "Deberías ver:"
echo "  🔐 Servidor escuchando en wss://0.0.0.0:8765"
echo "  ✅ SSL/TLS habilitado"
echo ""

# ============================================================================
# PASO 3: TERMINAL 2 - Iniciar el cliente
# ============================================================================

echo "📋 PASO 3: TERMINAL 2 - Iniciar el cliente"
echo "==========================================="
echo ""
echo "Abre OTRA terminal PowerShell y ejecuta:"
echo ""
echo "  cd c:\Users\angel\OneDrive\Desktop\Seguridas\https---github.com-Theisoluck-Chat-de-python"
echo "  .\.venv\Scripts\python.exe client_ws_gui.py"
echo ""
echo "Se abrirá una ventana GUI donde:"
echo "  1. Se te pedirá tu nombre de usuario"
echo "  2. Se auto-descubrirá el servidor automáticamente"
echo "  3. Se conectará via wss:// (WebSocket Secure)"
echo ""

# ============================================================================
# INFORMACIÓN IMPORTANTE
# ============================================================================

echo ""
echo "ℹ️  INFORMACIÓN IMPORTANTE"
echo "=========================="
echo ""
echo "✅ Protocolo: WSS (WebSocket Secure)"
echo "   Usa TLS 1.2/1.3 para cifrar toda la conexión"
echo ""
echo "✅ Cifrado de Mensajes: AES-256-GCM"
echo "   Cada mensaje se cifra además del SSL"
echo ""
echo "✅ Integridad: SHA-256"
echo "   Cada mensaje incluye hash para verificar que no fue modificado"
echo ""
echo "✅ Certificados: Autofirmados"
echo "   Válido por 365 días (solo para LAN)"
echo ""

# ============================================================================
# MÚLTIPLES CLIENTES
# ============================================================================

echo ""
echo "🔗 MÚLTIPLES CLIENTES"
echo "====================="
echo ""
echo "Puedes iniciar múltiples clientes:"
echo ""
echo "  TERMINAL 3:"
echo "    .\.venv\Scripts\python.exe client_ws_gui.py"
echo ""
echo "  TERMINAL 4:"
echo "    .\.venv\Scripts\python.exe client_ws_gui.py"
echo ""
echo "Todos se conectarán al servidor automáticamente"
echo ""

# ============================================================================
# DETENER EL SERVIDOR
# ============================================================================

echo ""
echo "🛑 DETENER"
echo "=========="
echo ""
echo "En cada terminal, presiona: Ctrl + C"
echo ""
echo "Para eliminar certificados (si necesitas regenerar):"
echo "  rm server.crt server.key"
echo ""

# ============================================================================
# VERIFICACIÓN
# ============================================================================

echo ""
echo "✅ VERIFICACIÓN"
echo "==============="
echo ""
echo "Para verificar que SSL/TLS está habilitado:"
echo ""
echo "1. Busca en la consola del servidor:"
echo "   '🔐 Servidor escuchando en wss://'"
echo ""
echo "2. Busca en la consola del cliente:"
echo "   'Conectado a wss://'"
echo "   '🔐 Comunicación cifrada activa + WSS'"
echo ""

# ============================================================================
# FINALIZADO
# ============================================================================

echo ""
echo "🎉 ¡Chat LAN Seguro con SSL/TLS!"
echo "=================================="
