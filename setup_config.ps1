# Script de configuración rápida para Chat LAN Seguro
# Ejecuta este script en PowerShell para configurar las variables de entorno

Write-Host "🔐 Configuración Chat LAN Seguro con SSL/TLS" -ForegroundColor Cyan
Write-Host "=" * 60

# Generar valores seguros
$secret = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object {[char]$_})
$salt = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }))
$token = "chat_lan_" + (Get-Random -Maximum 9999)

Write-Host "`n📋 Valores generados:" -ForegroundColor Green
Write-Host "   CHAT_SECRET: $secret"
Write-Host "   CHAT_SALT_BASE64: $salt"
Write-Host "   CHAT_DISCOVERY_TOKEN: $token"

Write-Host "`n¿Deseas configurar estas variables en el sistema? (S/N): " -NoNewline -ForegroundColor Yellow
$response = Read-Host

if ($response -eq 'S' -or $response -eq 's') {
    # Configurar variables obligatorias
    [Environment]::SetEnvironmentVariable("CHAT_SECRET", $secret, "User")
    [Environment]::SetEnvironmentVariable("CHAT_SALT_BASE64", $salt, "User")
    [Environment]::SetEnvironmentVariable("CHAT_DISCOVERY_TOKEN", $token, "User")
    
    # Configurar variables SSL
    [Environment]::SetEnvironmentVariable("USE_SSL", "true", "User")
    [Environment]::SetEnvironmentVariable("SSL_VERIFY", "false", "User")
    [Environment]::SetEnvironmentVariable("SSL_CERT_FILE", "server.crt", "User")
    [Environment]::SetEnvironmentVariable("SSL_KEY_FILE", "server.key", "User")
    
    # Configurar puertos
    [Environment]::SetEnvironmentVariable("SERVER_PORT", "8765", "User")
    [Environment]::SetEnvironmentVariable("CHAT_BROADCAST_PORT", "9999", "User")
    
    Write-Host "`n✅ Variables de entorno configuradas correctamente" -ForegroundColor Green
    Write-Host "`n⚠️  IMPORTANTE: Cierra y reabre PowerShell para que los cambios tengan efecto" -ForegroundColor Yellow
    
    # Guardar en archivo para referencia
    $configFile = "chat_config_backup.txt"
    @"
# Configuración generada el $(Get-Date)
# ⚠️ MANTÉN ESTE ARCHIVO SEGURO - Contiene credenciales

CHAT_SECRET=$secret
CHAT_SALT_BASE64=$salt
CHAT_DISCOVERY_TOKEN=$token
USE_SSL=true
SSL_VERIFY=false
SERVER_PORT=8765
CHAT_BROADCAST_PORT=9999
"@ | Out-File -FilePath $configFile -Encoding UTF8
    
    Write-Host "`n💾 Configuración guardada en: $configFile" -ForegroundColor Cyan
    Write-Host "   (Guarda este archivo en un lugar seguro)" -ForegroundColor Yellow
    
} else {
    Write-Host "`nConfiguración cancelada. Puedes configurar manualmente con:" -ForegroundColor Yellow
    Write-Host "   setx CHAT_SECRET `"$secret`""
    Write-Host "   setx CHAT_SALT_BASE64 `"$salt`""
    Write-Host "   setx CHAT_DISCOVERY_TOKEN `"$token`""
    Write-Host "   setx USE_SSL `"true`""
    Write-Host "   setx SSL_VERIFY `"false`""
}

Write-Host "`n" + "=" * 60
Write-Host "📋 Próximos pasos:" -ForegroundColor Cyan
Write-Host "   1. Cierra y reabre PowerShell"
Write-Host "   2. Genera certificados SSL:"
Write-Host "      python generate_ssl_cert.py"
Write-Host "   3. Inicia el servidor:"
Write-Host "      python server_ws.py"
Write-Host "   4. Inicia el cliente:"
Write-Host "      python client_ws_gui.py"
Write-Host "`n🔐 ¡Chat LAN seguro con SSL/TLS listo!" -ForegroundColor Green
