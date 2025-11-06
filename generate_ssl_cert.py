"""
Script para generar certificados SSL autofirmados para el chat LAN.
Este script crea un certificado que será usado para WSS (WebSocket Secure).
"""
import os
import subprocess
import sys

def generate_ssl_certificate():
    """Genera un certificado SSL autofirmado usando OpenSSL."""
    
    cert_file = "server.crt"
    key_file = "server.key"
    
    # Verificar si ya existen
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print(f"⚠️  Los archivos {cert_file} y {key_file} ya existen.")
        response = input("¿Deseas regenerarlos? (s/n): ")
        if response.lower() != 's':
            print("Operación cancelada.")
            return
    
    print("🔐 Generando certificado SSL autofirmado...")
    print("=" * 60)
    
    # Comando OpenSSL para generar certificado autofirmado
    # -x509: generar certificado autofirmado
    # -newkey rsa:4096: crear nueva llave RSA de 4096 bits
    # -keyout: archivo de llave privada
    # -out: archivo de certificado
    # -days 365: válido por 1 año
    # -nodes: no cifrar la llave privada (sin contraseña)
    # -subj: información del certificado
    
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", key_file,
        "-out", cert_file,
        "-days", "365",
        "-nodes",
        "-subj", "/C=MX/ST=Estado/L=Ciudad/O=ChatLAN/OU=Dev/CN=localhost"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print("✅ Certificado SSL generado exitosamente!")
        print(f"   📄 Certificado: {cert_file}")
        print(f"   🔑 Llave privada: {key_file}")
        print("\n⚠️  IMPORTANTE:")
        print("   - Este es un certificado AUTOFIRMADO (solo para desarrollo/LAN)")
        print("   - Los navegadores mostrarán advertencia de seguridad")
        print("   - NO usar en producción en Internet")
        print("   - Válido por 365 días")
        print("\n📋 Próximos pasos:")
        print("   1. Ejecuta el servidor: python server_ws.py")
        print("   2. El servidor usará automáticamente estos certificados")
        print("   3. Los clientes conectarán via wss:// (WebSocket Secure)")
        
    except FileNotFoundError:
        print("❌ ERROR: OpenSSL no está instalado o no está en el PATH")
        print("\n📥 Instalación de OpenSSL:")
        print("   Windows: Descarga desde https://slproweb.com/products/Win32OpenSSL.html")
        print("           O instala Git (incluye OpenSSL)")
        print("\n   Alternativa: Usa el siguiente comando PowerShell para instalar vía Chocolatey:")
        print("   choco install openssl")
        sys.exit(1)
        
    except subprocess.CalledProcessError as e:
        print(f"❌ ERROR al ejecutar OpenSSL: {e}")
        print(f"Salida: {e.stderr}")
        sys.exit(1)

def verify_certificates():
    """Verifica que los certificados existan y sean válidos."""
    cert_file = "server.crt"
    key_file = "server.key"
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("❌ Los certificados no existen. Ejecútalos primero.")
        return False
    
    print("\n🔍 Verificando certificado...")
    cmd = ["openssl", "x509", "-in", cert_file, "-text", "-noout"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print("✅ Certificado válido")
        
        # Extraer información básica
        for line in result.stdout.split('\n'):
            if 'Subject:' in line or 'Not Before:' in line or 'Not After:' in line:
                print(f"   {line.strip()}")
        
        return True
    except Exception as e:
        print(f"❌ Error al verificar certificado: {e}")
        return False

if __name__ == "__main__":
    print("🔐 Generador de Certificados SSL para Chat LAN")
    print("=" * 60)
    generate_ssl_certificate()
    print("\n" + "=" * 60)
    verify_certificates()
