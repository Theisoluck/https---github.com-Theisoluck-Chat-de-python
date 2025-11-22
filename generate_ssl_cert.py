"""
Script para generar certificados SSL autofirmados para el chat LAN.
VERSIÓN 2: Sin dependencia de OpenSSL (usa cryptography)
"""
import os
import sys

def generate_ssl_certificate_with_cryptography():
    """Genera certificados SSL usando la librería cryptography (sin OpenSSL)."""
    
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        print("❌ ERROR: librería 'cryptography' no está instalada")
        print("\n📥 Instálala con:")
        print("   pip install cryptography")
        sys.exit(1)
    
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
    
    try:
        # Generar clave privada RSA
        print("   1️⃣  Generando clave privada RSA 4096-bits...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # Datos del certificado
        print("   2️⃣  Creando certificado autofirmado...")
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"MX"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Estado"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Ciudad"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ChatLAN"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Dev"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        
        # Crear certificado
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            __import__('datetime').datetime.utcnow()
        ).not_valid_after(
            __import__('datetime').datetime.utcnow() + __import__('datetime').timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.DNSName(u"127.0.0.1"),
                x509.DNSName(u"*"),
            ]),
            critical=False,
        ).sign(
            private_key,
            hashes.SHA256(),
            default_backend()
        )
        
        # Guardar clave privada
        print("   3️⃣  Guardando clave privada...")
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Guardar certificado
        print("   4️⃣  Guardando certificado...")
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print("\n✅ Certificado SSL generado exitosamente!")
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
        
    except Exception as e:
        print(f"❌ ERROR al generar certificado: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

def verify_certificates():
    """Verifica que los certificados existan y sean válidos."""
    cert_file = "server.crt"
    key_file = "server.key"
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("❌ Los certificados no existen.")
        return False
    
    print("\n🔍 Verificando certificado...")
    
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        
        with open(cert_file, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        print("✅ Certificado válido")
        print(f"   Sujeto: {cert.subject.rfc4514_string()}")
        print(f"   Válido desde: {cert.not_valid_before}")
        print(f"   Válido hasta: {cert.not_valid_after}")
        print(f"   Serial: {cert.serial_number}")
        
        return True
    except Exception as e:
        print(f"❌ Error al verificar certificado: {e}")
        return False

if __name__ == "__main__":
    print("🔐 Generador de Certificados SSL para Chat LAN")
    print("=" * 60)
    print("ℹ️  Versión sin OpenSSL (usa librería cryptography)\n")
    generate_ssl_certificate_with_cryptography()
    print("\n" + "=" * 60)
    verify_certificates()

