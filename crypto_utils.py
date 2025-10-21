from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA256
import json
import base64
import logging
import hashlib

# Configurar logging para depuración (opcional)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# ⚠️ IMPORTANTE: Esta sal debe ser idéntica en cliente y servidor
FIXED_SALT = b"sal-fija-chat-2024"

def derive_key(password: str):
    """Deriva una clave AES de 32 bytes a partir de una contraseña."""
    key = scrypt(password.encode(), FIXED_SALT, 32, N=2**14, r=8, p=1)
    logger.info(f"🔑 Clave derivada: {key.hex()[:16]}... (longitud: {len(key)} bytes)")
    return key

def calculate_sha256(data: dict) -> str:
    """Calcula el hash SHA-256 del contenido JSON."""
    json_str = json.dumps(data, sort_keys=True)
    hash_obj = SHA256.new(json_str.encode())
    return hash_obj.hexdigest()

def encrypt_json(data: dict, key: bytes) -> str:
    """Cifra un diccionario a JSON seguro con verificación SHA-256."""
    # Añadimos el hash SHA-256 al mensaje original
    data_with_hash = data.copy()
    hash_value = calculate_sha256(data)
    data_with_hash["sha256"] = hash_value
    
    # Mostrar hash en la consola para mensajes
    if data.get("type") == "msg":
        logger.info(f"🔐 SHA-256 hash del mensaje: {hash_value}")
    
    plaintext = json.dumps(data_with_hash).encode()
    logger.debug(f"📨 Cifrando mensaje tipo: {data.get('type', 'unknown')} con SHA-256")
    
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    result = {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "data": base64.b64encode(ciphertext).decode(),
    }
    
    encrypted_json = json.dumps(result)
    logger.debug(f"🔒 Mensaje cifrado ({len(encrypted_json)} bytes)")
    return encrypted_json

def decrypt_json(encrypted_json: str, key: bytes) -> dict:
    """Descifra un JSON cifrado y verifica su hash SHA-256."""
    try:
        obj = json.loads(encrypted_json)
        nonce = base64.b64decode(obj["nonce"])
        tag = base64.b64decode(obj["tag"])
        ciphertext = base64.b64decode(obj["data"])
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        data_with_hash = json.loads(plaintext)
        
        # Extraer y verificar el hash SHA-256
        received_hash = data_with_hash.pop("sha256", None)
        if received_hash:
            calculated_hash = calculate_sha256(data_with_hash)
            
            # Mostrar información de verificación para mensajes en la consola
            if data_with_hash.get("type") == "msg":
                print(f"\n📩 Mensaje recibido - Verificación SHA-256:")
                print(f"   └─ Tipo: {data_with_hash.get('type')}")
                print(f"   └─ Usuario: {data_with_hash.get('user', 'Anon')}")
                print(f"   └─ Hash recibido: {received_hash}")
                print(f"   └─ Hash calculado: {calculated_hash}")
                print(f"   └─ Verificación: {'✅ CORRECTA' if received_hash == calculated_hash else '❌ FALLIDA'}")
                
            if received_hash != calculated_hash:
                logger.error(f"⚠️ Advertencia: Hash SHA-256 no coincide. Posible manipulación del mensaje.")
                logger.error(f"Hash recibido: {received_hash}")
                logger.error(f"Hash calculado: {calculated_hash}")
                raise ValueError("Verificación SHA-256 fallida: integridad del mensaje comprometida")
            logger.debug(f"✅ Verificación SHA-256 exitosa")
        else:
            # Para compatibilidad con mensajes antiguos sin hash
            logger.warning("⚠️ El mensaje no incluye verificación SHA-256")
        
        logger.debug(f"📬 Mensaje descifrado tipo: {data_with_hash.get('type', 'unknown')}")
        return data_with_hash
    except Exception as e:
        logger.error(f"❌ Error al descifrar: {e}")
        raise

def verify_encryption(password: str) -> bool:
    """Verifica que el cifrado y hash SHA-256 funcionan correctamente."""
    test_key = derive_key(password)
    test_data = {"type": "test", "message": "Hola mundo"}
    
    try:
        # Verificación de cifrado y descifrado
        encrypted = encrypt_json(test_data, test_key)
        decrypted = decrypt_json(encrypted, test_key)
        
        # Eliminar el hash sha256 para la comparación
        if "sha256" in decrypted:
            del decrypted["sha256"]
            
        basic_check = decrypted == test_data
        
        # Verificación explícita de SHA-256
        sha256_test_data = test_data.copy()
        sha256_hash = calculate_sha256(sha256_test_data)
        sha256_check = len(sha256_hash) == 64  # SHA-256 produce 64 caracteres hex
        
        logger.info(f"Verificación básica: {'✅' if basic_check else '❌'}")
        logger.info(f"Verificación SHA-256: {'✅' if sha256_check else '❌'}")
        
        return basic_check and sha256_check
    except Exception as e:
        logger.error(f"❌ Verificación fallida: {e}")
        return False

# Añadir función para obtener MD5 de un archivo para control de cambios
def get_file_md5(file_path: str) -> str:
    """Calcula el MD5 hash de un archivo."""
    try:
        with open(file_path, 'rb') as f:
            md5_hash = hashlib.md5()
            # Leer en bloques para archivos grandes
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
            return md5_hash.hexdigest()
    except Exception as e:
        logger.error(f"❌ Error calculando MD5 del archivo {file_path}: {e}")
        return "ERROR"