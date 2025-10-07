from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
import json
import base64
import logging

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

def encrypt_json(data: dict, key: bytes) -> str:
    """Cifra un diccionario a JSON seguro."""
    plaintext = json.dumps(data).encode()
    logger.debug(f"📨 Cifrando mensaje tipo: {data.get('type', 'unknown')}")
    
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
    """Descifra un JSON cifrado y devuelve el diccionario original."""
    try:
        obj = json.loads(encrypted_json)
        nonce = base64.b64decode(obj["nonce"])
        tag = base64.b64decode(obj["tag"])
        ciphertext = base64.b64decode(obj["data"])
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        data = json.loads(plaintext)
        logger.debug(f"📬 Mensaje descifrado tipo: {data.get('type', 'unknown')}")
        return data
    except Exception as e:
        logger.error(f"❌ Error al descifrar: {e}")
        raise

def verify_encryption(password: str) -> bool:
    """Verifica que el cifrado funciona correctamente."""
    test_key = derive_key(password)
    test_data = {"type": "test", "message": "Hola mundo"}
    
    try:
        encrypted = encrypt_json(test_data, test_key)
        decrypted = decrypt_json(encrypted, test_key)
        return decrypted == test_data
    except Exception as e:
        logger.error(f"❌ Verificación fallida: {e}")
        return False