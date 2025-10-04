# crypto_utils.py
# Utilidades de cifrado AES para el chat
# Requisitos: pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import json

def derive_key(password: str, salt: bytes = None) -> tuple:
    """Deriva una clave AES-256 desde una contraseña usando PBKDF2"""
    if salt is None:
        salt = get_random_bytes(16)
    key = PBKDF2(password, salt, 32, count=100000)  # 32 bytes = 256 bits
    return key, salt

def encrypt_message(message: str, key: bytes) -> str:
    """Cifra un mensaje usando AES-GCM y retorna base64"""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    
    # Combinar nonce + tag + ciphertext y codificar en base64
    encrypted_data = cipher.nonce + tag + ciphertext
    return base64.b64encode(encrypted_data).decode('ascii')

def decrypt_message(encrypted_msg: str, key: bytes) -> str:
    """Descifra un mensaje desde base64 usando AES-GCM"""
    try:
        encrypted_data = base64.b64decode(encrypted_msg.encode('ascii'))
        
        # Extraer componentes
        nonce = encrypted_data[:16]  # AES-GCM nonce es de 16 bytes por defecto
        tag = encrypted_data[16:32]  # Tag es de 16 bytes
        ciphertext = encrypted_data[32:]
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        message = cipher.decrypt_and_verify(ciphertext, tag)
        return message.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Error al descifrar: {e}")

def encrypt_json(data: dict, key: bytes) -> str:
    """Cifra un objeto JSON completo"""
    json_str = json.dumps(data, ensure_ascii=False)
    return encrypt_message(json_str, key)

def decrypt_json(encrypted_data: str, key: bytes) -> dict:
    """Descifra y parsea un objeto JSON"""
    json_str = decrypt_message(encrypted_data, key)
    return json.loads(json_str)