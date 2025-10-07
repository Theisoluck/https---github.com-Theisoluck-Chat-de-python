from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import json, base64

# --- Constantes RSA ---
RSA_KEY_SIZE = 2048 # Tamaño estándar
# Máximo de bytes de datos que podemos cifrar en un solo bloque (2048/8) - 42 bytes de padding
MAX_PLAINTEXT_BYTES = 214 

# --- Funciones RSA (Asimétrico Exclusivo) ---

def generate_rsa_key_pair():
    """Genera un par de claves RSA de 2048 bits (privada y pública)."""
    key = RSA.generate(RSA_KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_rsa_message(data: dict, public_key_pem: bytes) -> str:
    """
    Cifra un diccionario JSON usando la clave pública RSA.
    ADVERTENCIA: Solo puede cifrar mensajes de hasta 214 bytes de longitud.
    """
    plaintext = json.dumps(data).encode('utf-8')
    
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise ValueError(f"Mensaje demasiado largo ({len(plaintext)} bytes). RSA solo soporta hasta {MAX_PLAINTEXT_BYTES} bytes por mensaje.")
        
    rsa_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    
    encrypted_bytes = cipher_rsa.encrypt(plaintext)
    
    # Devolver los bytes cifrados codificados en Base64 y como string JSON
    result = {"data": base64.b64encode(encrypted_bytes).decode()}
    return json.dumps(result)

def decrypt_rsa_message(encrypted_json: str, private_key_pem: bytes) -> dict:
    """
    Descifra un JSON cifrado usando la clave privada RSA.
    """
    obj = json.loads(encrypted_json)
    encrypted_bytes = base64.b64decode(obj["data"])

    rsa_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    
    plaintext = cipher_rsa.decrypt(encrypted_bytes)
    
    return json.loads(plaintext.decode('utf-8'))
