# crypto_utils.py
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
import json, base64

# ⚠️ IMPORTANTE: Esta sal debe ser idéntica en cliente y servidor
FIXED_SALT = b"sal-fija-chat-2024"

def derive_key(password: str):
    """Deriva una clave AES de 32 bytes a partir de una contraseña."""
    key = scrypt(password.encode(), FIXED_SALT, 32, N=2**14, r=8, p=1)
    return key

def encrypt_json(data: dict, key: bytes) -> str:
    """Cifra un diccionario a JSON seguro."""
    plaintext = json.dumps(data).encode()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    result = {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "data": base64.b64encode(ciphertext).decode(),
    }
    return json.dumps(result)

def decrypt_json(encrypted_json: str, key: bytes) -> dict:
    """Descifra un JSON cifrado y devuelve el diccionario original."""
    obj = json.loads(encrypted_json)
    nonce = base64.b64decode(obj["nonce"])
    tag = base64.b64decode(obj["tag"])
    ciphertext = base64.b64decode(obj["data"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return json.loads(plaintext)
