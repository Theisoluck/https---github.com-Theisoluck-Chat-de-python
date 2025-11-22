from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import SHA256
import json
import base64
import logging
import hashlib
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

# =============================
# Configuración sin hard coding
# =============================
_env_salt_b64 = os.getenv("CHAT_SALT_BASE64", "U2FsdEZvckNoYXRMQU4yMDI0")  # Valor por defecto

try:
    FIXED_SALT = base64.b64decode(_env_salt_b64)
except Exception:
    # Fallback a una sal por defecto si hay error
    FIXED_SALT = b"SaltForChatLAN2024"


def derive_key(password: str):
    key = scrypt(password.encode(), FIXED_SALT, 32, N=2**14, r=8, p=1)
    fp = hashlib.sha256(key).hexdigest()[:8]
    logger.info(f"🔑 Clave derivada (fingerprint): {fp}... (len: {len(key)} bytes)")
    return key


def calculate_sha256(data: dict) -> str:
    json_str = json.dumps(data, sort_keys=True)
    hash_obj = SHA256.new(json_str.encode())
    return hash_obj.hexdigest()


def encrypt_json(data: dict, key: bytes) -> str:
    data_with_hash = data.copy()
    hash_value = calculate_sha256(data)
    data_with_hash["sha256"] = hash_value

    plaintext = json.dumps(data_with_hash).encode()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    result = {
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "data": base64.b64encode(ciphertext).decode(),
    }

    return json.dumps(result)


def decrypt_json(encrypted_json: str, key: bytes) -> dict:
    obj = json.loads(encrypted_json)
    nonce = base64.b64decode(obj["nonce"])
    tag = base64.b64decode(obj["tag"])
    ciphertext = base64.b64decode(obj["data"])

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    data_with_hash = json.loads(plaintext)

    received_hash = data_with_hash.pop("sha256", None)
    if received_hash:
        calculated_hash = calculate_sha256(data_with_hash)
        if received_hash != calculated_hash:
            raise ValueError("❌ Verificación SHA-256 fallida: integridad comprometida.")
    return data_with_hash
