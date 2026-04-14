import os
import hmac
import hashlib
import struct
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DEFAULT_PSK = b"replace-with-32+bytes-random-key!!!"


def generate_nonce(length: int) -> bytes:
    return os.urandom(length)


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def make_hmac(psk: bytes, data: bytes) -> bytes:
    return hmac.new(psk, data, hashlib.sha256).digest()


def verify_hmac(psk: bytes, data: bytes, received_mac: bytes) -> bool:
    expected = make_hmac(psk, data)
    return hmac.compare_digest(expected, received_mac)


def load_psk(psk_file: Optional[str] = None) -> bytes:
    """Load PSK from file if provided, otherwise fallback to env/default.

    File handling rules:
    - binary file: use raw bytes
    - text file: trim whitespace; if starts with hex: parse hex
    """
    if psk_file:
        raw = open(psk_file, 'rb').read().strip()
        if raw.startswith(b'hex:'):
            return bytes.fromhex(raw[4:].decode('ascii'))
        return raw

    env_hex = os.getenv('SRFT_PSK_HEX')
    if env_hex:
        return bytes.fromhex(env_hex)

    env_text = os.getenv('SRFT_PSK')
    if env_text:
        return env_text.encode('utf-8')

    return DEFAULT_PSK


def derive_session_keys(psk: bytes, client_nonce: bytes, server_nonce: bytes):
    """Derive directional keys and nonce prefixes from PSK + nonces."""
    salt = client_nonce + server_nonce

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32 + 32 + 4 + 4,
        salt=salt,
        info=b"srft-phase2",
        backend=default_backend(),
    )

    key_material = hkdf.derive(psk)

    return {
        "c2s_key": key_material[0:32],
        "s2c_key": key_material[32:64],
        "c2s_nonce_prefix": key_material[64:68],
        "s2c_nonce_prefix": key_material[68:72],
    }


def build_gcm_nonce(prefix: bytes, counter: int) -> bytes:
    return prefix + struct.pack("!Q", counter)


def encrypt_aead(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, aad)


def decrypt_aead(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)
