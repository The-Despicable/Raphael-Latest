import os, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def generate_keypair() -> tuple[bytes, bytes]:
    sk = Ed25519PrivateKey.generate()
    return sk.public_key().public_bytes_raw(), sk.private_bytes_raw()

def encrypt(key: bytes, plaintext: bytes) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ct).decode()

def decrypt(key: bytes, wire: str) -> bytes:
    raw = base64.b64decode(wire)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None)
