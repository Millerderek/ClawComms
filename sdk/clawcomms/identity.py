"""
Identity Manager — holds the bot's Ed25519 keypair in memory only.
Private key is never written to disk. Generated fresh each process start
or loaded from an in-memory seed provided at init.
"""

import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class IdentityManager:
    def __init__(self):
        self._private_key = Ed25519PrivateKey.generate()
        self._public_key  = self._private_key.public_key()

    @property
    def public_key_hex(self) -> str:
        raw = self._public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return raw.hex()

    @property
    def fingerprint(self) -> str:
        raw = self._public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return hashlib.sha256(raw).hexdigest()

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    def zeroize(self):
        """Best-effort: replace private key reference. GC handles the rest."""
        self._private_key = None
        self._public_key  = None
