"""Cifrado autenticado de respaldos locales, sin persistir frases secretas."""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_MAGIC = b"SAREVAT-BACKUP-1\x00"
_SALT_SIZE = 16
_NONCE_SIZE = 12


class BackupCipher:
    """Deriva una clave temporal desde una frase proporcionada por el operador."""

    def __init__(self, passphrase: str) -> None:
        if len(passphrase) < 12:
            raise ValueError("La frase de respaldo debe tener al menos 12 caracteres.")
        self._passphrase = passphrase.encode("utf-8")

    def encrypt(self, plaintext: str) -> bytes:
        salt = os.urandom(_SALT_SIZE)
        nonce = os.urandom(_NONCE_SIZE)
        key = self._derive_key(salt)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), _MAGIC)
        return _MAGIC + salt + nonce + ciphertext

    def decrypt(self, payload: bytes) -> str:
        minimum = len(_MAGIC) + _SALT_SIZE + _NONCE_SIZE + 16
        if len(payload) < minimum or not payload.startswith(_MAGIC):
            raise ValueError("El respaldo cifrado no tiene un formato compatible.")
        offset = len(_MAGIC)
        salt = payload[offset : offset + _SALT_SIZE]
        nonce = payload[offset + _SALT_SIZE : offset + _SALT_SIZE + _NONCE_SIZE]
        ciphertext = payload[offset + _SALT_SIZE + _NONCE_SIZE :]
        try:
            return AESGCM(self._derive_key(salt)).decrypt(nonce, ciphertext, _MAGIC).decode("utf-8")
        except (InvalidTag, UnicodeDecodeError) as exc:
            raise ValueError("La frase es incorrecta o el respaldo fue alterado.") from exc

    def _derive_key(self, salt: bytes) -> bytes:
        return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(self._passphrase)
