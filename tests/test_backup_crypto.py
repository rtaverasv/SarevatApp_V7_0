from __future__ import annotations

import pytest

from sarevat.backup_crypto import BackupCipher


def test_backup_cipher_encrypts_and_detects_bad_phrase_or_changes() -> None:
    cipher = BackupCipher("frase-de-respaldo-segura")
    payload = cipher.encrypt("username admin secret oculto")
    assert b"oculto" not in payload
    assert cipher.decrypt(payload) == "username admin secret oculto"
    with pytest.raises(ValueError):
        BackupCipher("otra-frase-segura").decrypt(payload)
    with pytest.raises(ValueError):
        cipher.decrypt(payload[:-1] + b"x")


def test_backup_cipher_requires_a_long_phrase() -> None:
    with pytest.raises(ValueError, match="12"):
        BackupCipher("corta")
