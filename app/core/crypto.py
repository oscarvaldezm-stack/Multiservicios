"""
Cifrado de campos sensibles del KYC (CURP, RFC, números de documento).

Diseño (cifrado de sobre / envelope encryption):

    KEK (llave maestra)  --cifra-->  DEK (una por expediente)  --cifra-->  campos

- La KEK vive fuera de la base: variable de entorno en desarrollo, KMS en producción
  (se cambia implementando otro `KeyProvider`, sin tocar el resto del código).
- Cada expediente tiene su propia DEK aleatoria de 256 bits, guardada CIFRADA en
  `kyc_profiles.data_key_enc`. Destruir esa DEK = borrado criptográfico: los campos
  quedan ilegibles incluso en respaldos antiguos.
- AES-256-GCM con datos asociados (AAD) = "<tabla>:<id_fila>:<campo>". Un texto
  cifrado copiado a otra fila u otro campo NO descifra: evita que alguien con acceso
  a la base intercambie la CURP de un técnico por la de otro.
- Índice ciego: HMAC-SHA256 con una llave distinta sobre el valor normalizado.
  Permite UNIQUE y búsquedas de duplicados sin descifrar nada.

Formato del texto cifrado:  versión(1 byte) | key_id(1 byte) | nonce(12) | ciphertext+tag
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import uuid
from abc import ABC, abstractmethod
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

_FORMAT_VERSION = 1
_NONCE_BYTES = 12


class CryptoError(Exception):
    """Texto cifrado inválido, manipulado o llave destruida."""


def _b64_key(value: str, name: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value.encode() + b"=" * (-len(value) % 4))
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"{name} no es base64 válido") from exc
    if len(raw) != 32:
        raise ValueError(f"{name} debe decodificar a exactamente 32 bytes")
    return raw


def _encrypt(key: bytes, key_id: int, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(_NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return bytes([_FORMAT_VERSION, key_id]) + nonce + ct


def _decrypt(key_lookup, blob: bytes, aad: bytes) -> bytes:
    if not blob or len(blob) < 2 + _NONCE_BYTES + 16 or blob[0] != _FORMAT_VERSION:
        raise CryptoError("Formato de texto cifrado inválido")
    key = key_lookup(blob[1])
    nonce, ct = blob[2 : 2 + _NONCE_BYTES], blob[2 + _NONCE_BYTES :]
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise CryptoError("No se pudo descifrar (dato manipulado o contexto distinto)") from exc


# ---------------------------------------------------------------------------
# Proveedor de la llave maestra (KEK)
# ---------------------------------------------------------------------------
class KeyProvider(ABC):
    """Envuelve y desenvuelve DEKs. En producción: implementación sobre AWS KMS."""

    @abstractmethod
    def wrap(self, dek: bytes, context: bytes) -> bytes: ...

    @abstractmethod
    def unwrap(self, wrapped: bytes, context: bytes) -> bytes: ...

    @property
    @abstractmethod
    def active_key_id(self) -> int: ...

    @abstractmethod
    def fingerprints(self) -> dict[int, str]:
        """Huella pública de cada llave configurada (nunca la llave). Sirve para verificar
        que el entorno tiene cargada la llave que la base espera."""

    def rewrap(self, wrapped: bytes, context: bytes) -> bytes:
        """Rotación: abre la DEK con la llave con que fue envuelta y la vuelve a envolver con la activa.
        Los datos cifrados con la DEK no se tocan."""
        return self.wrap(self.unwrap(wrapped, context), context)


class LocalKeyProvider(KeyProvider):
    """
    KEKs desde variables de entorno. Soporta rotación: la llave activa cifra, y las
    anteriores (por key_id) siguen sirviendo para descifrar DEKs viejas.
    """

    def __init__(self, keys: dict[int, bytes], active_id: int):
        if active_id not in keys:
            raise ValueError("La llave activa no está entre las llaves configuradas")
        self._keys = keys
        self._active = active_id

    def _lookup(self, key_id: int) -> bytes:
        try:
            return self._keys[key_id]
        except KeyError:
            raise CryptoError(f"Llave maestra {key_id} no disponible") from None

    def wrap(self, dek: bytes, context: bytes) -> bytes:
        return _encrypt(self._keys[self._active], self._active, dek, b"dek:" + context)

    def unwrap(self, wrapped: bytes, context: bytes) -> bytes:
        return _decrypt(self._lookup, wrapped, b"dek:" + context)

    @property
    def active_key_id(self) -> int:
        return self._active

    def fingerprints(self) -> dict[int, str]:
        return {kid: key_fingerprint(k) for kid, k in self._keys.items()}


@lru_cache
def get_key_provider() -> KeyProvider:
    s = get_settings()
    keys = {s.KYC_MASTER_KEY_ID: _b64_key(s.KYC_MASTER_KEY.get_secret_value(), "KYC_MASTER_KEY")}
    if s.KYC_PREVIOUS_MASTER_KEYS:
        for entry in s.KYC_PREVIOUS_MASTER_KEYS.get_secret_value().split(","):
            kid, _, val = entry.strip().partition(":")
            keys[int(kid)] = _b64_key(val, f"KYC_PREVIOUS_MASTER_KEYS[{kid}]")
    return LocalKeyProvider(keys, s.KYC_MASTER_KEY_ID)


# ---------------------------------------------------------------------------
# Cifrado de campos con la DEK del expediente
# ---------------------------------------------------------------------------
def _field_aad(table: str, row_id: uuid.UUID, field: str) -> bytes:
    return f"{table}:{row_id}:{field}".encode()


class FieldCipher:
    """Cifra/descifra campos de UNA fila usando la DEK de su expediente."""

    def __init__(self, dek: bytes):
        if len(dek) != 32:
            raise CryptoError("DEK inválida")
        self._dek = dek

    def encrypt(self, table: str, row_id: uuid.UUID, field: str, value: str) -> bytes:
        return _encrypt(self._dek, 0, value.encode("utf-8"), _field_aad(table, row_id, field))

    def decrypt(self, table: str, row_id: uuid.UUID, field: str, blob: bytes) -> str:
        return self.decrypt_bytes(table, row_id, field, blob).decode("utf-8")

    def encrypt_bytes(self, table: str, row_id: uuid.UUID, field: str, value: bytes) -> bytes:
        return _encrypt(self._dek, 0, value, _field_aad(table, row_id, field))

    def decrypt_bytes(self, table: str, row_id: uuid.UUID, field: str, blob: bytes) -> bytes:
        return _decrypt(lambda _kid: self._dek, blob, _field_aad(table, row_id, field))


# ---------------------------------------------------------------------------
# Archivos: una llave por archivo (FEK), envuelta con la DEK del expediente
# ---------------------------------------------------------------------------
#   KEK (KMS) -> DEK del expediente -> FEK del archivo -> bytes del archivo
# Destruir la DEK (borrado criptográfico del expediente) deja ilegibles también los
# archivos, aunque queden copias en el bucket, en su versionado o en respaldos.
FILE_TABLE = "kyc_document_files"


def new_file_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def _file_aad(file_id: uuid.UUID, variant: str) -> bytes:
    return f"{FILE_TABLE}:{file_id}:{variant}".encode()


def encrypt_file(fek: bytes, file_id: uuid.UUID, variant: str, data: bytes) -> bytes:
    """variant: 'original' o 'preview'. El mismo archivo cifrado no descifra como otra variante u otro archivo."""
    return _encrypt(fek, 0, data, _file_aad(file_id, variant))


def decrypt_file(fek: bytes, file_id: uuid.UUID, variant: str, blob: bytes) -> bytes:
    return _decrypt(lambda _kid: fek, blob, _file_aad(file_id, variant))


def wrapped_key_id(blob: bytes) -> int:
    """ID de la llave maestra con que se envolvió una DEK (segundo byte del formato)."""
    if not blob or len(blob) < 2:
        raise CryptoError("Formato inválido")
    return blob[1]


def key_fingerprint(key: bytes) -> str:
    return hmac.new(key, b"multiservicios-key-fingerprint-v1", hashlib.sha256).hexdigest()[:16]


def new_wrapped_dek(profile_id: uuid.UUID, provider: KeyProvider | None = None) -> bytes:
    """Genera una DEK nueva para un expediente y la devuelve ya envuelta por la KEK."""
    provider = provider or get_key_provider()
    return provider.wrap(AESGCM.generate_key(bit_length=256), str(profile_id).encode())


def cipher_for_profile(profile_id: uuid.UUID, wrapped_dek: bytes | None,
                       provider: KeyProvider | None = None) -> FieldCipher:
    if not wrapped_dek:
        raise CryptoError("La llave de este expediente fue destruida (borrado criptográfico)")
    provider = provider or get_key_provider()
    return FieldCipher(provider.unwrap(wrapped_dek, str(profile_id).encode()))


# ---------------------------------------------------------------------------
# Índice ciego
# ---------------------------------------------------------------------------
def normalize_identifier(value: str) -> str:
    return "".join(value.split()).upper()


def blind_index(kind: str, value: str, key: bytes | None = None) -> str:
    """HMAC-SHA256 hex (64 chars). `kind` separa espacios: la misma cadena como CURP y como RFC da índices distintos."""
    if key is None:
        key = _b64_key(get_settings().KYC_BLIND_INDEX_KEY.get_secret_value(), "KYC_BLIND_INDEX_KEY")
    msg = f"{kind}:{normalize_identifier(value)}".encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Enmascarado para auditoría y logs
# ---------------------------------------------------------------------------
def mask_identifier(value: str | None, keep_start: int = 4, keep_end: int = 2) -> str | None:
    if value is None:
        return None
    v = normalize_identifier(value)
    if len(v) <= keep_start + keep_end:
        return "•" * len(v)
    return v[:keep_start] + "•" * (len(v) - keep_start - keep_end) + v[-keep_end:]
