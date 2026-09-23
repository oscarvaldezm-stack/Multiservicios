"""Pruebas unitarias puras del cifrado de campos, rotación de llaves e índice ciego."""
import base64
import os
import uuid

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.crypto import (
    CryptoError,
    FieldCipher,
    LocalKeyProvider,
    blind_index,
    cipher_for_profile,
    mask_identifier,
    new_wrapped_dek,
)

CURP = "HEGG560427MVZRRL04"


def _key() -> bytes:
    return os.urandom(32)


def test_cifrado_ida_y_vuelta_y_no_deja_texto_plano():
    c, row = FieldCipher(_key()), uuid.uuid4()
    blob = c.encrypt("kyc_profiles", row, "curp", CURP)
    assert CURP.encode() not in blob
    assert c.decrypt("kyc_profiles", row, "curp", blob) == CURP


def test_mismo_valor_produce_textos_cifrados_distintos():
    c, row = FieldCipher(_key()), uuid.uuid4()
    assert c.encrypt("t", row, "curp", CURP) != c.encrypt("t", row, "curp", CURP)


def test_copiar_cifrado_a_otra_fila_o_campo_no_descifra():
    c, a, b = FieldCipher(_key()), uuid.uuid4(), uuid.uuid4()
    blob = c.encrypt("kyc_profiles", a, "curp", CURP)
    with pytest.raises(CryptoError):
        c.decrypt("kyc_profiles", b, "curp", blob)       # otra fila
    with pytest.raises(CryptoError):
        c.decrypt("kyc_profiles", a, "rfc", blob)        # otro campo


def test_cifrado_manipulado_se_detecta():
    c, row = FieldCipher(_key()), uuid.uuid4()
    blob = bytearray(c.encrypt("t", row, "curp", CURP))
    blob[-1] ^= 0x01
    with pytest.raises(CryptoError):
        c.decrypt("t", row, "curp", bytes(blob))


def test_otra_llave_no_descifra():
    row = uuid.uuid4()
    blob = FieldCipher(_key()).encrypt("t", row, "curp", CURP)
    with pytest.raises(CryptoError):
        FieldCipher(_key()).decrypt("t", row, "curp", blob)


def test_rotacion_de_llave_maestra():
    k1, k2, pid = _key(), _key(), uuid.uuid4()
    old = LocalKeyProvider({1: k1}, active_id=1)
    wrapped = new_wrapped_dek(pid, old)
    rotated = LocalKeyProvider({1: k1, 2: k2}, active_id=2)
    # Las DEK viejas se siguen abriendo con la llave anterior...
    cipher_for_profile(pid, wrapped, rotated)
    # ...y las nuevas quedan envueltas con la llave 2.
    assert new_wrapped_dek(pid, rotated)[1] == 2
    # Sin la llave 1 ya no se puede abrir lo viejo.
    with pytest.raises(CryptoError):
        cipher_for_profile(pid, wrapped, LocalKeyProvider({2: k2}, active_id=2))


def test_dek_ligada_a_su_expediente():
    provider, pid = LocalKeyProvider({1: _key()}, 1), uuid.uuid4()
    wrapped = new_wrapped_dek(pid, provider)
    with pytest.raises(CryptoError):
        cipher_for_profile(uuid.uuid4(), wrapped, provider)   # otra DEK no sirve para otro expediente


def test_borrado_criptografico():
    with pytest.raises(CryptoError):
        cipher_for_profile(uuid.uuid4(), None)


def test_indice_ciego_normaliza_y_separa_espacios():
    key = _key()
    assert blind_index("curp", CURP, key) == blind_index("curp", " hegg560427mvzrrl04 ", key)
    assert blind_index("curp", CURP, key) != blind_index("rfc", CURP, key)
    assert blind_index("curp", CURP, key) != blind_index("curp", CURP, _key())
    assert len(blind_index("curp", CURP, key)) == 64


def test_enmascarado():
    assert mask_identifier(CURP) == "HEGG" + "•" * 12 + "04"
    assert mask_identifier(None) is None


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode()


def test_configuracion_exige_llaves_distintas_y_de_32_bytes():
    base = dict(DATABASE_URL="postgresql+psycopg://u:p@h/d", JWT_SECRET_KEY="j" * 40,
                KYC_MASTER_KEY=_b64(b"a" * 32), KYC_BLIND_INDEX_KEY=_b64(b"a" * 32))
    with pytest.raises(ValidationError, match="distintas"):
        Settings(**base)
    ok = Settings(**{**base, "KYC_BLIND_INDEX_KEY": _b64(b"c" * 32)})
    from app.core.crypto import _b64_key
    with pytest.raises(ValueError, match="32 bytes"):
        _b64_key(_b64(b"x" * 16), "KYC_MASTER_KEY")
    assert ok.KYC_MASTER_KEY_ID == 1
