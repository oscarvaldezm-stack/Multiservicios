"""
Pruebas del sistema de protección de datos (anexo): clasificación, cifrado en reposo,
rotación y revocación de llaves, borrado seguro, logs sin datos sensibles, enmascarado,
control de acceso, HTTPS y almacenamiento privado.
"""
import base64
import logging
import os
import stat
import uuid

import pytest
from sqlalchemy import inspect, select, text

from app.core import crypto
from app.core.actor import Actor
from app.core.config import Settings
from app.core.crypto import CryptoError, LocalKeyProvider, blind_index, key_fingerprint
from app.db.session import engine
from app.kyc import identity
from app.kyc.permissions import Permission
from app.models import (
    ActorType,
    AdminRole,
    AuditLog,
    EncryptionKeyMetadata,
    KeyPurpose,
    KeyStatus,
    KycDocument,
    KycDocumentFile,
)
from app.security import classification
from app.security import encryption_service as es
from app.security.log_sanitizer import SensitiveDataFilter, sanitize
from app.storage.object_storage import LocalObjectStorage, S3ObjectStorage, StorageError
from tests import filegen
from tests.conftest import get_profile, valid_curp, valid_rfc
from tests.test_kyc_documents import (  # noqa: F401  (fixtures)
    DOCS,
    INE_NUMBER,
    new_doc,
    process,
    raw_object,
    sepomex,
    tech,
    upload,
)

KEY1, KEY2 = b"m" * 32, b"n" * 32          # KEY1 = la de conftest (KYC_MASTER_KEY)
SYSTEM = Actor.system()


def use_provider(monkeypatch, keys: dict[int, bytes], active: int) -> LocalKeyProvider:
    provider = LocalKeyProvider(keys, active)
    monkeypatch.setattr(crypto, "get_key_provider", lambda: provider)
    monkeypatch.setattr(es, "get_key_provider", lambda: provider)
    return provider


@pytest.fixture
def ine_doc(client, db, tech):
    """Técnico con CURP/RFC cifrados y una INE con un archivo ya procesado (bucket limpio)."""
    uid, h = tech
    doc_id = new_doc(client, h).json()["id"]
    assert upload(client, h, doc_id, "FRONT", filegen.jpeg(seed=7)).status_code in (200, 202)
    process(db)
    f = db.scalar(select(KycDocumentFile).where(KycDocumentFile.document_id == doc_id))
    return get_profile(db, uid), db.get(KycDocument, doc_id), f


def read_clean(profile, f) -> bytes:
    return es.decrypt_file_variant(profile, f, "original", raw_object(f.bucket, f.object_key))


# =============================================================================
# 1. Clasificación
# =============================================================================
def test_toda_columna_cifrada_esta_declarada_y_es_binaria():
    insp = inspect(engine)
    declared = set(classification.ENCRYPTED_COLUMNS)
    found = set()
    for table in insp.get_table_names():
        for col in insp.get_columns(table):
            name = f"{table}.{col['name']}"
            if col["name"].endswith("_enc"):
                found.add(name)
                assert str(col["type"]) == "BYTEA", name
    assert found == declared


def test_ninguna_columna_guarda_en_claro_datos_prohibidos():
    insp = inspect(engine)
    bad = [f"{t}.{c['name']}" for t in insp.get_table_names() for c in insp.get_columns(t)
           if c["name"] in classification.FORBIDDEN_PLAINTEXT_COLUMNS]
    assert bad == []                                    # ni CURP, ni CLABE, ni tarjeta, ni CVV, ni password


def test_niveles_altos_exigen_cifrado_y_prohiben_logs():
    for level in (classification.DataClass.SENSITIVE, classification.DataClass.HIGHLY_SENSITIVE):
        c = classification.CONTROLS[level]
        assert c.encrypted_at_rest_app and c.masked_by_default and c.access_audited and not c.allowed_in_logs
    assert "NO se almacena" in classification.INVENTORY["bank.clabe"][1]
    assert "NUNCA" in classification.INVENTORY["payment.card"][1]


# =============================================================================
# 2. Cifrado en reposo
# =============================================================================
def test_la_base_no_contiene_identificadores_legibles(db, ine_doc):
    profile, doc, _ = ine_doc
    with engine.connect() as conn:
        dump = b"".join(
            bytes(str(row), "utf-8")
            for table in ("kyc_profiles", "kyc_documents", "kyc_document_files", "audit_logs", "outbox_events")
            for row in conn.execute(text(f'SELECT * FROM "{table}"'))
        )
    for secret in (valid_curp(4), valid_rfc(4), INE_NUMBER):
        assert secret.encode() not in dump
    # pero con la llave correcta sí se recupera
    assert es.decrypt_data(profile, es.PROFILE_TABLE, profile.id, "curp", profile.curp_enc) == valid_curp(4)
    assert es.decrypt_data(profile, es.DOCUMENT_TABLE, doc.id, "number", doc.number_enc) == INE_NUMBER


def test_el_cifrado_esta_ligado_a_su_fila_y_campo(db, ine_doc):
    profile, _, _ = ine_doc
    with pytest.raises(CryptoError):                    # CURP copiado al campo RFC: no descifra
        es.decrypt_data(profile, es.PROFILE_TABLE, profile.id, "rfc", profile.curp_enc)
    with pytest.raises(CryptoError):                    # CURP copiado a otro expediente: no descifra
        es.decrypt_data(profile, es.PROFILE_TABLE, uuid.uuid4(), "curp", profile.curp_enc)
    tampered = bytearray(profile.curp_enc)
    tampered[-1] ^= 1
    with pytest.raises(CryptoError):                    # un bit alterado: GCM lo detecta
        es.decrypt_data(profile, es.PROFILE_TABLE, profile.id, "curp", bytes(tampered))


def test_objetos_en_el_bucket_son_ilegibles_sin_la_llave_del_archivo(db, ine_doc):
    profile, _, f = ine_doc
    blob = raw_object(f.bucket, f.object_key)
    assert not blob.startswith(b"\xff\xd8") and b"JFIF" not in blob
    plain = read_clean(profile, f)
    assert plain.startswith(b"\xff\xd8\xff") and filegen.GPS_MARKER.encode() not in plain
    other = KycDocumentFile(id=uuid.uuid4(), file_key_enc=f.file_key_enc)     # misma FEK, otro id
    with pytest.raises(CryptoError):
        es.decrypt_file_variant(profile, other, "original", blob)


def test_numero_de_documento_se_devuelve_enmascarado(client, db, tech):
    _, h = tech
    created = new_doc(client, h)
    full = client.get(DOCS.rsplit("/", 1)[0], headers=h)            # expediente completo del técnico
    assert full.status_code == 200
    for r in (created, full):
        assert INE_NUMBER not in r.text and "HRGL" in r.text


# =============================================================================
# 3. Rotación y revocación de llaves
# =============================================================================
def test_rotacion_completa_sin_perder_datos(db, ine_doc, monkeypatch):
    profile, doc, f = ine_doc
    before = read_clean(profile, f)
    assert crypto.wrapped_key_id(profile.data_key_enc) == 1
    es.verify_key_configuration(db)                     # estado inicial sano

    # Paso 1: llave 2 activa, la 1 sigue disponible para descifrar.
    use_provider(monkeypatch, {1: KEY1, 2: KEY2}, active=2)
    with pytest.raises(es.KeyConfigurationError, match="no está registrada"):
        es.verify_key_configuration(db)
    es.register_active_kek(db, SYSTEM)
    db.commit()
    es.verify_key_configuration(db)
    status = {m.key_id: m.status for m in db.scalars(
        select(EncryptionKeyMetadata).where(EncryptionKeyMetadata.purpose == KeyPurpose.KYC_KEK))}
    assert status == {1: KeyStatus.DECRYPT_ONLY, 2: KeyStatus.ACTIVE}
    # Lo viejo se sigue leyendo (descifrado histórico) y lo nuevo se cifra con la 2.
    assert es.decrypt_data(profile, es.PROFILE_TABLE, profile.id, "curp", profile.curp_enc) == valid_curp(4)
    assert crypto.wrapped_key_id(crypto.new_wrapped_dek(uuid.uuid4())) == 2

    # Revocar antes de migrar: se niega (se perderían datos).
    with pytest.raises(es.KeyConfigurationError, match="expedientes con esta llave"):
        es.revoke_kek(db, SYSTEM, 1, "rotación anual")
    with pytest.raises(es.KeyConfigurationError, match="activa"):
        es.revoke_kek(db, SYSTEM, 2, "no")

    # Paso 2: re-envolver. Los campos y archivos NO se re-cifran.
    curp_blob, fek_blob = profile.curp_enc, f.file_key_enc
    assert es.rotate_keys(db, SYSTEM) == 1
    assert es.rotate_keys(db, SYSTEM) == 0              # idempotente
    db.expire_all()
    assert crypto.wrapped_key_id(profile.data_key_enc) == 2 and es.count_wrapped_with(db, 1) == 0
    assert profile.curp_enc == curp_blob and f.file_key_enc == fek_blob

    # Paso 3: revocar la 1 y retirarla de la configuración.
    es.revoke_kek(db, SYSTEM, 1, "rotación anual")
    db.commit()
    with pytest.raises(es.KeyConfigurationError, match="REVOCADA"):
        es.verify_key_configuration(db)                 # sigue configurada: el arranque falla
    use_provider(monkeypatch, {2: KEY2}, active=2)
    es.verify_key_configuration(db)
    assert es.decrypt_data(profile, es.PROFILE_TABLE, profile.id, "curp", profile.curp_enc) == valid_curp(4)
    assert read_clean(profile, f) == before

    # La llave vieja sola ya no abre nada; y una revocada no se reactiva.
    use_provider(monkeypatch, {1: KEY1}, active=1)
    with pytest.raises(CryptoError):
        es.decrypt_data(profile, es.PROFILE_TABLE, profile.id, "curp", profile.curp_enc)
    with pytest.raises(es.KeyConfigurationError, match="revocada"):
        es.register_active_kek(db, SYSTEM)
    actions = [a.action for a in db.scalars(select(AuditLog).where(AuditLog.action.like("security.key.%")))]
    assert {"security.key.activated", "security.key.rewrapped", "security.key.revoked"} <= set(actions)


def test_id_de_llave_reutilizado_con_otro_material_se_rechaza(db, monkeypatch):
    use_provider(monkeypatch, {1: KEY2}, active=1)      # id 1 pero llave distinta a la registrada
    with pytest.raises(es.KeyConfigurationError, match="no coincide"):
        es.verify_key_configuration(db)
    with pytest.raises(es.KeyConfigurationError, match="otra llave"):
        es.register_active_kek(db, SYSTEM)


def test_rekey_de_un_expediente_comprometido(db, ine_doc):
    profile, doc, f = ine_doc
    before = read_clean(profile, f)
    old_dek, old_curp, old_fek = profile.data_key_enc, profile.curp_enc, f.file_key_enc
    es.rekey_profile(db, SYSTEM, profile)
    db.commit()
    db.expire_all()
    assert profile.data_key_enc != old_dek and profile.curp_enc != old_curp and f.file_key_enc != old_fek
    assert es.decrypt_data(profile, es.PROFILE_TABLE, profile.id, "curp", profile.curp_enc) == valid_curp(4)
    assert es.decrypt_data(profile, es.DOCUMENT_TABLE, doc.id, "number", doc.number_enc) == INE_NUMBER
    assert read_clean(profile, f) == before             # el archivo del bucket no se tocó
    # Con la DEK vieja (la que se filtró) ya no se abren los datos nuevos.
    leaked = crypto.cipher_for_profile(profile.id, old_dek)
    with pytest.raises(CryptoError):
        leaked.decrypt(es.PROFILE_TABLE, profile.id, "curp", profile.curp_enc)


def test_reindexado_de_indices_ciegos(db, ine_doc):
    profile, doc, _ = ine_doc
    new_key = b"z" * 32
    assert es.reindex_blind_indexes(db, SYSTEM, new_key) == 1
    db.commit()
    db.expire_all()
    assert profile.curp_hash == blind_index("curp", valid_curp(4), new_key)
    assert doc.number_hash == blind_index("docnum:INE", INE_NUMBER, new_key)
    metas = db.scalars(select(EncryptionKeyMetadata).where(
        EncryptionKeyMetadata.purpose == KeyPurpose.BLIND_INDEX).order_by(EncryptionKeyMetadata.key_id)).all()
    assert [m.status for m in metas] == [KeyStatus.REVOKED, KeyStatus.ACTIVE]
    assert metas[-1].fingerprint == key_fingerprint(new_key)
    # El entorno aún tiene la llave vieja: el arranque lo detecta hasta que se cambie.
    with pytest.raises(es.KeyConfigurationError, match="índice ciego"):
        es.verify_key_configuration(db)


def test_metadatos_de_llaves_nunca_guardan_la_llave(db):
    rows = db.execute(text("SELECT * FROM encryption_keys_metadata")).all()
    assert rows
    dump = str(rows).encode()
    for raw in (KEY1, b"b" * 32):
        assert raw not in dump and base64.urlsafe_b64encode(raw) not in dump
    assert db.scalar(text("SELECT count(*) FROM encryption_keys_metadata "
                          "WHERE purpose = 'KYC_KEK' AND status = 'ACTIVE'")) == 1


# =============================================================================
# 4. Eliminación segura
# =============================================================================
def test_borrado_criptografico_deja_todo_ilegible(db, ine_doc):
    profile, doc, f = ine_doc
    blob = raw_object(f.bucket, f.object_key)
    identity.crypto_shred(db, profile, SYSTEM)
    db.commit()
    db.expire_all()
    assert profile.data_key_enc is None and profile.anonymized_at is not None
    for attempt in (
        lambda: es.decrypt_data(profile, es.PROFILE_TABLE, profile.id, "curp", profile.curp_enc),
        lambda: es.decrypt_data(profile, es.DOCUMENT_TABLE, doc.id, "number", doc.number_enc),
        lambda: es.decrypt_file_variant(profile, f, "original", blob),      # aun con una copia del bucket
    ):
        with pytest.raises(CryptoError):
            attempt()


def test_borrado_criptografico_respeta_retencion_legal(db, ine_doc):
    profile, _, _ = ine_doc
    profile.legal_hold = True
    with pytest.raises(PermissionError):
        identity.crypto_shred(db, profile, SYSTEM)


def test_eliminar_documento_borra_objeto_y_llave(client, db, tech, ine_doc):
    _, h = tech
    profile, doc, f = ine_doc
    bucket, key = f.bucket, f.object_key
    assert client.delete(f"{DOCS}/{doc.id}", headers=h).status_code == 204
    db.expire_all()
    assert f.file_key_enc is None and f.purged_at is not None
    from app.storage.object_storage import get_storage
    assert not get_storage().exists(bucket, key) and not get_storage().exists(bucket, key + "-preview")


# =============================================================================
# 5. Logs sin información sensible
# =============================================================================
@pytest.mark.parametrize("raw,leak,expected", [
    ("CLABE 012180001234567897 registrada", "012180001234567897", "**************7897"),
    ("tarjeta 4111 1111 1111 1111", "4111 1111 1111 1111", "****1111"),
    ("tarjeta 4111111111111111", "4111111111111111", "****1111"),
    (f"curp={valid_curp(4)}", valid_curp(4), "HEGG"),
    (f"rfc {valid_rfc(4)} ok", valid_rfc(4), "HEGG"),
    ("password=Secreta123!", "Secreta123!", "[REDACTADO]"),
    ('{"refresh_token": "abc.def.ghi-123456"}', "abc.def.ghi-123456", "[REDACTADO]"),
    ("Authorization: Bearer abcdefghijklmnop123", "abcdefghijklmnop123", "[REDACTADO]"),
    ("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJhLWZhbHNh", "eyJhbGciOiJIUzI1NiJ9", "[JWT-REDACTADO]"),
    ("GET /api/v1/kyc/file-views/AbCdEf0123456789AbCdEf0123456789AbCdEf01234 200",
     "AbCdEf0123456789AbCdEf0123456789AbCdEf01234", "[TICKET-REDACTADO]"),
    ("stripe sk_live_51HabcdefGHIJKLmnop", "sk_live_51HabcdefGHIJKLmnop", "[LLAVE-PROVEEDOR-REDACTADA]"),
    ("webhook whsec_abcdefgh12345678", "whsec_abcdefgh12345678", "[LLAVE-PROVEEDOR-REDACTADA]"),
])
def test_sanitizador_enmascara(raw, leak, expected):
    out = sanitize(raw)
    assert leak not in out and expected in out


def test_sanitizador_no_rompe_texto_normal():
    msg = "Orden 42 asignada al técnico 7 en CP 91700 por $1,250.00"
    assert sanitize(msg) == msg


def test_filtro_aplica_a_argumentos_y_excepciones(caplog):
    log = logging.getLogger("prueba.sanitizador")
    log.addFilter(SensitiveDataFilter())
    try:
        with caplog.at_level(logging.INFO, logger="prueba.sanitizador"):
            log.info("cuenta %s de %s", "012180001234567897", valid_curp(4))
            try:
                raise ValueError(f"CLABE inválida 012180001234567897 password=xyz12345")
            except ValueError:
                log.exception("fallo")
    finally:
        log.filters.clear()
    text_ = caplog.text
    assert "012180001234567897" not in text_ and valid_curp(4) not in text_ and "xyz12345" not in text_
    assert "**************7897" in text_


def test_logger_de_seguridad_tiene_el_filtro_instalado(caplog):
    from app.security import log_sanitizer
    log_sanitizer.install()
    with caplog.at_level(logging.WARNING, logger="security"):
        logging.getLogger("security").warning("intento con tarjeta 4111111111111111")
    assert "4111111111111111" not in caplog.text and "****1111" in caplog.text


def test_flujo_real_no_deja_datos_sensibles_en_logs(client, db, tech, caplog):
    _, h = tech
    with caplog.at_level(logging.DEBUG):
        doc_id = new_doc(client, h).json()["id"]
        upload(client, h, doc_id, "FRONT", filegen.jpeg(seed=3))
        process(db)
    for secret in (INE_NUMBER, valid_curp(4), valid_rfc(4), h["Authorization"].split()[1]):
        assert secret not in caplog.text


# =============================================================================
# 6. Enmascarado y control de acceso
# =============================================================================
@pytest.mark.parametrize("kind,value,expected", [
    ("clabe", "012180001234567897", "**************7897"),
    ("card", "4111-1111-1111-1111", "************1111"),
    ("phone", "+52 229 123 4567", "*********4567"),
    ("curp", "HEGG560427MVZRRL04", "HEGG" + "•" * 12 + "04"),
    ("email", "gloria@example.com", "g***@example.com"),
    ("clabe", None, None),
])
def test_enmascarado(kind, value, expected):
    assert es.mask_sensitive_data(kind, value) == expected


def test_enmascarado_de_tipo_desconocido_falla():
    with pytest.raises(ValueError):
        es.mask_sensitive_data("cvv", "123")


def _admin(*roles) -> Actor:
    return Actor(user_id=uuid.uuid4(), actor_type=ActorType.ADMIN, admin_roles=frozenset(roles))


def test_validate_access():
    owner = uuid.uuid4()
    tech = Actor(user_id=owner, actor_type=ActorType.TECHNICIAN)
    other_tech = Actor(user_id=uuid.uuid4(), actor_type=ActorType.TECHNICIAN)
    rev = _admin(AdminRole.KYC_REVIEWER)
    assert es.validate_access(tech, Permission.KYC_CASE_READ_ASSIGNED, owner_id=owner)
    assert not es.validate_access(other_tech, Permission.KYC_CASE_READ_ASSIGNED, owner_id=owner)
    assert es.validate_access(rev, Permission.KYC_CASE_READ_ASSIGNED, owner_id=owner, assigned_to=rev.user_id)
    assert not es.validate_access(rev, Permission.KYC_CASE_READ_ASSIGNED, owner_id=owner, assigned_to=uuid.uuid4())
    assert not es.validate_access(rev, Permission.KYC_CASE_READ_ANY, owner_id=owner)
    assert es.validate_access(_admin(AdminRole.KYC_SUPERVISOR), Permission.KYC_CASE_READ_ANY, owner_id=owner)
    for role in (AdminRole.SUPPORT, AdminRole.SUPERADMIN, AdminRole.FINANCE_ADMIN):
        assert not es.validate_access(_admin(role), Permission.KYC_CASE_READ_ANY, owner_id=owner)


# =============================================================================
# 7. HTTPS, cabeceras y configuración de producción
# =============================================================================
def test_en_produccion_se_exige_https_y_hsts(client, monkeypatch):
    import app.main as main
    monkeypatch.setattr(main.settings, "ENVIRONMENT", "production")
    r = client.get("/api/v1/kyc/catalogs/document-types")
    assert r.status_code == 400 and r.json()["detail"]["code"] == "HTTPS_REQUIRED"
    assert client.get("/health").status_code == 200                       # sondeo interno
    ok = client.get("/health", headers={"X-Forwarded-Proto": "https"})
    assert ok.headers["strict-transport-security"].startswith("max-age=63072000")


def test_cabeceras_de_seguridad_siempre(client):
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY" and r.headers["cache-control"] == "no-store"


def _prod(**over):
    base = dict(ENVIRONMENT="production", BCRYPT_ROUNDS=12, ALLOWED_HOSTS=["api.example.mx"],
                CORS_ORIGINS=["https://app.example.mx"], STORAGE_BACKEND="s3", S3_KMS_KEY_ID="arn:aws:kms:x",
                KYC_SCANNER="clamd")
    return Settings(**(base | over))


@pytest.mark.parametrize("over,msg", [
    ({"STORAGE_BACKEND": "local"}, "S3"),
    ({"S3_KMS_KEY_ID": None}, "KMS"),
    ({"KYC_SCANNER": "dev_eicar"}, "clamd"),
    ({"BCRYPT_ROUNDS": 4}, "BCRYPT"),
])
def test_produccion_rechaza_configuracion_insegura(over, msg):
    with pytest.raises(ValueError, match=msg):
        _prod(**over)


def test_produccion_valida_arranca():
    assert _prod().is_production


def test_llaves_iguales_se_rechazan():
    same = base64.urlsafe_b64encode(b"q" * 32).decode()
    with pytest.raises(ValueError, match="distintas"):
        Settings(KYC_MASTER_KEY=same, KYC_BLIND_INDEX_KEY=same)


def test_no_hay_llaves_en_el_codigo():
    """Ninguna llave de 32 bytes en base64 escrita en el código de la aplicación."""
    import re
    root = os.path.join(os.path.dirname(__file__), "..", "app")
    pattern = re.compile(r"['\"][A-Za-z0-9_-]{43}=?['\"]")
    hits = []
    for dirpath, _, files in os.walk(root):
        for name in files:
            if name.endswith(".py"):
                with open(os.path.join(dirpath, name), encoding="utf-8") as fh:
                    hits += [f"{name}: {m}" for m in pattern.findall(fh.read())]
    assert hits == []


# =============================================================================
# 8. Almacenamiento privado
# =============================================================================
def test_local_rechaza_rutas_peligrosas_y_guarda_con_permisos_0600(tmp_path):
    st = LocalObjectStorage(tmp_path)
    for key in ("../fuera", "/etc/passwd", "kyc/../../x", "KYC/Mayus", "kyc/a b", ""):
        with pytest.raises(StorageError):
            st.put("kyc-clean", key, b"x")
    with pytest.raises(StorageError):
        st.put("../bucket", "kyc/a", b"x")
    st.put("kyc-clean", "kyc/abc/def", b"cifrado")
    path = tmp_path / "kyc-clean" / "kyc" / "abc" / "def"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and st.get("kyc-clean", "kyc/abc/def") == b"cifrado"


def test_s3_exige_kms_y_cifra_cada_escritura():
    import boto3
    from botocore.stub import Stubber

    client = boto3.client("s3", region_name="mx-central-1", aws_access_key_id="x", aws_secret_access_key="y")
    with pytest.raises(StorageError):
        S3ObjectStorage(client, "")
    st = S3ObjectStorage(client, "arn:aws:kms:mx-central-1:111:key/abc")
    with Stubber(client) as stub:
        stub.add_response("put_object", {}, {
            "Bucket": "kyc-clean", "Key": "kyc/p/f", "Body": b"cifrado",
            "ServerSideEncryption": "aws:kms", "SSEKMSKeyId": "arn:aws:kms:mx-central-1:111:key/abc",
            "BucketKeyEnabled": True, "ContentType": "application/octet-stream", "ChecksumAlgorithm": "SHA256",
        })
        st.put("kyc-clean", "kyc/p/f", b"cifrado")
        stub.add_client_error("head_object", service_error_code="404", http_status_code=404)
        assert st.exists("kyc-clean", "kyc/p/otro") is False
        stub.add_client_error("head_object", service_error_code="403", http_status_code=403)
        with pytest.raises(StorageError):                 # sin permiso NO es "no existe"
            st.exists("kyc-clean", "kyc/p/otro")
        stub.assert_no_pending_responses()
    with pytest.raises(StorageError):
        st.put("kyc-clean", "../../x", b"x")


def test_la_api_no_sirve_el_directorio_de_almacenamiento(client, db, ine_doc):
    _, _, f = ine_doc
    for path in (f"/{f.bucket}/{f.object_key}", f"/static/{f.object_key}", "/var/storage",
                 f"/api/v1/storage/{f.bucket}/{f.object_key}"):
        assert client.get(path).status_code == 404


def test_datos_bancarios_solo_como_referencia_del_proveedor():
    """Anexo §14: no existe tabla de cuentas bancarias cifradas; Stripe custodia la CLABE."""
    insp = inspect(engine)
    tables = set(insp.get_table_names())
    assert "encrypted_bank_accounts" not in tables and "bank_accounts" not in tables
    for t in tables:
        for c in insp.get_columns(t):
            assert not any(w in c["name"] for w in ("clabe", "card", "cvv", "iban")), f"{t}.{c['name']}"

