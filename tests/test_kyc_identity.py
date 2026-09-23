"""Identidad cifrada del expediente contra PostgreSQL real."""
from datetime import date

import pytest
from sqlalchemy import select, text

from app.core.actor import Actor
from app.core.crypto import CryptoError
from app.kyc import identity
from app.kyc.validators import IdentityValidationError
from app.models import ActorType, AuditLog, KycProfile, KycStatus, KycStatusHistory, User
from tests.conftest import BIRTH, drive_to, get_profile, register, valid_curp, valid_rfc


@pytest.fixture
def tech(client, category, db):
    register(client, "technician", "tec@example.com", category_ids=[category.id])
    uid = db.scalar(select(User.id).where(User.email == "tec@example.com"))
    return uid, Actor(user_id=uid, actor_type=ActorType.TECHNICIAN)


def _set(db, profile, actor, curp=None, rfc=None, birth=BIRTH):
    identity.set_identity(db, profile, actor, first_names="Gloria", paternal_surname="Hernández",
                          maternal_surname=None, birth_date=birth,
                          curp=curp or valid_curp(), rfc=rfc or valid_rfc())


def test_registro_crea_expediente_con_llave_propia(tech, db):
    uid, _ = tech
    p = get_profile(db, uid)
    assert p.status == KycStatus.NOT_STARTED and p.data_key_enc
    hist = db.scalar(select(KycStatusHistory).where(KycStatusHistory.kyc_profile_id == p.id))
    assert hist.from_status is None and hist.to_status == KycStatus.NOT_STARTED
    assert db.scalar(select(AuditLog.action).where(AuditLog.kyc_profile_id == p.id)) == "kyc.profile.created"


def test_curp_y_rfc_se_guardan_cifrados_y_se_leen(tech, db):
    uid, actor = tech
    p = get_profile(db, uid)
    _set(db, p, actor)
    db.commit()
    raw = db.execute(text("SELECT curp_enc, rfc_enc, curp_hash FROM kyc_profiles WHERE id = :id"),
                     {"id": p.id}).one()
    assert valid_curp().encode() not in raw.curp_enc and valid_rfc().encode() not in raw.rfc_enc
    assert len(raw.curp_hash) == 64
    assert identity.read_identifiers(p) == (valid_curp(), valid_rfc())


def test_auditoria_solo_guarda_identificadores_enmascarados(tech, db):
    uid, actor = tech
    p = get_profile(db, uid)
    _set(db, p, actor)
    db.commit()
    entry = db.scalar(select(AuditLog).where(AuditLog.action == "kyc.identity.updated"))
    dump = str(entry.changes)
    assert valid_curp() not in dump and valid_rfc() not in dump
    assert entry.changes["curp_masked"].startswith("HEGG") and "•" in entry.changes["curp_masked"]


def test_curp_duplicada_en_otro_expediente_se_bloquea_sin_revelarlo(tech, client, category, db):
    uid, actor = tech
    _set(db, get_profile(db, uid), actor)
    db.commit()
    register(client, "technician", "impostor@example.com", category_ids=[category.id])
    uid2 = db.scalar(select(User.id).where(User.email == "impostor@example.com"))
    with pytest.raises(identity.DuplicateIdentity) as exc:
        _set(db, get_profile(db, uid2), Actor(user_id=uid2, actor_type=ActorType.TECHNICIAN), rfc=valid_rfc(7))
    assert "CURP" not in str(exc.value)                      # mensaje genérico
    db.commit()                                              # la auditoría del intento sí se guarda
    assert db.scalar(select(AuditLog).where(AuditLog.action == "kyc.identity.duplicate_detected"))


def test_rfc_duplicado_tambien_se_bloquea(tech, client, category, db):
    uid, actor = tech
    _set(db, get_profile(db, uid), actor)
    db.commit()
    register(client, "technician", "otro@example.com", category_ids=[category.id])
    uid2 = db.scalar(select(User.id).where(User.email == "otro@example.com"))
    with pytest.raises(identity.DuplicateIdentity):
        _set(db, get_profile(db, uid2), Actor(user_id=uid2, actor_type=ActorType.TECHNICIAN), curp=valid_curp(5))


def test_datos_inconsistentes_se_rechazan(tech, db):
    uid, actor = tech
    p = get_profile(db, uid)
    with pytest.raises(IdentityValidationError) as exc:
        _set(db, p, actor, birth=date(1956, 4, 28))
    assert exc.value.code == "CURP_BIRTHDATE_MISMATCH"


def test_menor_de_edad_se_rechaza(tech, db):
    from app.kyc.validators import _curp_check_digit, _rfc_check_digit
    uid, actor = tech
    curp17 = "HEGG100427MVZRRLA"
    rfc12 = "HEGG100427A1"
    with pytest.raises(IdentityValidationError) as exc:
        _set(db, get_profile(db, uid), actor, curp=curp17 + _curp_check_digit(curp17),
             rfc=rfc12 + _rfc_check_digit(rfc12), birth=date(2010, 4, 27))
    assert exc.value.code == "UNDERAGE"


def test_solo_el_titular_captura_su_identidad(tech, reviewer, db):
    uid, _ = tech
    with pytest.raises(PermissionError):
        _set(db, get_profile(db, uid), Actor.from_user(reviewer))


def test_identidad_no_editable_en_revision(tech, reviewer, supervisor, db):
    uid, actor = tech
    p = drive_to(db, uid, KycStatus.SUBMITTED, reviewer, supervisor)
    with pytest.raises(identity.NotEditable):
        _set(db, p, actor)


def test_borrado_criptografico_hace_ilegible_la_identidad(tech, supervisor, db):
    uid, actor = tech
    p = get_profile(db, uid)
    _set(db, p, actor)
    identity.crypto_shred(db, p, Actor.from_user(supervisor))
    db.commit()
    assert p.anonymized_at is not None
    with pytest.raises(CryptoError):
        identity.read_identifiers(db.get(KycProfile, p.id))


def test_retencion_legal_impide_borrado(tech, supervisor, db):
    uid, actor = tech
    p = get_profile(db, uid)
    p.legal_hold = True
    with pytest.raises(PermissionError):
        identity.crypto_shred(db, p, Actor.from_user(supervisor))
