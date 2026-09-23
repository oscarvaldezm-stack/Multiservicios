"""
Calificaciones verificadas y antifraude (anexo, sección 17): solo con orden COMPLETADA y PAGADA,
una por orden, sin manipulación desde la API ni desde la base, con edición limitada, reportes,
moderación auditada y reputación resistente a manipulación.
"""
import uuid
from decimal import Decimal

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.models import (
    AdminRole,
    AuditLog,
    Review,
    ReviewAuditLog,
    ReviewStatus,
    TechnicianReputation,
)
from app.reviews import reputation
from tests.conftest import API, auth, login, make_admin
from tests.marketplace import (
    ORDERS,
    REVIEWS,
    approved_tech,
    new_client,
    order_status,
    run_order,
    webhook,
)


@pytest.fixture
def people(client, db, category, reviewer, supervisor):
    tid, th = approved_tech(client, db, category, reviewer, supervisor)
    cid, ch = new_client(client, db)
    return tid, th, cid, ch


@pytest.fixture
def ready(client, db, category, people):
    """Orden COMPLETADA y PAGADA (READY_FOR_REVIEW)."""
    tid, th, cid, ch = people
    return run_order(client, db, ch, th, category), people


def review(client, h, oid, rating=5, **kw):
    return client.post(REVIEWS, headers=h, json={"service_order_id": str(oid), "rating": rating, **kw})


def err(r) -> str:
    return r.json()["detail"]["code"]


def admin_h(client, db, email, *roles):
    make_admin(db, email, *roles)
    return auth(login(client, email).json()["access_token"])


def db_review(db, rid) -> Review:
    db.expire_all()
    return db.get(Review, uuid.UUID(str(rid)))


# =============================================================================
# Caso correcto
# =============================================================================
def test_orden_completada_y_pagada_permite_calificar(client, db, ready):
    oid, (tid, th, cid, ch) = ready
    elig = client.get(f"{ORDERS}/{oid}/review-eligibility", headers=ch).json()
    assert elig["can_review"] is True and elig["review_deadline"]
    r = review(client, ch, oid, 5, comment="Excelente trabajo, muy limpio",
               ratings={"QUALITY": 5, "PUNCTUALITY": 4})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["verification"] == "VERIFIED_SERVICE" and body["status"] == "PUBLISHED"
    assert body["ratings"] == {"PUNCTUALITY": 4, "QUALITY": 5} and body["can_edit"] is True
    assert order_status(db, oid) == "REVIEWED"
    rev = db_review(db, body["id"])
    assert rev.technician_id == tid and rev.client_id == cid
    logs = db.scalars(select(ReviewAuditLog).where(ReviewAuditLog.review_id == rev.id)).all()
    assert [log.action for log in logs] == ["CREATED"]
    rep = db.get(TechnicianReputation, tid)
    assert rep.verified_reviews == 1 and rep.completed_jobs == 1 and rep.rating_avg == Decimal("5.00")


# =============================================================================
# Casos bloqueados por estado de orden o pago
# =============================================================================
@pytest.mark.parametrize("until,code", [
    ("ACCEPTED", "REVIEW_ORDER_NOT_COMPLETED"),
    ("IN_PROGRESS", "REVIEW_ORDER_NOT_COMPLETED"),
    ("AWAITING_APPROVAL", "REVIEW_ORDER_NOT_COMPLETED"),
    ("COMPLETED", "REVIEW_PAYMENT_NOT_CONFIRMED"),         # servicio aceptado, pago aún no confirmado
])
def test_sin_servicio_completado_y_pagado_no_se_califica(until, code, client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until=until)
    r = review(client, ch, oid)
    assert r.status_code == 409 and err(r) == code
    assert db.scalar(select(Review)) is None


def test_orden_cancelada_no_se_califica(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="AUTHORIZED")
    client.post(f"{ORDERS}/{oid}/cancel", headers=ch, json={})
    assert err(review(client, ch, oid)) == "REVIEW_ORDER_NOT_REVIEWABLE"


def test_orden_sin_tecnico_no_se_califica(client, db, category, people):
    _, _, _, ch = people
    from tests.marketplace import create_order
    oid = create_order(client, ch, category)["id"]
    assert err(review(client, ch, oid)) == "REVIEW_NO_TECHNICIAN"


def test_pago_fallido_no_se_califica(client, db, category, people):
    _, th, _, ch = people
    oid = run_order(client, db, ch, th, category, until="COMPLETED")
    webhook(db, oid, "failed")
    assert order_status(db, oid) == "FAILED"
    assert err(review(client, ch, oid)) == "REVIEW_ORDER_NOT_REVIEWABLE"


def test_disputa_activa_bloquea_la_calificacion(client, db, ready):
    oid, (_, _, _, ch) = ready
    client.post(f"{ORDERS}/{oid}/dispute", headers=ch, json={"reason": "Dejó una fuga nueva en la cocina"})
    assert err(review(client, ch, oid)) == "REVIEW_ORDER_DISPUTED"


def test_reembolso_total_bloquea_y_oculta_la_resena_existente(client, db, ready):
    oid, (tid, _, _, ch) = ready
    rid = review(client, ch, oid, 1, comment="Nunca terminó el trabajo").json()["id"]
    from tests.marketplace import payment_of
    webhook(db, oid, "refunded", amount=payment_of(db, oid).captured_cents)
    assert order_status(db, oid) == "REFUNDED"
    assert db_review(db, rid).status == ReviewStatus.HIDDEN
    assert db.get(TechnicianReputation, tid).verified_reviews == 0


def test_reembolso_parcial_mantiene_la_calificacion(client, db, ready):
    oid, (_, _, _, ch) = ready
    webhook(db, oid, "refunded", amount=Decimal("100.00"))
    assert order_status(db, oid) == "READY_FOR_REVIEW"
    assert review(client, ch, oid, 3).status_code == 201


def test_plazo_para_calificar(client, db, ready):
    oid, (_, _, _, ch) = ready
    db.execute(text("UPDATE service_orders SET paid_at = now() - interval '31 days' WHERE id = :id"), {"id": oid})
    db.commit()
    assert err(review(client, ch, oid)) == "REVIEW_WINDOW_CLOSED"


def test_correo_sin_verificar_no_califica(client, db, category, reviewer, supervisor):
    _, th = approved_tech(client, db, category, reviewer, supervisor)
    _, ch = new_client(client, db, verified=False)
    oid = run_order(client, db, ch, th, category)
    r = review(client, ch, oid)
    assert r.status_code == 403 and err(r) == "EMAIL_NOT_VERIFIED"


# =============================================================================
# Propiedad, roles y duplicados
# =============================================================================
def test_cliente_no_califica_orden_ajena(client, db, ready):
    oid, _ = ready
    _, ch2 = new_client(client, db, "otro@example.com")
    r = review(client, ch2, oid)
    assert r.status_code == 404 and err(r) == "ORDER_NOT_FOUND"
    assert client.get(f"{ORDERS}/{oid}/review-eligibility", headers=ch2).status_code == 404


def test_orden_inexistente_da_el_mismo_404(client, db, people):
    _, _, _, ch = people
    assert err(review(client, ch, uuid.uuid4())) == "ORDER_NOT_FOUND"


def test_usuario_no_autenticado(client, db, ready):
    oid, _ = ready
    assert review(client, {}, oid).status_code == 401


def test_tecnico_no_puede_calificar_ni_autocalificarse(client, db, ready, admin_tokens):
    oid, (_, th, _, _) = ready
    assert review(client, th, oid).status_code == 403
    assert review(client, auth(admin_tokens["access_token"]), oid).status_code == 403


def test_segunda_calificacion_de_la_misma_orden(client, db, ready):
    oid, (_, _, _, ch) = ready
    assert review(client, ch, oid).status_code == 201
    r = review(client, ch, oid, 1)
    assert r.status_code == 409 and err(r) == "REVIEW_ALREADY_EXISTS"
    assert r.json()["detail"]["message"] == "Esta orden ya tiene una calificación registrada"
    assert db.scalar(select(text("count(*)")).select_from(Review)) == 1


# =============================================================================
# Manipulación desde la API
# =============================================================================
@pytest.mark.parametrize("extra", [
    {"verification": "VERIFIED_SERVICE"}, {"status": "PUBLISHED"}, {"weight": 1}, {"technician_id": str(uuid.uuid4())},
    {"client_id": str(uuid.uuid4())}, {"created_at": "2020-01-01T00:00:00Z"},
])
def test_campos_del_servidor_no_se_aceptan(extra, client, db, ready):
    oid, (_, _, _, ch) = ready
    assert review(client, ch, oid, **extra).status_code == 422


@pytest.mark.parametrize("payload", [
    {"rating": 0}, {"rating": 6}, {"rating": "5"}, {"rating": 4.5},
    {"rating": 5, "ratings": {"QUALITY": 9}}, {"rating": 5, "ratings": {"PRICE": 5}},
    {"rating": 5, "comment": "x" * 1001},
])
def test_valores_invalidos(payload, client, db, ready):
    oid, (_, _, _, ch) = ready
    r = client.post(REVIEWS, headers=ch, json={"service_order_id": oid, **payload})
    assert r.status_code == 422


@pytest.mark.parametrize("comment,code", [
    ("<script>alert(1)</script>", "CONTENT_MARKUP_NOT_ALLOWED"),
    ("Buen trabajo <b>genial</b>", "CONTENT_MARKUP_NOT_ALLOWED"),
    ("Llámame al 229 123 4567", "CONTENT_CONTACT_NOT_ALLOWED"),
    ("Escríbeme a pedro@example.com", "CONTENT_CONTACT_NOT_ALLOWED"),
    ("Visita www.otraplataforma.com", "CONTENT_CONTACT_NOT_ALLOWED"),
])
def test_comentarios_saneados(comment, code, client, db, ready):
    oid, (_, _, _, ch) = ready
    r = review(client, ch, oid, comment=comment)
    assert r.status_code == 422 and err(r) == code


def test_lenguaje_ofensivo_se_retiene_para_moderacion(client, db, ready):
    oid, (tid, _, _, ch) = ready
    r = review(client, ch, oid, 1, comment="Es un p3ndej0, no sabe nada")
    assert r.status_code == 201 and r.json()["status"] == "PENDING_MODERATION"
    assert db.get(TechnicianReputation, tid).verified_reviews == 0
    public = client.get(f"{API}/technicians/{tid}/reviews", headers=ch).json()
    assert public["items"] == []


def test_caracteres_de_control_se_eliminan(client, db, ready):
    oid, (_, _, _, ch) = ready
    r = review(client, ch, oid, comment="Muy​ bien‮ hecho")
    assert r.status_code == 201 and r.json()["comment"] == "Muy bien hecho"


# =============================================================================
# Manipulación directa en la base de datos
# =============================================================================
def _sql_fails(db, sql, params, fragment):
    with pytest.raises(DBAPIError) as exc:
        db.execute(text(sql), params)
        db.flush()
    db.rollback()
    assert fragment in str(exc.value.orig)


def test_base_rechaza_resena_sin_orden_valida(client, db, category, people):
    tid, th, cid, ch = people
    oid = run_order(client, db, ch, th, category, until="COMPLETED")
    sql = ("INSERT INTO reviews (id, service_order_id, client_id, technician_id, rating, editable_until, integrity_mac) "
           "VALUES (:id, :o, :c, :t, 5, now() + interval '1 day', 'x')")
    _sql_fails(db, sql, {"id": uuid.uuid4(), "o": oid, "c": cid, "t": tid}, "REVIEW_NOT_ELIGIBLE")


def test_base_rechaza_resena_de_otro_cliente_o_tecnico(client, db, ready):
    oid, (tid, _, cid, _) = ready
    sql = ("INSERT INTO reviews (id, service_order_id, client_id, technician_id, rating, editable_until, integrity_mac) "
           "VALUES (:id, :o, :c, :t, 5, now() + interval '1 day', 'x')")
    _sql_fails(db, sql, {"id": uuid.uuid4(), "o": oid, "c": tid, "t": cid}, "REVIEW_ORDER_MISMATCH")


def test_base_rechaza_verificacion_distinta(client, db, ready):
    oid, (_, _, _, ch) = ready
    rid = review(client, ch, oid).json()["id"]
    _sql_fails(db, "UPDATE reviews SET verification = 'MANUAL' WHERE id = :id", {"id": rid}, "REVIEW_IMMUTABLE")


def test_estrellas_no_se_cambian_por_sql(client, db, ready):
    oid, (_, _, _, ch) = ready
    rid = review(client, ch, oid, 2).json()["id"]
    # Aun dentro del periodo de edición: sin pasar por la aplicación (que cuenta la edición) no se puede.
    _sql_fails(db, "UPDATE reviews SET rating = 5 WHERE id = :id", {"id": rid}, "REVIEW_IMMUTABLE")
    db.execute(text("UPDATE reviews SET editable_until = editable_until"), {})  # sin cambios: permitido
    db.rollback()
    _sql_fails(db, "UPDATE reviews SET editable_until = now() + interval '30 days' WHERE id = :id", {"id": rid},
               "REVIEW_IMMUTABLE")
    _sql_fails(db, "UPDATE reviews SET client_id = technician_id WHERE id = :id", {"id": rid}, "REVIEW_IMMUTABLE")
    _sql_fails(db, "DELETE FROM reviews WHERE id = :id", {"id": rid}, "APPEND_ONLY")
    _sql_fails(db, "DELETE FROM review_audit_logs WHERE review_id = :id", {"id": rid}, "APPEND_ONLY")


def test_firma_detecta_alteraciones_que_si_permite_la_base(client, db, ready):
    oid, (_, _, _, ch) = ready
    rid = review(client, ch, oid, 2).json()["id"]
    mod = admin_h(client, db, "mod@example.com", AdminRole.CONTENT_MODERATOR)
    assert client.get(f"{API}/admin/reviews/integrity", headers=mod).json()["tampered_ids"] == []
    db.execute(text("UPDATE reviews SET weight = 0.25 WHERE id = :id"), {"id": rid})   # "bajarle peso" a escondidas
    db.commit()
    res = client.get(f"{API}/admin/reviews/integrity", headers=mod).json()
    assert res["tampered_ids"] == [rid]
    assert client.get(f"{API}/admin/reviews/{rid}", headers=mod).json()["integrity_ok"] is False


# =============================================================================
# Edición
# =============================================================================
def test_editar_dentro_del_plazo_guarda_valor_anterior_y_nuevo(client, db, ready):
    oid, (tid, _, cid, ch) = ready
    rid = review(client, ch, oid, 3, comment="Regular").json()["id"]
    r = client.put(f"{REVIEWS}/{rid}", headers=ch, json={"rating": 4, "comment": "Volvió a revisar, bien",
                                                         "reason": "Regresó a corregir"})
    assert r.status_code == 200 and r.json()["rating"] == 4 and r.json()["edits_left"] == 2
    log = db.scalar(select(ReviewAuditLog).where(ReviewAuditLog.review_id == uuid.UUID(rid),
                                                 ReviewAuditLog.action == "EDITED"))
    assert log.old_values["rating"] == 3 and log.new_values["rating"] == 4
    assert log.actor_id == cid and log.reason == "Regresó a corregir" and log.created_at
    assert db.get(TechnicianReputation, tid).rating_avg == Decimal("4.00")


def test_editar_exige_motivo_y_algo_que_cambiar(client, db, ready):
    oid, (_, _, _, ch) = ready
    rid = review(client, ch, oid, 3).json()["id"]
    assert client.put(f"{REVIEWS}/{rid}", headers=ch, json={"rating": 4}).status_code == 422
    assert client.put(f"{REVIEWS}/{rid}", headers=ch, json={"reason": "nada"}).status_code == 422


def test_despues_de_24_horas_queda_bloqueada(client, db, ready):
    oid, (_, _, _, ch) = ready
    rid = review(client, ch, oid, 3).json()["id"]
    # Simula el paso del tiempo (solo posible saltándose el trigger en la prueba).
    db.execute(text("ALTER TABLE reviews DISABLE TRIGGER trg_reviews_immutable"))
    db.execute(text("UPDATE reviews SET editable_until = now() - interval '1 minute' WHERE id = :id"), {"id": rid})
    db.execute(text("ALTER TABLE reviews ENABLE TRIGGER trg_reviews_immutable"))
    db.commit()
    r = client.put(f"{REVIEWS}/{rid}", headers=ch, json={"rating": 5, "reason": "Cambio de opinión"})
    assert r.status_code == 409 and err(r) == "REVIEW_EDIT_WINDOW_CLOSED"
    _sql_fails(db, "UPDATE reviews SET rating = 5, edit_count = edit_count + 1 WHERE id = :id", {"id": rid},
               "REVIEW_IMMUTABLE")


def test_limite_de_ediciones(client, db, ready):
    oid, (_, _, _, ch) = ready
    rid = review(client, ch, oid, 3).json()["id"]
    for n in (4, 5, 4):
        assert client.put(f"{REVIEWS}/{rid}", headers=ch, json={"rating": n, "reason": "Ajuste"}).status_code == 200
    r = client.put(f"{REVIEWS}/{rid}", headers=ch, json={"rating": 5, "reason": "Ajuste"})
    assert err(r) == "REVIEW_EDIT_LIMIT"


def test_solo_el_autor_edita(client, db, ready):
    oid, (_, th, _, ch) = ready
    rid = review(client, ch, oid, 3).json()["id"]
    _, ch2 = new_client(client, db, "otro@example.com")
    assert client.put(f"{REVIEWS}/{rid}", headers=ch2, json={"rating": 5, "reason": "x" * 5}).status_code == 404
    assert client.put(f"{REVIEWS}/{rid}", headers=th, json={"rating": 5, "reason": "x" * 5}).status_code == 403


# =============================================================================
# Respuesta del técnico
# =============================================================================
def test_tecnico_responde_una_vez_y_no_modifica_la_calificacion(client, db, ready, category, reviewer, supervisor):
    oid, (_, th, _, ch) = ready
    rid = review(client, ch, oid, 2, comment="Llegó tarde").json()["id"]
    r = client.post(f"{REVIEWS}/{rid}/reply", headers=th, json={"reply": "Una disculpa, hubo tráfico"})
    assert r.status_code == 200 and r.json()["technician_reply"] == "Una disculpa, hubo tráfico"
    assert r.json()["rating"] == 2
    again = client.post(f"{REVIEWS}/{rid}/reply", headers=th, json={"reply": "Otra respuesta"})
    assert err(again) == "REVIEW_ALREADY_REPLIED"
    _, th2 = approved_tech(client, db, category, reviewer, supervisor, "tec2@example.com", n=5)
    assert client.post(f"{REVIEWS}/{rid}/reply", headers=th2, json={"reply": "Hola"}).status_code == 404
    assert client.post(f"{REVIEWS}/{rid}/reply", headers=ch, json={"reply": "Hola"}).status_code == 403
    assert client.put(f"{REVIEWS}/{rid}", headers=th, json={"rating": 5, "reason": "Quiero"}).status_code == 403


# =============================================================================
# Reportes y moderación
# =============================================================================
def test_reportar_resena(client, db, ready):
    oid, (_, th, _, ch) = ready
    rid = review(client, ch, oid, 1, comment="Pésimo servicio").json()["id"]
    r = client.post(f"{REVIEWS}/{rid}/report", headers=th, json={"reason": "FALSE", "note": "Nunca dije eso"})
    assert r.status_code == 201 and r.json()["status"] == "OPEN"
    assert err(client.post(f"{REVIEWS}/{rid}/report", headers=th, json={"reason": "FALSE"})) == "REPORT_ALREADY_EXISTS"
    # El autor no reporta su propia reseña.
    assert client.post(f"{REVIEWS}/{rid}/report", headers=ch, json={"reason": "SPAM"}).status_code == 404
    assert client.post(f"{REVIEWS}/{rid}/report", headers=th, json={"reason": "INVENTADO"}).status_code == 422


def _credible_reporters(client, db, category, th, n=3):
    """Clientes con antigüedad y un servicio pagado (los únicos cuyos reportes ocultan)."""
    heads = []
    for i in range(n):
        _, h = new_client(client, db, f"reporta{i}@example.com")
        run_order(client, db, h, th, category)
        heads.append(h)
    return heads


def test_cuentas_recien_creadas_no_ocultan_resenas_ajenas(client, db, ready):
    oid, (_, _, _, ch) = ready
    rid = review(client, ch, oid, 5).json()["id"]
    for i in range(4):
        _, h = new_client(client, db, f"bot{i}@example.com", age_days=0)
        assert client.post(f"{REVIEWS}/{rid}/report", headers=h, json={"reason": "FALSE"}).status_code == 201
    assert db_review(db, rid).status == ReviewStatus.PUBLISHED        # quedan en la cola, no ocultan


def test_varios_clientes_reportan_y_se_oculta_temporalmente(client, db, category, ready):
    oid, (tid, th, _, ch) = ready
    rid = review(client, ch, oid, 5).json()["id"]
    for h in _credible_reporters(client, db, category, th):
        assert client.post(f"{REVIEWS}/{rid}/report", headers=h, json={"reason": "SPAM"}).status_code == 201
    rev = db_review(db, rid)
    assert rev.status == ReviewStatus.HIDDEN and rev.moderation_reason == "AUTO_HIDDEN_REPORTS"
    assert client.get(f"{API}/technicians/{tid}/reviews", headers=ch).json()["items"] == []

    # Soporte no puede "mantenerla" (sería republicarla); el moderador sí.
    sup = admin_h(client, db, "soporte@example.com", AdminRole.SUPPORT)
    mod = admin_h(client, db, "mod@example.com", AdminRole.CONTENT_MODERATOR)
    detail = client.get(f"{API}/admin/reviews/{rid}", headers=mod).json()
    first = detail["reports"][0]["id"]
    assert client.post(f"{API}/admin/review-reports/{first}/resolution", headers=sup,
                       json={"resolution": "KEEP", "note": "Parece legítima"}).status_code == 403
    for rep in detail["reports"]:
        r = client.post(f"{API}/admin/review-reports/{rep['id']}/resolution", headers=mod,
                        json={"resolution": "KEEP", "note": "Reseña legítima"})
        assert r.status_code == 200
    assert db_review(db, rid).status == ReviewStatus.PUBLISHED


def test_soporte_oculta_pero_solo_moderacion_elimina_y_queda_auditado(client, db, ready):
    oid, (tid, _, _, ch) = ready
    rid = review(client, ch, oid, 5, comment="Muy bien").json()["id"]
    sup = admin_h(client, db, "soporte@example.com", AdminRole.SUPPORT)
    url = f"{API}/admin/reviews/{rid}/moderation"
    no_note = client.post(url, headers=sup, json={"action": "HIDE", "reason": "FAKE_REVIEW"})
    assert err(no_note) == "MODERATION_NOTE_REQUIRED"
    r = client.post(url, headers=sup, json={"action": "HIDE", "reason": "FAKE_REVIEW", "note": "Cuenta vinculada"})
    assert r.status_code == 200 and r.json()["status"] == "HIDDEN"
    assert client.post(url, headers=sup, json={"action": "REMOVE", "reason": "FAKE_REVIEW",
                                               "note": "x"}).status_code == 403

    mod = admin_h(client, db, "mod@example.com", AdminRole.CONTENT_MODERATOR)
    r = client.post(url, headers=mod, json={"action": "REMOVE", "reason": "FAKE_REVIEW",
                                            "note": "El cliente es familiar del técnico"})
    assert r.status_code == 200 and r.json()["status"] == "REMOVED"
    assert db.scalar(select(Review).where(Review.id == uuid.UUID(rid))) is not None     # nunca se borra
    audit = db.scalar(select(AuditLog).where(AuditLog.action == "review.moderated.removed"))
    assert audit.reason_code == "FAKE_REVIEW" and audit.reason_note == "El cliente es familiar del técnico"
    history = [h["action"] for h in r.json()["history"]]
    assert history[-2:] == ["MODERATED_HIDDEN", "MODERATED_REMOVED"]
    rep = db.get(TechnicianReputation, tid)
    assert rep.verified_reviews == 0 and rep.fraud_strikes == 1
    again = client.post(url, headers=mod, json={"action": "PUBLISH", "reason": "VERIFIED_OK"})
    assert err(again) == "REVIEW_ALREADY_REMOVED"


@pytest.mark.parametrize("role", [AdminRole.KYC_REVIEWER, AdminRole.FINANCE_ADMIN])
def test_roles_sin_permiso_no_moderan(role, client, db, ready):
    oid, (_, _, _, ch) = ready
    rid = review(client, ch, oid).json()["id"]
    h = admin_h(client, db, "x@example.com", role)
    assert client.get(f"{API}/admin/reviews", headers=h).status_code == 403
    assert client.post(f"{API}/admin/reviews/{rid}/moderation", headers=h,
                       json={"action": "HIDE", "reason": "SPAM", "note": "x"}).status_code == 403


def test_tecnico_y_cliente_no_entran_al_panel(client, db, ready):
    oid, (_, th, _, ch) = ready
    rid = review(client, ch, oid).json()["id"]
    for h in (th, ch):
        assert client.post(f"{API}/admin/reviews/{rid}/moderation", headers=h,
                           json={"action": "HIDE", "reason": "SPAM", "note": "x"}).status_code == 403


# =============================================================================
# Antifraude
# =============================================================================
def test_cuenta_cliente_del_propio_tecnico_se_retiene(client, db, category, reviewer, supervisor):
    """El técnico crea una cuenta cliente en su mismo teléfono y se contrata a sí mismo."""
    tid, th = approved_tech(client, db, category, reviewer, supervisor, device="telefono-del-tecnico-01")
    _, fake = new_client(client, db, "falso@example.com", device="telefono-del-tecnico-01")
    oid = run_order(client, db, fake, th, category)
    r = review(client, fake, oid, 5, comment="El mejor técnico del mundo")
    assert r.status_code == 201 and r.json()["status"] == "PENDING_MODERATION"
    rev = db_review(db, r.json()["id"])
    assert "SHARED_DEVICE_WITH_TECHNICIAN" in rev.risk_flags and rev.weight == 0
    assert "risk_flags" not in r.json()                            # las señales nunca se muestran al cliente
    assert db.get(TechnicianReputation, tid).verified_reviews == 0


def test_misma_tarjeta_en_varias_cuentas_se_retiene(client, db, category, people):
    tid, th, _, ch = people
    oid1 = run_order(client, db, ch, th, category, fingerprint="fp_tarjeta_1")
    assert review(client, ch, oid1, 5).json()["status"] == "PUBLISHED"
    _, ch2 = new_client(client, db, "segunda@example.com")
    oid2 = run_order(client, db, ch2, th, category, fingerprint="fp_tarjeta_1")
    r = review(client, ch2, oid2, 5)
    assert r.json()["status"] == "PENDING_MODERATION"
    assert "SAME_PAYMENT_METHOD_OTHER_CLIENT" in db_review(db, r.json()["id"]).risk_flags


def test_cuenta_nueva_y_orden_barata_pesan_menos(client, db, category, reviewer, supervisor):
    tid, th = approved_tech(client, db, category, reviewer, supervisor)
    _, ch = new_client(client, db, age_days=0)
    oid = run_order(client, db, ch, th, category, price="100.00")
    rev = db_review(db, review(client, ch, oid, 5).json()["id"])
    assert rev.status == ReviewStatus.PUBLISHED and rev.weight == Decimal("0.25")
    assert set(rev.risk_flags) >= {"NEW_CLIENT_ACCOUNT", "LOW_VALUE_ORDER"}


def test_limite_diario_de_calificaciones(client, db, ready, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "REVIEW_MAX_PER_DAY", 0)
    oid, (_, _, _, ch) = ready
    r = review(client, ch, oid)
    assert r.status_code == 429 and err(r) == "REVIEW_RATE_LIMITED"


# =============================================================================
# Reputación y consulta pública
# =============================================================================
def test_una_sola_resena_perfecta_no_da_cinco_estrellas_de_reputacion(client, db, ready):
    oid, (tid, _, _, ch) = ready
    review(client, ch, oid, 5)
    rep = db.get(TechnicianReputation, tid)
    assert rep.rating_avg == Decimal("5.00")                       # lo que ve el cliente
    assert Decimal("4.0") < rep.bayes_rating < Decimal("4.3")      # lo que usa el ranking
    assert 0 < rep.reputation_score < 100


def test_muchas_ordenes_del_mismo_cliente_no_inflan_la_reputacion(client, db, category, people):
    tid, th, _, ch = people
    for _ in range(4):
        oid = run_order(client, db, ch, th, category)
        review(client, ch, oid, 5)
    rep = db.get(TechnicianReputation, tid)
    one_client = rep.bayes_rating
    assert rep.verified_reviews == 4
    # Cuatro clientes distintos con la misma calificación pesan más que uno repetido cuatro veces.
    assert one_client == pytest.approx(Decimal((5 * 4.0 + 5) / 6), abs=Decimal("0.002"))


def test_consulta_publica_solo_muestra_publicadas_sin_datos_personales(client, db, ready, category):
    oid, (tid, th, cid, ch) = ready
    review(client, ch, oid, 4, comment="Buen trabajo", ratings={"CLEANLINESS": 5})
    body = client.get(f"{API}/technicians/{tid}/reviews", headers=ch).json()
    item = body["items"][0]
    assert item["client_display"] == "Usuario P." and item["verification"] == "VERIFIED_SERVICE"
    assert "client_id" not in item and "risk_flags" not in item and "weight" not in item
    assert body["summary"]["verified_reviews"] == 1 and body["summary"]["completed_jobs"] == 1
    assert body["summary"]["category_avgs"]["CLEANLINESS"] == 5.0
    assert client.get(f"{API}/technicians/{cid}/reviews", headers=ch).status_code == 404
    assert client.get(f"{API}/technicians/{tid}/reviews").status_code == 401


def test_paginacion_por_cursor(client, db, category, people):
    tid, th, _, ch = people
    for i in range(3):
        _, h = new_client(client, db, f"c{i}@example.com")
        review(client, h, run_order(client, db, h, th, category), 5)
    first = client.get(f"{API}/technicians/{tid}/reviews", headers=ch, params={"limit": 2}).json()
    assert len(first["items"]) == 2 and first["next_cursor"]
    second = client.get(f"{API}/technicians/{tid}/reviews", headers=ch,
                        params={"limit": 2, "cursor": first["next_cursor"]}).json()
    assert len(second["items"]) == 1 and second["next_cursor"] is None
    assert client.get(f"{API}/technicians/{tid}/reviews", headers=ch,
                      params={"cursor": "basura!!"}).status_code == 422


def test_mis_resenas_cliente_y_tecnico(client, db, ready):
    oid, (tid, th, _, ch) = ready
    review(client, ch, oid, 4)
    assert len(client.get(f"{API}/clients/me/reviews", headers=ch).json()) == 1
    mine = client.get(f"{API}/technicians/me/reviews", headers=th).json()
    assert mine["technician_id"] == str(tid) and len(mine["items"]) == 1


def test_recalculo_es_idempotente(client, db, ready):
    oid, (tid, _, _, ch) = ready
    review(client, ch, oid, 4)
    a = reputation.recompute(db, tid)
    b = reputation.recompute(db, tid)
    assert (a.bayes_rating, a.reputation_score) == (b.bayes_rating, b.reputation_score)




# =============================================================================
# Regresiones de la revisión independiente
# =============================================================================
def test_resena_de_orden_reembolsada_no_se_republica_al_resolver_reportes(client, db, category, ready):
    oid, (tid, th, _, ch) = ready
    rid = review(client, ch, oid, 5).json()["id"]
    for h in _credible_reporters(client, db, category, th):
        client.post(f"{REVIEWS}/{rid}/report", headers=h, json={"reason": "FALSE"})
    assert db_review(db, rid).status == ReviewStatus.HIDDEN
    from tests.marketplace import payment_of
    webhook(db, oid, "refunded", amount=payment_of(db, oid).captured_cents)
    rev = db_review(db, rid)
    assert rev.moderation_reason == "ORDER_REFUNDED" and rev.weight == 0
    mod = admin_h(client, db, "mod@example.com", AdminRole.CONTENT_MODERATOR)
    for rep in client.get(f"{API}/admin/reviews/{rid}", headers=mod).json()["reports"]:
        client.post(f"{API}/admin/review-reports/{rep['id']}/resolution", headers=mod,
                    json={"resolution": "KEEP", "note": "Legítima"})
    assert db_review(db, rid).status == ReviewStatus.HIDDEN
    r = client.post(f"{API}/admin/reviews/{rid}/moderation", headers=mod, json={"action": "PUBLISH",
                                                                                "reason": "VERIFIED_OK"})
    assert err(r) == "REVIEW_ORDER_REFUNDED"
    assert db.get(TechnicianReputation, tid).verified_reviews <= 3


def test_soporte_no_revierte_la_decision_de_moderacion(client, db, ready):
    oid, (_, _, _, ch) = ready
    rid = review(client, ch, oid, 5).json()["id"]
    url = f"{API}/admin/reviews/{rid}/moderation"
    mod = admin_h(client, db, "mod@example.com", AdminRole.CONTENT_MODERATOR)
    sup = admin_h(client, db, "soporte@example.com", AdminRole.SUPPORT)
    assert client.post(url, headers=mod, json={"action": "HIDE", "reason": "FAKE_REVIEW",
                                               "note": "Cuenta vinculada"}).status_code == 200
    assert client.post(url, headers=sup, json={"action": "PUBLISH", "reason": "VERIFIED_OK"}).status_code == 403
    assert client.post(url, headers=sup, json={"action": "HIDE", "reason": "SPAM", "note": "x",
                                               "count_in_reputation": False}).status_code == 403


def test_editar_no_deshace_la_decision_del_moderador(client, db, ready):
    oid, (_, _, _, ch) = ready
    rid = review(client, ch, oid, 3, comment="Normal").json()["id"]
    mod = admin_h(client, db, "mod@example.com", AdminRole.CONTENT_MODERATOR)
    url = f"{API}/admin/reviews/{rid}/moderation"
    client.post(url, headers=mod, json={"action": "HIDE", "reason": "OTHER", "note": "Revisar"})
    r = client.post(url, headers=mod, json={"action": "PUBLISH", "reason": "OTHER", "note": "Visible, sin peso",
                                            "count_in_reputation": False})
    assert r.status_code == 200 and Decimal(r.json()["weight"]) == 0
    assert client.put(f"{REVIEWS}/{rid}", headers=ch, json={"comment": "Normal, ok", "reason": "Detalle"}).status_code == 200
    rev = db_review(db, rid)
    assert rev.weight == 0 and rev.status == ReviewStatus.PUBLISHED
    # ...pero si agrega lenguaje ofensivo vuelve a moderación.
    client.put(f"{REVIEWS}/{rid}", headers=ch, json={"comment": "Es un idiota", "reason": "Enojo"})
    assert db_review(db, rid).status == ReviewStatus.PENDING_MODERATION


def test_firma_cubre_el_motivo_de_moderacion(client, db, ready):
    oid, (_, _, _, ch) = ready
    rid = review(client, ch, oid, 2).json()["id"]
    db.execute(text("UPDATE reviews SET moderation_reason = 'VERIFIED_OK' WHERE id = :id"), {"id": rid})
    db.commit()
    mod = admin_h(client, db, "mod@example.com", AdminRole.CONTENT_MODERATOR)
    assert client.get(f"{API}/admin/reviews/integrity", headers=mod).json()["tampered_ids"] == [rid]
