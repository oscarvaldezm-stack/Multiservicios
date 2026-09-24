"""
Permisos finos de administradores.

- Los roles se guardan en la base (admin_role_assignments); el mapa rol → permisos vive
  aquí, en código, con pruebas. Cambiar qué puede hacer un rol exige un cambio revisado.
- Separación de funciones: quien administra roles (SUPERADMIN) no puede ver documentos
  ni decidir expedientes, y nadie puede modificar sus propios roles.
"""
from __future__ import annotations

import enum

from app.models.enums import AdminRole


class Permission(str, enum.Enum):
    KYC_QUEUE_READ = "kyc:queue:read"              # ver la cola con datos enmascarados
    KYC_CASE_CLAIM = "kyc:case:claim"              # tomar / liberar un caso
    KYC_CASE_READ_ASSIGNED = "kyc:case:read_assigned"  # expediente completo, solo si está asignado a mí
    KYC_CASE_READ_ANY = "kyc:case:read_any"        # expediente completo de cualquier caso
    KYC_DOCUMENT_DECIDE = "kyc:document:decide"
    KYC_APPROVE = "kyc:approve"
    KYC_REQUEST_CORRECTION = "kyc:request_correction"
    KYC_REJECT_FINAL = "kyc:reject_final"
    KYC_SUSPEND = "kyc:suspend"
    KYC_REINSTATE = "kyc:reinstate"
    AUDIT_READ = "audit:read"
    CATALOG_MANAGE = "catalog:manage"
    RETENTION_MANAGE = "retention:manage"
    ADMIN_ROLES_MANAGE = "admin:roles:manage"
    USERS_READ = "users:read"
    USERS_DEACTIVATE = "users:deactivate"
    # Órdenes y reseñas (Fase 4)
    ORDERS_READ = "orders:read"
    ORDERS_DISPUTE_RESOLVE = "orders:dispute:resolve"
    REVIEWS_READ = "reviews:read"                  # cola de moderación, detalle con señales y bitácora
    REVIEWS_MODERATE = "reviews:moderate"          # ocultar y resolver reportes (sin revertir decisiones)
    REVIEWS_PUBLISH = "reviews:publish"            # publicar / liberar retenidas / decidir el peso en la reputación
    REVIEWS_REMOVE = "reviews:remove"              # eliminar (decisión final)
    # Pagos (Fase 1)
    COMMISSION_RULES_MANAGE = "finance:commission_rules:manage"   # crear y cerrar reglas de comisión
    PAYMENT_ACCOUNTS_REVIEW = "finance:payment_accounts:review"   # revisar cuentas con nombre distinto al KYC
    # Pagos (Fase 5)
    FINANCE_READ = "finance:read"                                  # pagos, reembolsos, disputas y depósitos
    REFUNDS_EXECUTE = "finance:refunds:execute"                    # reembolsos hasta el umbral (D8)
    REFUNDS_APPROVE_HIGH = "finance:refunds:approve_high"          # segunda firma arriba del umbral
    DISPUTES_MANAGE = "finance:disputes:manage"                    # evidencia de contracargos
    CANCELLATION_POLICIES_MANAGE = "finance:cancellation_policies:manage"
    # Pagos (Fase 6)
    FINANCE_ALERTS_ACK = "finance:alerts:ack"                      # marcar alertas de finanzas como atendidas
    WEBHOOKS_MANAGE = "finance:webhooks:manage"                    # reencolar eventos del proveedor


P = Permission

ROLE_PERMISSIONS: dict[AdminRole, frozenset[Permission]] = {
    AdminRole.KYC_REVIEWER: frozenset({
        P.KYC_QUEUE_READ, P.KYC_CASE_CLAIM, P.KYC_CASE_READ_ASSIGNED, P.KYC_DOCUMENT_DECIDE,
        P.KYC_APPROVE, P.KYC_REQUEST_CORRECTION,
    }),
    AdminRole.KYC_SUPERVISOR: frozenset({
        P.KYC_QUEUE_READ, P.KYC_CASE_CLAIM, P.KYC_CASE_READ_ASSIGNED, P.KYC_CASE_READ_ANY,
        P.KYC_DOCUMENT_DECIDE, P.KYC_APPROVE, P.KYC_REQUEST_CORRECTION, P.KYC_REJECT_FINAL,
        P.KYC_SUSPEND, P.KYC_REINSTATE, P.AUDIT_READ, P.PAYMENT_ACCOUNTS_REVIEW,
    }),
    AdminRole.SUPPORT: frozenset({P.KYC_QUEUE_READ, P.USERS_READ, P.ORDERS_READ, P.REVIEWS_READ,
                                  P.REVIEWS_MODERATE}),
    AdminRole.SUPERADMIN: frozenset({
        P.KYC_QUEUE_READ, P.AUDIT_READ, P.CATALOG_MANAGE, P.RETENTION_MANAGE,
        P.ADMIN_ROLES_MANAGE, P.USERS_READ, P.USERS_DEACTIVATE, P.REVIEWS_READ,
    }),
    # Roles de finanzas: sin permisos KYC; resuelven disputas de dinero.
    AdminRole.FINANCE_VIEWER: frozenset({P.ORDERS_READ, P.FINANCE_READ}),
    AdminRole.FINANCE_OPERATOR: frozenset({P.ORDERS_READ, P.ORDERS_DISPUTE_RESOLVE, P.FINANCE_READ, P.REFUNDS_EXECUTE,
                                           P.DISPUTES_MANAGE, P.FINANCE_ALERTS_ACK}),
    AdminRole.FINANCE_ADMIN: frozenset({P.ORDERS_READ, P.ORDERS_DISPUTE_RESOLVE, P.COMMISSION_RULES_MANAGE,
                                        P.PAYMENT_ACCOUNTS_REVIEW, P.FINANCE_READ, P.REFUNDS_EXECUTE,
                                        P.REFUNDS_APPROVE_HIGH, P.DISPUTES_MANAGE,
                                        P.CANCELLATION_POLICIES_MANAGE, P.FINANCE_ALERTS_ACK, P.WEBHOOKS_MANAGE}),
    # Moderación de contenido: única que puede PUBLICAR (revertir un ocultamiento) y ELIMINAR reseñas (la bitácora de cada reseña va en su detalle).
    AdminRole.CONTENT_MODERATOR: frozenset({P.REVIEWS_READ, P.REVIEWS_MODERATE, P.REVIEWS_PUBLISH,
                                            P.REVIEWS_REMOVE}),
}

# Combinaciones prohibidas en una misma persona (separación de funciones).
INCOMPATIBLE_ROLES: tuple[frozenset[AdminRole], ...] = (
    frozenset({AdminRole.SUPERADMIN, AdminRole.KYC_REVIEWER}),
    frozenset({AdminRole.SUPERADMIN, AdminRole.KYC_SUPERVISOR}),
)

# Permisos que JAMÁS debe tener quien administra roles.
_NEVER_FOR_SUPERADMIN = {P.KYC_CASE_READ_ANY, P.KYC_CASE_READ_ASSIGNED, P.KYC_APPROVE, P.KYC_DOCUMENT_DECIDE}
assert not (ROLE_PERMISSIONS[AdminRole.SUPERADMIN] & _NEVER_FOR_SUPERADMIN)
assert set(ROLE_PERMISSIONS) == set(AdminRole), "Todo rol debe tener su entrada de permisos"


def permissions_for(roles: frozenset[AdminRole] | set[AdminRole]) -> frozenset[Permission]:
    out: set[Permission] = set()
    for r in roles:
        out |= ROLE_PERMISSIONS[r]
    return frozenset(out)


def check_role_set(roles: set[AdminRole]) -> None:
    for combo in INCOMPATIBLE_ROLES:
        if combo <= roles:
            names = " y ".join(sorted(r.value for r in combo))
            raise ValueError(f"Separación de funciones: {names} no pueden asignarse a la misma persona")
