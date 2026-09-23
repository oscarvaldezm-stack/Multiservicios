import enum

from sqlalchemy import Enum as SAEnum


class UserRole(str, enum.Enum):
    CLIENT = "client"
    TECHNICIAN = "technician"
    ADMIN = "admin"


class KycStatus(str, enum.Enum):
    """Estado del expediente KYC. Solo APPROVED permite recibir órdenes."""

    NOT_STARTED = "NOT_STARTED"
    PENDING_DOCUMENTS = "PENDING_DOCUMENTS"
    SUBMITTED = "SUBMITTED"
    UNDER_REVIEW = "UNDER_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    CORRECTION_REQUIRED = "CORRECTION_REQUIRED"
    SUSPENDED = "SUSPENDED"
    EXPIRED = "EXPIRED"


class KycDocumentStatus(str, enum.Enum):
    UPLOADING = "UPLOADING"
    SCANNING = "SCANNING"
    PENDING_REVIEW = "PENDING_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    INVALID = "INVALID"          # falló validación o escaneo
    SUPERSEDED = "SUPERSEDED"    # el técnico subió uno nuevo
    EXPIRED = "EXPIRED"


class DocumentCategory(str, enum.Enum):
    IDENTITY = "IDENTITY"
    ADDRESS = "ADDRESS"
    SELFIE = "SELFIE"                        # decisión D1: selfie sosteniendo la identificación
    BACKGROUND_CHECK = "BACKGROUND_CHECK"    # decisión D6: opcional, otorga insignia


class DocumentSide(str, enum.Enum):
    FRONT = "FRONT"
    BACK = "BACK"
    PAGE = "PAGE"
    SELFIE = "SELFIE"


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"
    INVALID = "INVALID"
    ERROR = "ERROR"


class ReviewDecision(str, enum.Enum):
    APPROVED = "APPROVED"
    CORRECTION_REQUIRED = "CORRECTION_REQUIRED"
    REJECTED = "REJECTED"


class DocumentDecision(str, enum.Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class ReasonScope(str, enum.Enum):
    DOCUMENT = "DOCUMENT"
    CORRECTION = "CORRECTION"
    REJECTION = "REJECTION"
    SUSPENSION = "SUSPENSION"


class ActorType(str, enum.Enum):
    CLIENT = "CLIENT"
    TECHNICIAN = "TECHNICIAN"
    ADMIN = "ADMIN"
    SYSTEM = "SYSTEM"


class AuditResult(str, enum.Enum):
    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    ERROR = "ERROR"


class AdminRole(str, enum.Enum):
    KYC_REVIEWER = "KYC_REVIEWER"
    KYC_SUPERVISOR = "KYC_SUPERVISOR"
    SUPPORT = "SUPPORT"
    SUPERADMIN = "SUPERADMIN"
    FINANCE_VIEWER = "FINANCE_VIEWER"
    FINANCE_OPERATOR = "FINANCE_OPERATOR"
    FINANCE_ADMIN = "FINANCE_ADMIN"
    CONTENT_MODERATOR = "CONTENT_MODERATOR"


class RetentionAction(str, enum.Enum):
    DELETE = "DELETE"
    ANONYMIZE = "ANONYMIZE"


class OrderStatus(str, enum.Enum):
    """
    Ciclo de vida de una orden de servicio (ver app/orders/state_machine.py).
    Solo READY_FOR_REVIEW permite crear una calificación.
    """

    REQUESTED = "REQUESTED"                  # el cliente publicó la solicitud
    ACCEPTED = "ACCEPTED"                    # un técnico APROBADO la aceptó con precio acordado
    SCHEDULED = "SCHEDULED"                  # fecha y hora confirmadas
    IN_PROGRESS = "IN_PROGRESS"              # el técnico inició (pago ya autorizado)
    AWAITING_APPROVAL = "AWAITING_APPROVAL"  # el técnico terminó; espera la aceptación del cliente
    COMPLETED = "COMPLETED"                  # el cliente aceptó (o pasaron 72 h): se captura el pago
    PAID = "PAID"                            # pago confirmado por el proveedor
    READY_FOR_REVIEW = "READY_FOR_REVIEW"    # puede calificarse
    REVIEWED = "REVIEWED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"                        # el pago no se pudo autorizar o capturar
    DISPUTED = "DISPUTED"                    # congelada: ni pago al técnico ni calificación
    REFUNDED = "REFUNDED"                    # reembolso total


class PaymentStatus(str, enum.Enum):
    PENDING = "PENDING"                        # intención creada, sin autorizar
    AUTHORIZED = "AUTHORIZED"                  # fondos retenidos en la tarjeta (al salir el técnico)
    CAPTURED = "CAPTURED"                      # cobrado y en custodia de la plataforma = pago confirmado
    RELEASED = "RELEASED"                      # transferido al técnico
    PARTIALLY_REFUNDED = "PARTIALLY_REFUNDED"
    REFUNDED = "REFUNDED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"                      # autorización anulada (orden cancelada)


# Estados de pago que cuentan como "pago confirmado" para calificar.
PAYMENT_CONFIRMED = frozenset({PaymentStatus.CAPTURED, PaymentStatus.RELEASED, PaymentStatus.PARTIALLY_REFUNDED})


class ReviewStatus(str, enum.Enum):
    PUBLISHED = "PUBLISHED"
    PENDING_MODERATION = "PENDING_MODERATION"  # retenida por antifraude o lenguaje: no pública, no cuenta
    HIDDEN = "HIDDEN"                          # oculta temporalmente (reportes, reembolso, moderador)
    REMOVED = "REMOVED"                        # eliminada por un moderador (se conserva para auditoría)


class ReviewCategory(str, enum.Enum):
    QUALITY = "QUALITY"                  # calidad del trabajo
    PUNCTUALITY = "PUNCTUALITY"
    COMMUNICATION = "COMMUNICATION"
    CLEANLINESS = "CLEANLINESS"
    PROFESSIONALISM = "PROFESSIONALISM"


class ReportReason(str, enum.Enum):
    OFFENSIVE = "OFFENSIVE"
    FALSE = "FALSE"
    SPAM = "SPAM"
    NOT_RELATED = "NOT_RELATED"          # no corresponde al servicio
    OTHER = "OTHER"


class ReportStatus(str, enum.Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"


class ReportResolution(str, enum.Enum):
    KEEP = "KEEP"
    HIDE = "HIDE"
    REMOVE = "REMOVE"


class SignalKind(str, enum.Enum):
    DEVICE = "DEVICE"
    IP = "IP"


def pg_enum(enum_cls: type[enum.Enum], name: str) -> SAEnum:
    """ENUM nativo de PostgreSQL que guarda el *valor* ('client'), no el nombre ('CLIENT')."""
    return SAEnum(
        enum_cls,
        name=name,
        values_callable=lambda e: [m.value for m in e],
        validate_strings=True,
    )


class KeyPurpose(str, enum.Enum):
    KYC_KEK = "KYC_KEK"              # llave maestra que envuelve las DEK de expedientes
    BLIND_INDEX = "BLIND_INDEX"      # llave HMAC de índices ciegos


class KeyStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"                # cifra y descifra
    DECRYPT_ONLY = "DECRYPT_ONLY"    # rotada: solo descifra lo viejo mientras se re-envuelve
    REVOKED = "REVOKED"              # comprometida o retirada: ya no debe estar configurada
