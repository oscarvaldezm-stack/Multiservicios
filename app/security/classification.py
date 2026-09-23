"""
Clasificación de datos y controles exigidos por nivel.

Es una tabla viva: las pruebas verifican que cada columna cifrada del modelo esté
declarada aquí y que ningún dato ALTAMENTE_SENSIBLE viva en claro en la base.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass


class DataClass(str, enum.Enum):
    PUBLIC = "PUBLICO"
    INTERNAL = "INTERNO"
    SENSITIVE = "SENSIBLE"
    HIGHLY_SENSITIVE = "ALTAMENTE_SENSIBLE"


@dataclass(frozen=True)
class Controls:
    encrypted_at_rest_app: bool      # cifrado en la aplicación (además del disco / bucket)
    masked_by_default: bool          # se muestra enmascarado salvo permiso explícito
    access_audited: bool             # cada lectura queda en audit_logs
    allowed_in_logs: bool
    stored_by_us: bool = True        # False = lo custodia un tercero (Stripe) y solo guardamos referencia


CONTROLS: dict[DataClass, Controls] = {
    DataClass.PUBLIC: Controls(False, False, False, True),
    DataClass.INTERNAL: Controls(False, False, False, True),
    DataClass.SENSITIVE: Controls(True, True, True, False),
    DataClass.HIGHLY_SENSITIVE: Controls(True, True, True, False),
}

# Inventario: dato -> (clasificación, dónde vive / cómo se protege)
INVENTORY: dict[str, tuple[DataClass, str]] = {
    "technician.display_name": (DataClass.PUBLIC, "users.full_name"),
    "technician.rating": (DataClass.PUBLIC, "technician_profiles.rating_avg"),
    "service.category": (DataClass.PUBLIC, "service_categories"),
    "order.status": (DataClass.INTERNAL, "service_requests.status"),
    "kyc.status": (DataClass.INTERNAL, "kyc_profiles.status"),
    "user.email": (DataClass.SENSITIVE, "users.email (índice único; enmascarado en la cola de revisión)"),
    "user.phone": (DataClass.SENSITIVE, "users.phone"),
    "kyc.legal_name": (DataClass.SENSITIVE, "kyc_profiles.first_names / apellidos"),
    "kyc.birth_date": (DataClass.SENSITIVE, "kyc_profiles.birth_date"),
    "kyc.address": (DataClass.SENSITIVE, "kyc_addresses"),
    "kyc.curp": (DataClass.SENSITIVE, "kyc_profiles.curp_enc (AES-256-GCM) + curp_hash (HMAC)"),
    "kyc.rfc": (DataClass.SENSITIVE, "kyc_profiles.rfc_enc (AES-256-GCM) + rfc_hash (HMAC)"),
    "kyc.document_number": (DataClass.HIGHLY_SENSITIVE, "kyc_documents.number_enc + number_hash"),
    "kyc.document_file": (DataClass.HIGHLY_SENSITIVE, "bucket privado, cifrado con FEK por archivo + SSE-KMS"),
    "kyc.file_key": (DataClass.HIGHLY_SENSITIVE, "kyc_document_files.file_key_enc (envuelta con la DEK)"),
    "kyc.profile_key": (DataClass.HIGHLY_SENSITIVE, "kyc_profiles.data_key_enc (envuelta con la KEK)"),
    "keys.master": (DataClass.HIGHLY_SENSITIVE, "KMS / variable de entorno; solo metadatos en encryption_keys_metadata"),
    "bank.clabe": (DataClass.HIGHLY_SENSITIVE, "NO se almacena: la custodia Stripe; guardamos solo la referencia de cuenta"),
    "bank.account_number": (DataClass.HIGHLY_SENSITIVE, "NO se almacena (Stripe)"),
    "payment.card": (DataClass.HIGHLY_SENSITIVE, "NUNCA toca nuestros servidores (componente de Stripe, PCI SAQ A)"),
    "payment.provider_secret": (DataClass.HIGHLY_SENSITIVE, "gestor de secretos / variable de entorno"),
    "auth.password": (DataClass.HIGHLY_SENSITIVE, "users.hashed_password (bcrypt); nunca en claro"),
    "auth.refresh_token": (DataClass.HIGHLY_SENSITIVE, "refresh_tokens.token_hash (SHA-256)"),
}

# Columnas que DEBEN guardarse cifradas (BYTEA) en la base.
ENCRYPTED_COLUMNS: frozenset[str] = frozenset({
    "kyc_profiles.curp_enc", "kyc_profiles.rfc_enc", "kyc_profiles.data_key_enc",
    "kyc_documents.number_enc", "kyc_document_files.file_key_enc",
})

# Nombres de columna que jamás deben existir en claro en ninguna tabla.
FORBIDDEN_PLAINTEXT_COLUMNS: frozenset[str] = frozenset({
    "curp", "rfc", "clabe", "account_number", "card_number", "cvv", "cvc", "password", "document_number",
})
