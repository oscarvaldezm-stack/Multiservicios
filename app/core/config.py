"""
Configuración centralizada. Todos los secretos vienen de variables de entorno
(o de un archivo .env en desarrollo). NUNCA se escriben en el código.
"""
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "Multiservicios API"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    API_V1_PREFIX: str = "/api/v1"

    # --- Base de datos -------------------------------------------------------
    # Formato: postgresql+psycopg://usuario:password@host:5432/basedatos
    DATABASE_URL: str
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # --- JWT -----------------------------------------------------------------
    # Genera uno con:  python -c "import secrets; print(secrets.token_urlsafe(64))"
    JWT_SECRET_KEY: SecretStr
    # Se fija el algoritmo del lado del servidor: jamás se confía en el "alg" del token.
    JWT_ALGORITHM: Literal["HS256", "HS384", "HS512"] = "HS256"
    JWT_ISSUER: str = "multiservicios-api"
    JWT_AUDIENCE: str = "multiservicios-clients"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=15, ge=1, le=60)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7, ge=1, le=30)

    # --- Contraseñas / fuerza bruta -----------------------------------------
    BCRYPT_ROUNDS: int = Field(default=12, ge=4, le=16)
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15

    # --- HTTP ----------------------------------------------------------------
    CORS_ORIGINS: list[str] = []
    ALLOWED_HOSTS: list[str] = ["*"]

    # --- KYC: cifrado de campos ------------------------------------------------
    # 32 bytes en base64url. Genera con:
    #   python -c "import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
    # En producción la llave maestra vive en KMS (ver app/core/crypto.py: KeyProvider).
    KYC_MASTER_KEY: SecretStr
    KYC_MASTER_KEY_ID: int = Field(default=1, ge=1, le=255)
    # Llaves anteriores para descifrar tras una rotación: "1:<b64>,2:<b64>"
    KYC_PREVIOUS_MASTER_KEYS: SecretStr | None = None
    # Llave DISTINTA para índices ciegos (HMAC). Si se filtra, no permite descifrar.
    KYC_BLIND_INDEX_KEY: SecretStr

    # --- KYC: reglas configurables -------------------------------------------
    KYC_REVIEW_CLAIM_TIMEOUT_HOURS: int = Field(default=48, ge=1)
    KYC_ADDRESS_PROOF_MAX_AGE_DAYS: int = Field(default=90, ge=1)
    KYC_REVALIDATION_MONTHS: int = Field(default=24, ge=1)
    # Versión vigente del aviso de privacidad. Al publicar uno nuevo, se cambia aquí y
    # los técnicos deben aceptarlo de nuevo antes de seguir con su expediente.
    KYC_PRIVACY_NOTICE_VERSION: str = Field(default="2026-09", min_length=1, max_length=20)
    # Exigir correo verificado antes de enviar el expediente (Fase 0, sección 3).
    KYC_REQUIRE_VERIFIED_EMAIL: bool = True

    # --- KYC: documentos ------------------------------------------------------
    STORAGE_BACKEND: Literal["local", "s3"] = "local"
    STORAGE_LOCAL_ROOT: str = "./var/storage"          # fuera de cualquier ruta servida por Nginx
    KYC_QUARANTINE_BUCKET: str = "kyc-quarantine"
    KYC_CLEAN_BUCKET: str = "kyc-clean"
    S3_REGION: str = "mx-central-1"
    S3_ENDPOINT_URL: str | None = None
    S3_KMS_KEY_ID: str | None = None                    # ARN de la llave KMS dedicada al KYC
    KYC_SCANNER: Literal["clamd", "dev_eicar"] = "dev_eicar"
    CLAMD_HOST: str = "clamav"
    CLAMD_PORT: int = 3310
    KYC_MAX_FILE_BYTES: int = Field(default=10 * 1024 * 1024, ge=1024, le=10 * 1024 * 1024)
    KYC_MAX_IMAGE_PIXELS: int = Field(default=40_000_000, ge=1_000_000)
    KYC_MAX_PDF_PAGES: int = Field(default=5, ge=1, le=20)
    KYC_MAX_UPLOADS_PER_DAY: int = Field(default=30, ge=1)
    KYC_MAX_SCAN_ATTEMPTS: int = Field(default=8, ge=1)
    KYC_FILE_VIEWS_PER_HOUR: int = Field(default=300, ge=1)   # por administrador; alerta de descarga masiva
    KYC_VIEW_TICKET_TTL_SECONDS: int = Field(default=60, ge=10, le=300)

    # --- Integridad (reseñas) y señales antifraude ------------------------------------
    # Llave HMAC propia: firma cada reseña (detecta cambios directos en la base) y seudonimiza
    # IP y dispositivo en user_signals. 32 bytes en base64url, distinta de las demás.
    INTEGRITY_KEY: SecretStr

    # --- KYC: decisiones --------------------------------------------------------------
    KYC_MAX_ACTIVE_CLAIMS: int = Field(default=10, ge=1)    # casos tomados a la vez por revisor

    # --- Órdenes -------------------------------------------------------------------------
    ORDER_AUTO_APPROVE_HOURS: int = Field(default=72, ge=1)    # decisión de pagos D5
    ORDER_REQUEST_EXPIRY_HOURS: int = Field(default=72, ge=1)  # solicitud sin técnico se cancela
    ORDER_DISPUTE_WINDOW_DAYS: int = Field(default=7, ge=1)    # después del pago
    ORDER_MAX_OPEN_PER_CLIENT: int = Field(default=5, ge=1)       # solicitudes abiertas a la vez (antispam)

    # --- Pagos (Fase 1: montos, impuestos y costo del proveedor) -------------------------
    # Todas las tasas en puntos base (1600 = 16 %). Decisión D6: el precio acordado va SIN IVA;
    # al cliente se le cobra precio + IVA, y al técnico se le retienen ISR e IVA.
    # Las retenciones las debe validar el contador (tasas 2026 para plataformas digitales).
    PAYMENT_PROVIDER: str = Field(default="stripe", min_length=1, max_length=30)
    PAYMENT_CURRENCY: str = Field(default="MXN", pattern=r"^[A-Z]{3}$")
    TAX_IVA_BP: int = Field(default=1600, ge=0, le=10000)                  # IVA del servicio y de la comisión
    WITHHOLDING_ISR_BP: int = Field(default=250, ge=0, le=10000)           # técnico con RFC
    WITHHOLDING_IVA_BP: int = Field(default=800, ge=0, le=10000)
    WITHHOLDING_ISR_NO_RFC_BP: int = Field(default=2000, ge=0, le=10000)   # técnico sin RFC
    WITHHOLDING_IVA_NO_RFC_BP: int = Field(default=1600, ge=0, le=10000)
    # Costo estimado del proveedor (tarjeta nacional, más IVA). Verificar la tarifa vigente.
    PROVIDER_FEE_RATE_BP: int = Field(default=360, ge=0, le=10000)
    PROVIDER_FEE_FIXED_CENTS: int = Field(default=300, ge=0)
    # Rango de precios admitido; una regla de comisión debe cubrir el costo del proveedor en todo el rango.
    PAYMENT_MIN_SERVICE_CENTS: int = Field(default=5_000, ge=1)            # $50
    PAYMENT_MAX_SERVICE_CENTS: int = Field(default=50_000_000, ge=1)       # $500,000
    # Vigencia de una autorización con tarjeta guardada (Visa, sin el cliente presente: ~4 d 18 h).
    PAYMENT_AUTHORIZATION_VALID_HOURS: int = Field(default=114, ge=1, le=24 * 30)

    # --- Pagos (Fase 2: Stripe) ------------------------------------------------------------
    # "fake" = proveedor en memoria para desarrollo y pruebas (prohibido en producción).
    PAYMENT_PROVIDER_BACKEND: Literal["stripe", "fake"] = "fake"
    # Clave secreta SOLO en el backend. Preferir una clave restringida (rk_) con permisos mínimos.
    STRIPE_SECRET_KEY: SecretStr | None = None
    # La única clave que viaja a la app (Flutter / web).
    STRIPE_PUBLISHABLE_KEY: str | None = None
    # Un secreto de firma DISTINTO por endpoint de webhook (plataforma y Connect). Se usan en la Fase 4.
    STRIPE_WEBHOOK_SECRET: SecretStr | None = None
    STRIPE_CONNECT_WEBHOOK_SECRET: SecretStr | None = None
    # Versión de la API fijada: un cambio de Stripe no altera el comportamiento sin un despliegue revisado.
    STRIPE_API_VERSION: str = Field(default="2026-08-26.dahlia", min_length=10, max_length=40)
    STRIPE_MAX_NETWORK_RETRIES: int = Field(default=2, ge=0, le=5)
    # --- Pagos (Fase 4: webhooks y conciliación) --------------------------------------------
    WEBHOOK_MAX_BODY_BYTES: int = Field(default=512 * 1024, ge=1024)   # un evento de Stripe pesa unos KB
    WEBHOOK_MAX_ATTEMPTS: int = Field(default=8, ge=1, le=20)           # después: DEAD y alerta a finanzas
    RECONCILIATION_WINDOW_HOURS: int = Field(default=48, ge=24, le=24 * 14)
    RECONCILIATION_INTERVAL_HOURS: int = Field(default=24, ge=1, le=24 * 7)
    # --- Pagos (Fase 5) -----------------------------------------------------------------------
    # D8: reembolsos arriba de este monto (lo que se devuelve al cliente) requieren una segunda firma.
    REFUND_DOUBLE_APPROVAL_CENTS: int = Field(default=200_000, ge=0)
    # Adónde vuelve el técnico al terminar (o al vencer) el formulario de Stripe. HTTPS en producción.
    STRIPE_CONNECT_RETURN_URL: str = "http://localhost:3000/pagos/cuenta/listo"
    STRIPE_CONNECT_REFRESH_URL: str = "http://localhost:3000/pagos/cuenta/reintentar"
    PAYMENT_ACCOUNT_COUNTRY: str = Field(default="MX", pattern=r"^[A-Z]{2}$")

    # --- Reseñas -------------------------------------------------------------------------
    REVIEW_WINDOW_DAYS: int = Field(default=30, ge=1)          # para calificar después del pago
    REVIEW_EDIT_HOURS: int = Field(default=24, ge=1)
    REVIEW_MAX_EDITS: int = Field(default=3, ge=0)
    REVIEW_MAX_PER_DAY: int = Field(default=10, ge=1)          # por cliente
    REVIEW_REPORTS_PER_DAY: int = Field(default=20, ge=1)      # por usuario
    REVIEW_AUTO_HIDE_REPORTS: int = Field(default=3, ge=2)     # clientes creíbles distintos -> oculta en espera de revisión
    REVIEW_REPORTER_MIN_AGE_DAYS: int = Field(default=7, ge=0)  # antigüedad mínima para que un reporte cuente
    REVIEW_REPLIES_ENABLED: bool = True
    REVIEW_REQUIRE_VERIFIED_EMAIL: bool = True
    REVIEW_MIN_ORDER_AMOUNT: float = Field(default=150.0, ge=0)  # menos: la reseña pesa la mitad
    REPUTATION_PRIOR_MEAN: float = Field(default=4.0, ge=1, le=5)
    REPUTATION_PRIOR_WEIGHT: float = Field(default=5.0, ge=0)
    REPUTATION_HALF_LIFE_DAYS: int = Field(default=365, ge=30)

    @field_validator("DATABASE_URL")
    @classmethod
    def _check_db_url(cls, v: str) -> str:
        if not v.startswith("postgresql+psycopg://"):
            raise ValueError("DATABASE_URL debe usar el driver 'postgresql+psycopg://'")
        return v

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def _check_secret(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 32:
            raise ValueError("JWT_SECRET_KEY debe tener al menos 32 caracteres aleatorios")
        return v

    @model_validator(mode="after")
    def _keys_are_distinct(self) -> "Settings":
        secrets_ = [self.JWT_SECRET_KEY.get_secret_value(), self.KYC_MASTER_KEY.get_secret_value(),
                    self.KYC_BLIND_INDEX_KEY.get_secret_value(), self.INTEGRITY_KEY.get_secret_value()]
        if len(set(secrets_)) != len(secrets_):
            raise ValueError("JWT_SECRET_KEY, KYC_MASTER_KEY, KYC_BLIND_INDEX_KEY e INTEGRITY_KEY deben ser distintas")
        return self

    @model_validator(mode="after")
    def _payment_range(self) -> "Settings":
        if self.PAYMENT_MIN_SERVICE_CENTS >= self.PAYMENT_MAX_SERVICE_CENTS:
            raise ValueError("PAYMENT_MIN_SERVICE_CENTS debe ser menor que PAYMENT_MAX_SERVICE_CENTS")
        return self

    @model_validator(mode="after")
    def _stripe_keys(self) -> "Settings":
        """Formato de las claves, modo prueba/producción coherente y un secreto por webhook."""
        sk = self.STRIPE_SECRET_KEY.get_secret_value() if self.STRIPE_SECRET_KEY else None
        pk = self.STRIPE_PUBLISHABLE_KEY
        if sk is not None and not sk.startswith(("sk_test_", "sk_live_", "rk_test_", "rk_live_")):
            raise ValueError("STRIPE_SECRET_KEY debe ser una clave secreta (sk_) o restringida (rk_) de Stripe")
        if pk is not None and not pk.startswith(("pk_test_", "pk_live_")):
            raise ValueError("STRIPE_PUBLISHABLE_KEY debe ser una clave publicable (pk_)")
        hooks = [h.get_secret_value() for h in (self.STRIPE_WEBHOOK_SECRET, self.STRIPE_CONNECT_WEBHOOK_SECRET) if h]
        if any(not h.startswith("whsec_") for h in hooks):
            raise ValueError("Los secretos de webhook de Stripe empiezan con whsec_")
        if len(hooks) == 2 and hooks[0] == hooks[1]:
            raise ValueError("STRIPE_WEBHOOK_SECRET y STRIPE_CONNECT_WEBHOOK_SECRET deben ser distintos")
        if self.PAYMENT_PROVIDER_BACKEND == "stripe":
            if not sk or not pk:
                raise ValueError("Con PAYMENT_PROVIDER_BACKEND=stripe se requieren STRIPE_SECRET_KEY y STRIPE_PUBLISHABLE_KEY")
            if ("_live_" in sk) != ("_live_" in pk):
                raise ValueError("STRIPE_SECRET_KEY y STRIPE_PUBLISHABLE_KEY deben ser del mismo modo (prueba o producción)")
        live = [k for k in (sk, pk) if k and "_live_" in k]
        if self.ENVIRONMENT == "production":
            if self.PAYMENT_PROVIDER_BACKEND != "stripe":
                raise ValueError("En producción PAYMENT_PROVIDER_BACKEND debe ser stripe")
            if len(live) != 2:
                raise ValueError("En producción las claves de Stripe deben ser de modo live (nunca sk_test_/pk_test_)")
            if len(hooks) != 2:
                raise ValueError("En producción se requieren STRIPE_WEBHOOK_SECRET y STRIPE_CONNECT_WEBHOOK_SECRET")
            if not (self.STRIPE_CONNECT_RETURN_URL.startswith("https://")
                    and self.STRIPE_CONNECT_REFRESH_URL.startswith("https://")):
                raise ValueError("En producción las URLs de retorno de Stripe deben ser HTTPS")
        elif live:
            raise ValueError("Fuera de producción no se permiten claves live de Stripe: usa las de modo prueba")
        return self

    @model_validator(mode="after")
    def _production_hardening(self) -> "Settings":
        if self.ENVIRONMENT == "production":
            if self.BCRYPT_ROUNDS < 12:
                raise ValueError("En producción BCRYPT_ROUNDS debe ser >= 12")
            if "*" in self.ALLOWED_HOSTS:
                raise ValueError("En producción define ALLOWED_HOSTS explícitamente")
            if "*" in self.CORS_ORIGINS:
                raise ValueError("En producción CORS_ORIGINS no puede ser '*'")
            if self.STORAGE_BACKEND != "s3" or not self.S3_KMS_KEY_ID:
                raise ValueError("En producción los documentos van a S3 con llave KMS (STORAGE_BACKEND=s3, S3_KMS_KEY_ID)")
            if self.KYC_SCANNER != "clamd":
                raise ValueError("En producción el antivirus debe ser clamd")
        return self

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
