# Multiservicios API: Backend

Autenticación + KYC de técnicos (Fase 1: modelo de datos y núcleo; Fase 2: API del técnico, catálogos y permisos de administradores; Fase 3: documentos y sistema de protección de datos; Fase 4: decisiones del revisor, órdenes de servicio y calificaciones verificadas) + módulo de pagos (Fase 1: pagos en centavos, motor de comisiones y libro contable; Fase 2: Stripe en modo prueba, cuenta del técnico y guardado de tarjeta; Fase 3: autorización al salir el técnico, captura y regla crítica completa; Fase 4: webhooks, worker y conciliación).

FastAPI · SQLAlchemy 2.0 · PostgreSQL · OAuth2 Password Flow + JWT · Passlib/bcrypt

## Estructura

```
app/
├── core/
│   ├── config.py        # Settings desde variables de entorno (valida secretos y endurece producción)
│   ├── security.py      # bcrypt (Passlib), emisión/validación JWT, refresh tokens opacos
│   ├── crypto.py        # KYC: AES-256-GCM por expediente, rotación de llave maestra, índice ciego
│   └── actor.py         # Quién ejecuta cada acción auditable y desde qué IP
├── db/
│   ├── base.py          # Base declarativa + naming convention + timestamps
│   └── session.py       # Engine, pool y get_db()
├── models/              # Modelos (kyc.py: expediente, documentos, revisión, auditoría, catálogos)
├── kyc/
│   ├── state_machine.py # ALLOWED_TRANSITIONS + transition(): única vía para cambiar el estado KYC
│   ├── identity.py      # Crear expediente, guardar CURP/RFC cifrados, borrado criptográfico
│   ├── validators.py    # CURP y RFC con dígito verificador, mayoría de edad, CP
│   ├── service.py       # Casos de uso del técnico: consentimiento, datos, domicilio, envío
│   ├── requirements.py  # Qué falta para enviar (checklist y validación del envío)
│   ├── permissions.py   # Roles de administrador → permisos, separación de funciones
│   ├── documents.py     # Alta, subida, cuarentena, worker de escaneo, borrado y vista previa
│   ├── files.py         # Tipo real por bytes, límites, saneamiento de imágenes, revisión de PDF, marca de agua
│   ├── access.py        # Quién puede leer un expediente (asignación + región)
│   └── view_tickets.py  # Tickets de visualización de un solo uso (60 s)
├── security/
│   ├── encryption_service.py # Punto único: cifrar, descifrar, enmascarar, validar acceso, rotar llaves
│   ├── classification.py     # Clasificación de datos y controles por nivel (verificada por pruebas)
│   ├── log_sanitizer.py      # Enmascara CLABE, tarjetas, CURP, RFC, JWT, secretos y tickets en logs
│   └── scanner.py            # Antivirus ClamAV (INSTREAM), falla cerrado
├── storage/object_storage.py # Almacenamiento privado: local (dev) o S3 con SSE-KMS
├── orders/              # Máquina de estados de la orden y casos de uso (cliente, técnico, disputas, trabajos)
├── payments/
│   ├── service.py       # Crear, anular y aplicar eventos del proveedor sobre un pago (nunca desde la app)
│   ├── commission.py    # CommissionEngine: centavos, IVA, retenciones, reglas y costo del proveedor
│   ├── state_machine.py # ALLOWED_PAYMENT_TRANSITIONS + move(): única vía para cambiar el estado del pago
│   ├── ledger.py        # Libro de partida doble (cada grupo de asientos suma cero)
│   ├── accounts.py      # Cuenta de pagos del técnico: alta, formulario de Stripe, estado, bloqueos
│   ├── customers.py     # Cliente en Stripe y guardado de tarjeta (SetupIntent)
│   ├── idempotency.py   # Encabezado Idempotency-Key de los POST de pagos
│   ├── webhooks.py      # Bandeja de webhooks y su worker (re-consulta al proveedor, reintentos)
│   ├── reconciliation.py # Conciliación diaria con el proveedor
│   └── providers/       # Contrato PaymentProvider, adaptador de Stripe y proveedor falso
├── reviews/             # Calificaciones: servicio, antifraude, reputación, firma de integridad, filtros de texto
├── audit/writer.py      # Auditoría con cadena de hashes y verify_chain()
├── schemas/auth.py      # Validación Pydantic (frontera de entrada/salida)
├── api/
│   ├── deps.py          # get_current_user, require_roles(), CurrentClient/Technician/Admin
│   └── routes/
│       ├── auth.py            # register/client, register/technician, token, refresh, logout, logout-all
│       ├── users.py           # Rutas separadas por rol
│       ├── technician_kyc.py  # /technicians/me/kyc/*
│       ├── kyc_catalogs.py    # /kyc/catalogs/*
│       ├── admin_kyc.py       # /admin/kyc/cases, /admin/users/{id}/roles
│       ├── admin_documents.py # Ver documentos, tickets, bitácora de auditoría
│       ├── admin_kyc_decisions.py # Tomar casos, decidir documentos y expedientes, suspender
│       ├── orders.py          # /orders, /clients/me/orders, /technicians/me/jobs-feed, /admin/orders
│       ├── reviews.py         # /reviews, /technicians/{id}/reviews, /admin/reviews
│       ├── payments.py        # /technicians/me/payment-account, /clients/me/payment-methods
│       └── webhooks.py        # /webhooks/stripe y /webhooks/stripe-connect (firma, sin JWT)
└── main.py              # App, CORS, TrustedHost, headers de seguridad
migrations/              # Alembic: 0001 base, 0002 KYC, 0003 motivo de corrección, 0004 protección de datos y documentos, 0005 órdenes, pagos y calificaciones, 0006 pagos en centavos, comisiones y libro contable, 0007 cuenta de pagos del técnico, 0008 autorización y regla crítica ampliada
scripts/
├── init_db.py           # Solo desarrollo: aplica migraciones y carga categorías
├── create_admin.py      # Único camino para crear administradores
├── load_sepomex.py      # Carga el catálogo oficial de códigos postales
└── rotate_keys.py       # Estado, activación, re-envoltura, revocación y re-key de llaves
worker/run.py            # Worker de antivirus y saneamiento (proceso aparte, sin acceso a Internet)
worker/jobs.py           # Trabajos periódicos: casos abandonados, KYC vencidos, aprobación a 72 h, solicitudes viejas, captura de pagos, webhooks, conciliación
deploy/nginx/nginx.conf  # TLS 1.2/1.3, HTTP→HTTPS, HSTS, límites por IP, logs sin tickets
tests/                   # 635 pruebas contra PostgreSQL real (esquema creado con las migraciones)
```

## Arranque rápido

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# BD con un usuario de privilegios mínimos (no 'postgres')
psql -U postgres -c "CREATE ROLE multiservicios_app LOGIN PASSWORD 'una-password-fuerte';"
psql -U postgres -c "CREATE DATABASE multiservicios OWNER multiservicios_app;"

cp .env.example .env         # y edita DATABASE_URL, JWT_SECRET_KEY y las dos llaves KYC
alembic upgrade head         # crea el esquema completo, con triggers y catálogos
python -m scripts.load_sepomex CPdescarga.txt   # catálogo SEPOMEX (descárgalo de Correos de México)
python -m scripts.create_admin admin@tuempresa.com "Tu Nombre"
uvicorn app.main:app --reload   # docs en http://localhost:8000/docs
```

Para las pruebas, crea una base aparte (`multiservicios_test`), exporta `TEST_DATABASE_URL` y ejecuta `pytest -v`. Las pruebas borran y recrean el esquema de esa base: nunca apuntes `TEST_DATABASE_URL` a una base con datos.

> **Nunca uses `Base.metadata.create_all`** para crear el esquema: los triggers de seguridad del KYC solo existen en las migraciones.

---

## 1. Diseño de la base de datos

```mermaid
erDiagram
    users ||--o| client_profiles : "rol=client"
    users ||--o| technician_profiles : "rol=technician"
    technician_profiles ||--o{ technician_services : ofrece
    service_categories ||--o{ technician_services : ""
    users ||--o{ service_requests : "cliente crea"
    users ||--o{ service_requests : "técnico atiende"
    service_categories ||--o{ service_requests : ""
    service_requests ||--o| payments : "escrow"
    service_requests ||--o| reviews : "1 reseña"
    users ||--o{ refresh_tokens : sesiones

    users {
        uuid id PK
        string email UK "minúsculas (CHECK)"
        string hashed_password "bcrypt $2b$"
        enum role "client|technician|admin"
        bool is_active
        int failed_login_attempts
        timestamptz locked_until
        int token_version "invalida JWT emitidos"
    }
    technician_profiles {
        uuid user_id PK_FK
        enum verification_status "pending|approved|rejected|suspended"
        numeric rating_avg "0-5, calculado"
        int jobs_completed
        int coverage_radius_km
        string payout_account_ref "ref. al proveedor, no CLABE"
    }
    service_requests {
        uuid id PK
        uuid client_id FK
        uuid technician_id FK
        enum status "open → assigned → in_progress → pending_approval → completed"
        numeric agreed_price
    }
    payments {
        uuid id PK
        uuid service_request_id FK_UK
        numeric amount
        numeric platform_fee "comisión"
        numeric technician_payout
        enum status "pending|held|released|refunded|failed"
    }
    refresh_tokens {
        uuid id PK
        uuid family_id "rotación"
        string token_hash UK "SHA-256"
        timestamptz revoked_at
    }
```

**Decisiones clave**

| Decisión | Por qué |
|---|---|
| Una tabla `users` + perfiles separados (`client_profiles`, `technician_profiles`) | Las credenciales viven aisladas de los datos de negocio. El rol decide qué perfil existe. |
| UUID como PK en entidades expuestas | Los IDs secuenciales (`/users/1`, `/users/2`...) facilitan enumerar recursos (IDOR). |
| ENUMs nativos de PostgreSQL | La BD rechaza roles o estados inventados aunque falle la validación de la app. |
| CHECK constraints (17) | Defensa en profundidad: `platform_fee + technician_payout = amount`, rating 1-5, email en minúsculas, un cliente no puede ser su propio técnico, etc. |
| `payments` con estados `held → released` | Modela el escrow que pide el proyecto: el dinero se retiene y solo se libera cuando el cliente acepta el trabajo. |
| `rating_avg`, `jobs_completed` en el perfil | Los calcula el sistema; el esquema de edición del técnico no los incluye. |
| Sin datos de tarjeta, CLABE ni INE | Solo referencias al proveedor de pagos o a un bucket privado (PCI-DSS y datos personales). |
| `Numeric(10,2)` para dinero | Nunca `float` para montos. |
| `timestamptz` en todas las fechas | Evita errores de zona horaria. |

---

## 2. Autenticación

```
POST /api/v1/auth/register/client       → 201 (rol = client, fijado por la ruta)
POST /api/v1/auth/register/technician   → 201 (rol = technician, verificación = pending)
POST /api/v1/auth/token                 → {access_token (JWT 15 min), refresh_token (opaco 7 días)}
POST /api/v1/auth/refresh               → par nuevo; el refresh anterior queda revocado
POST /api/v1/auth/logout                → revoca la sesión de ese dispositivo
POST /api/v1/auth/logout-all            → invalida todos los tokens del usuario
```

**Contraseñas (Passlib + bcrypt)**
- `CryptContext(schemes=["bcrypt"], bcrypt__rounds=12, deprecated="auto")`.
- `verify_and_update()` re-hashea al hacer login si en el futuro subes los rounds.
- Máximo 72 bytes (límite real de bcrypt: más allá se truncaría sin avisar). Mínimo 10 caracteres con mayúsculas, minúsculas y números.
- `dummy_verify()` cuando el correo no existe, para que el tiempo de respuesta no revele qué correos están registrados.

**Access token (JWT, 15 min)**
- Claims: `sub`, `role`, `ver`, `type=access`, `iss`, `aud`, `iat`, `nbf`, `exp`, `jti`; todos obligatorios al decodificar.
- `algorithms=[HS256]` fijo del lado del servidor: bloquea `alg: none` y la confusión de algoritmos.
- `ver` se compara con `users.token_version`: un logout global, un cambio de contraseña o una desactivación invalidan al instante los tokens ya emitidos.

**Refresh token (opaco, 7 días)**
- 384 bits aleatorios; en la BD solo se guarda su SHA-256.
- **Rotación:** cada uso entrega uno nuevo.
- **Detección de reuso:** si llega un token ya rotado (señal de robo), se revoca toda la familia y se incrementa `token_version`. Así se expulsa tanto al atacante como a la sesión legítima.

**Fuerza bruta:** 5 intentos fallidos bloquean la cuenta 15 minutos (HTTP 423). El contador se actualiza con `SELECT ... FOR UPDATE`, así que peticiones en paralelo no pueden saltárselo.

---

## 3. Separación de roles

1. **El rol nunca viene del cliente.** Los esquemas de registro usan `extra="forbid"` y no tienen campo `role`: enviar `"role": "admin"` devuelve 422. Los administradores solo se crean con `scripts/create_admin.py` desde el servidor.
2. **El token prueba identidad, no permisos.** `get_current_user` carga el usuario desde la BD en cada petición y autoriza con `user.role` de la BD, no con el claim del JWT. Un JWT con `role: admin` falsificado no sirve (además, la firma falla).
3. **Negar por defecto a nivel de router:**
   ```python
   technician_router = APIRouter(prefix="/technicians",
       dependencies=[Depends(require_roles(UserRole.TECHNICIAN))])
   ```
   Cualquier endpoint nuevo dentro de ese router hereda la restricción.
4. **401 frente a 403:** 401 = no autenticado; 403 = autenticado pero sin permiso.
5. **Segundo nivel para técnicos:** `VerifiedTechnician` exige `verification_status = approved` (lo aprueba un admin) antes de ver o aceptar trabajos.
6. **Listas blancas para editar:** `TechnicianProfileUpdate` solo permite `bio`, `years_experience`, `base_city`, `coverage_radius_km` e `is_available`. Intentar editar `rating_avg` o `verification_status` devuelve 422.

**Pendiente para la siguiente fase (autorización por objeto / IDOR):** cuando existan los endpoints de solicitudes, cada consulta debe filtrar por dueño, no solo por rol:
```python
select(ServiceRequest).where(ServiceRequest.id == request_id,
                             ServiceRequest.client_id == current_user.id)
```
Así un cliente no puede leer la solicitud de otro cambiando el UUID en la URL.

---

## 4. Prevención de inyección SQL

1. **Solo ORM / Core con parámetros enlazados.** `select(User).where(User.email == email)` genera `WHERE email = %(email)s`; el valor viaja separado del SQL y nunca se interpreta como código.
2. **Si algún día necesitas SQL crudo**, siempre con `text()` y parámetros:
   ```python
   # ✅ Correcto
   db.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})
   # ❌ NUNCA
   db.execute(text(f"SELECT * FROM users WHERE email = '{email}'"))
   ```
   Los nombres de tablas o columnas no se pueden parametrizar: si deben ser dinámicos, valídalos contra una lista blanca (por ejemplo, `sort_by: Literal["created_at", "rating_avg"]`).
3. **Validación de tipos antes de la BD:** los parámetros de ruta son `uuid.UUID`, así que `/technicians/1 OR 1=1/verification` devuelve 422 sin llegar a PostgreSQL. `limit` está acotado a 1-200.
4. **Usuario de BD con privilegios mínimos:** la app no se conecta como `postgres`. En producción, que el dueño de las tablas (el que corre las migraciones) sea distinto del usuario de la app, y que este solo tenga `SELECT/INSERT/UPDATE/DELETE`:
   ```sql
   GRANT CONNECT ON DATABASE multiservicios TO multiservicios_app;
   GRANT USAGE ON SCHEMA public TO multiservicios_app;
   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO multiservicios_app;
   REVOKE CREATE ON SCHEMA public FROM PUBLIC;
   ```
   Aunque hubiera una inyección, no podría hacer `DROP TABLE`.
5. **`statement_timeout=15s`** en cada conexión, para que una consulta abusiva no acapare el pool.

---

## 5. Otras medidas incluidas
- Secretos solo por variables de entorno; `JWT_SECRET_KEY` de al menos 32 caracteres (la app no arranca si no).
- En producción la app se niega a arrancar con `ALLOWED_HOSTS=*`, `CORS=*` o bcrypt con menos de 12 rounds, y se ocultan `/docs` y `/openapi.json`.
- Headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store` y HSTS (en producción).
- Las respuestas nunca incluyen `hashed_password` ni `token_version` (`response_model=UserOut`).

## 6. Antes de salir a producción (siguientes fases)
- **Rate limiting** por IP en `/auth/token` y `/auth/register/*` (slowapi o en el API Gateway/Nginx), como complemento del bloqueo por cuenta.
- **Verificación de correo** y **recuperación de contraseña** con tokens de un solo uso. Al cambiar la contraseña: incrementar `token_version`.
- Para la app móvil: guardar el refresh token en Keychain/Keystore. Para web: cookie `HttpOnly; Secure; SameSite=Strict` en lugar de `localStorage`.
- HTTPS obligatorio (TLS en el balanceador) y logs de auditoría de acciones de admin.
- Si en el futuro separas servicios, migrar el JWT a RS256/EdDSA (llave privada solo en el servicio de auth).

---

## 7. KYC de técnicos: Fase 1 (modelo de datos y núcleo)

El diseño completo está en el doc **Módulo KYC de técnicos: Fase 0, arquitectura**. Esta fase entrega la base sobre la que se construyen los endpoints (Fase 2) y la subida de documentos (Fase 3).

**Decisiones aplicadas:** selfie sosteniendo la identificación (obligatoria), RFC obligatorio de persona física, carta de antecedentes no penales opcional con insignia, catálogo SEPOMEX completo.

### Tablas nuevas (19)

| Grupo | Tablas |
| --- | --- |
| Expediente | `kyc_profiles`, `kyc_addresses`, `kyc_documents`, `kyc_document_files` |
| Revisión | `kyc_reviews`, `kyc_document_reviews`, `kyc_status_history` |
| Trazabilidad | `audit_logs`, `consents`, `outbox_events` |
| Permisos | `admin_role_assignments`, `admin_region_scopes` |
| Catálogos | `countries`, `mx_states` (32, INEGI), `mx_municipalities`, `mx_postal_settlements` (SEPOMEX), `document_types` (11), `rejection_reasons` (18) |
| Retención | `retention_policies` (6 propuestas, **todas deshabilitadas**) |

`technician_profiles.verification_status` desapareció: el estado vive en `kyc_profiles.status`. La migración crea un expediente `NOT_STARTED` para cada técnico existente, **incluidos los que estaban "aprobados"** con el sistema anterior, porque esa aprobación no tenía documentos detrás.

### Defensas en la base de datos

La aplicación valida todo, pero estas reglas también las impone PostgreSQL, así que ni un endpoint olvidado ni un script las pueden saltar:

| Regla | Mecanismo |
| --- | --- |
| Solo las 12 transiciones de estado permitidas | Trigger `kyc_enforce_transition` (una prueba verifica que coincide con el código) |
| Un expediente nace en `NOT_STARTED` | Mismo trigger, en `INSERT` |
| Enviado = datos completos y mayor de edad | CHECK `complete_data_after_submission` y `adult_at_submission` |
| Revisor asignado solo en revisión | CHECK `reviewer_only_under_review` |
| Historial y auditoría no se editan ni borran | Trigger `forbid_update_delete` |
| Domicilio enviado a revisión queda congelado | Trigger `kyc_address_immutable` |
| **Asignar una orden exige KYC `APPROVED` y usuario activo** | Trigger `service_request_assignment_guard` con `FOR SHARE` |
| Solo con KYC aprobado se puede estar disponible, y al salir de `APPROVED` se apaga | Triggers `technician_availability_guard` y `kyc_unavailable_when_not_approved` |

### Cifrado de CURP y RFC

- Cada expediente tiene su propia llave (DEK) de 256 bits, guardada cifrada con la llave maestra (KEK). En producción la KEK vive en un KMS: basta implementar otro `KeyProvider`.
- AES-256-GCM con datos asociados `tabla:id:campo`: un valor cifrado copiado a otra fila u otro campo no descifra.
- Índice ciego HMAC-SHA256 con una llave distinta, para detectar CURP o RFC duplicados sin descifrar.
- Rotación de llave maestra sin re-cifrar datos (`KYC_PREVIOUS_MASTER_KEYS`).
- **Borrado criptográfico:** destruir la DEK de un expediente deja sus datos ilegibles incluso en respaldos.

### Auditoría con cadena de hashes

Cada fila de `audit_logs` guarda el hash de la anterior. `verify_chain()` detecta una fila alterada o borrada aunque alguien desactive el trigger. El escritor rechaza campos como `curp`, `rfc`, `password` o `token`; solo acepta versiones enmascaradas.

### Limitaciones conocidas

- El dueño de las tablas puede desactivar triggers. En producción, la app debe conectarse con un usuario que **no** sea dueño de las tablas ni tenga `TRUNCATE`; las migraciones corren con otro usuario.
- `audit_logs` aún no está particionada por mes; conviene hacerlo cuando pase de algunos millones de filas.

---

## 8. KYC de técnicos: Fase 2 (API del técnico, catálogos y permisos)

Todas las respuestas de error tienen la misma forma y un código estable, para que la app decida qué mostrar sin depender del texto:

```json
{"detail": {"code": "KYC_REQUIREMENTS_MISSING", "message": "Faltan requisitos para enviar tu verificación",
            "missing": ["EMAIL_NOT_VERIFIED", "ADDRESS", "DOC_IDENTITY", "DOC_ADDRESS_PROOF", "DOC_SELFIE"]}}
```

### Endpoints del técnico

Todas las rutas son `/me`: el técnico nunca envía el ID de un expediente, así que no puede apuntar al de otra persona. Requieren JWT de un usuario con rol `technician` (otro rol: 403; sin sesión: 401).

| Método y ruta | Request | Respuesta | Errores principales |
| --- | --- | --- | --- |
| `GET /api/v1/technicians/me/kyc` | — | 200: estado, pendientes, datos (CURP y RFC **enmascarados**), domicilio, documentos, consentimientos, corrección solicitada y qué secciones se pueden editar | — |
| `GET /api/v1/technicians/me/kyc/status` | — | 200: estado, `can_submit`, `missing`, `next_step` (ligero, para consultar cada cierto tiempo) | — |
| `POST /api/v1/technicians/me/kyc/consents` | `{"notice_version": "2026-09", "purposes": ["KYC_IDENTITY", "BIOMETRIC_SELFIE"]}` | 201: propósitos aceptados. Repetir no duplica | 409 `KYC_NOTICE_OUTDATED`; 422 propósito inválido |
| `PUT /api/v1/technicians/me/kyc/personal-data` | nombre(s), apellidos, `birth_date`, `curp`, `rfc` | 200: expediente. La primera captura pasa el estado a `PENDING_DOCUMENTS` | 409 `KYC_CONSENT_REQUIRED`, `KYC_NOT_EDITABLE`, `KYC_IDENTITY_CONFLICT`; 422 `CURP_*`, `RFC_*`, `UNDERAGE`, campos extra o caracteres no permitidos |
| `PUT /api/v1/technicians/me/kyc/address` | calle y números + `postal_settlement_id` (colonia del catálogo) **o** `postal_code` + `settlement` + `municipality_id` | 200: expediente; CP, municipio, estado y ciudad los calcula el backend | 409 `KYC_CONSENT_REQUIRED`, `KYC_NOT_EDITABLE`; 422 `ADDRESS_POSTAL_CODE_MISMATCH`, `ADDRESS_POSTAL_CODE_UNKNOWN`, `ADDRESS_SETTLEMENT_UNKNOWN` |
| `POST /api/v1/technicians/me/kyc/submission` | — | 202: `SUBMITTED`, ciclo nuevo, domicilio congelado | 409 `KYC_NOT_SUBMITTABLE`; 422 `KYC_REQUIREMENTS_MISSING` con la lista exacta |

**Validaciones de datos personales:** CURP con dígito verificador y coherente con la fecha de nacimiento; RFC de persona física con dígito verificador, sin genéricos y con la misma fecha; mayor de 18 años; nombres solo con letras, acentos, espacios, apóstrofo, guion o punto; sin caracteres de control. Si la CURP o el RFC ya pertenecen a otro expediente se responde un mensaje genérico (no confirma qué coincidió) y el intento queda auditado aunque la petición falle.

**Qué falta para enviar** (`missing`): `CONSENT_KYC_IDENTITY`, `CONSENT_BIOMETRIC_SELFIE`, `EMAIL_NOT_VERIFIED`, `PERSONAL_DATA`, `ADDRESS`, `DOC_IDENTITY`, `DOC_IDENTITY_EXPIRED`, `DOC_ADDRESS_PROOF`, `DOC_ADDRESS_PROOF_TOO_OLD` (más de 90 días), `DOC_ADDRESS_PROOF_OTHER_ADDRESS` (el comprobante es de otro domicilio), `DOC_SELFIE`, `DOC_FILES_PENDING_SCAN`. Un documento solo cuenta si todos sus lados tienen escaneo `CLEAN`.

**Qué se puede editar según el estado:**

| Estado | Datos personales | Domicilio | Documentos |
| --- | --- | --- | --- |
| `NOT_STARTED`, `PENDING_DOCUMENTS` | Sí | Sí | Sí |
| `CORRECTION_REQUIRED` con `CORRECCION_DATOS_PERSONALES` | Sí | Sí | Sí |
| `CORRECTION_REQUIRED` con `CORRECCION_DOMICILIO` | No | Sí | Sí |
| `CORRECTION_REQUIRED` con `CORRECCION_DOCUMENTOS` | No | No | Sí |
| `EXPIRED` (revalidación) | No | Sí | Sí |
| `SUBMITTED`, `UNDER_REVIEW`, `APPROVED`, `REJECTED`, `SUSPENDED` | No | No | No |

**Versiones del domicilio:** si el domicilio ya se envió a revisión o ya tiene un comprobante ligado, cambiarlo crea una versión nueva y el comprobante anterior deja de contar. Así un recibo de la dirección vieja nunca "valida" una dirección nueva.

### Catálogos (cualquier usuario autenticado)

| Ruta | Uso |
| --- | --- |
| `GET /api/v1/kyc/catalogs/privacy-notice` | Versión vigente del aviso y sus finalidades |
| `GET /api/v1/kyc/catalogs/document-types` | Tipos de documento activos y qué exige cada uno |
| `GET /api/v1/kyc/catalogs/states` y `/states/{id}/municipalities` | Estados INEGI y sus municipios |
| `GET /api/v1/kyc/catalogs/postal-codes/{cp}` | Colonias de un CP (autocompletar el formulario); 404 si no existe, 422 si no son 5 dígitos |

### Administración

Requieren JWT de un usuario `admin` **y** el permiso indicado. Un permiso faltante responde 403 `PERMISSION_DENIED` y se audita.

| Método y ruta | Permiso | Qué devuelve |
| --- | --- | --- |
| `GET /api/v1/admin/kyc/cases?status=&assigned=any\|me\|unassigned&limit=&cursor=` | `kyc:queue:read` | Cola en orden de llegada, **sin** CURP, RFC, correo ni apellidos completos ("Gloria H."). Paginación por cursor; respeta las regiones del revisor |
| `GET /api/v1/admin/kyc/cases/{case_id}` | `kyc:queue:read` + (`kyc:case:read_any`, o `kyc:case:read_assigned` y el caso asignado a él) | Expediente completo con CURP y RFC descifrados, historial y `version`. Cada apertura se audita. Sin acceso: **404** idéntico al de un caso inexistente |
| `GET /api/v1/admin/users/{user_id}/roles` | `admin:roles:manage` | Roles y permisos efectivos |
| `PUT /api/v1/admin/users/{user_id}/roles` | `admin:roles:manage` | Reemplaza los roles. 403 `SELF_ROLE_CHANGE`, 422 `ROLE_CONFLICT`, 409 `LAST_SUPERADMIN`. Quitar privilegios cierra las sesiones del usuario |

**Roles y permisos** (`app/kyc/permissions.py`):

| Permiso | Revisor | Supervisor | Soporte | Superadmin |
| --- | --- | --- | --- | --- |
| Ver cola enmascarada | Sí | Sí | Sí | Sí |
| Tomar o liberar casos | Sí | Sí | No | No |
| Expediente completo | Solo asignados | Todos | No | No |
| Decidir documentos, aprobar, pedir corrección | Sí | Sí | No | No |
| Rechazo definitivo, suspender, reactivar | No | Sí | No | No |
| Consultar auditoría | No | Sí | No | Sí |
| Catálogos, retención, roles de administradores | No | No | No | Sí |
| Ver y desactivar usuarios | No | No | Solo ver | Sí |

Separación de funciones: `SUPERADMIN` no se combina con `KYC_REVIEWER` ni `KYC_SUPERVISOR`, y nadie modifica sus propios roles.

### Auditoría de intentos denegados

Un acceso denegado termina en error y hace rollback. Para que no se pierda, se escribe con `write_audit_detached` en una transacción propia: permisos insuficientes (`admin.permission.denied`), expediente ajeno (`kyc.case.access_denied`), CURP o RFC duplicado (`kyc.identity.duplicate_detected`) y autoedición de roles (`admin.roles.self_change_denied`).

### Antes de usar en producción

- **Verificación de correo:** `KYC_REQUIRE_VERIFIED_EMAIL=true` (por defecto) impide enviar el expediente hasta que `users.is_email_verified` sea verdadero. El flujo de verificación de correo aún no existe; mientras tanto, nadie podrá enviar su expediente en un entorno real.
- **IP real detrás de Nginx:** correr uvicorn con `--proxy-headers --forwarded-allow-ips=<IP de Nginx>`; si no, la auditoría registrará la IP del proxy.
- **Límite de peticiones** por IP y por usuario (por ejemplo, en el catálogo de códigos postales y en `personal-data`) queda para la fase de infraestructura (Nginx + Redis).
- **Texto del aviso de privacidad:** el endpoint publica versión y finalidades; el texto íntegro lo redacta el área legal.


## 9. KYC Fase 3: documentos y sistema de protección de datos

### 9.1 Clasificación de datos (`app/security/classification.py`)

| Nivel | Ejemplos | Controles |
| --- | --- | --- |
| Público | Nombre visible del técnico, calificación, categorías | Ninguno especial |
| Interno | Estado de órdenes, estado KYC | Solo usuarios autenticados con rol |
| Sensible | Correo, teléfono, nombre legal, fecha de nacimiento, domicilio, CURP, RFC | Cifrado o acceso restringido, enmascarado por defecto, lectura auditada, prohibido en logs |
| Altamente sensible | Documentos KYC, número de INE/pasaporte, llaves, contraseñas, CLABE, tarjetas | Cifrado en la aplicación + en el almacenamiento, acceso por asignación, auditoría de cada vista. CLABE y tarjetas **no se almacenan** (Stripe) |

Una prueba recorre el esquema real y falla si aparece una columna `*_enc` no declarada, o una columna llamada `curp`, `rfc`, `clabe`, `card_number`, `cvv`, `password`, etc.

### 9.2 Cifrado: jerarquía de llaves (envelope encryption)

```
KEK (KMS o variable de entorno, versionada: key_id)   ← nunca está en el código ni en la base
 └─ DEK por expediente (kyc_profiles.data_key_enc, AES-256-GCM)
     ├─ CURP, RFC, número de documento   (AAD = tabla + id de fila + campo)
     └─ FEK por archivo (kyc_document_files.file_key_enc)
         └─ bytes del documento y su vista previa en el bucket (AAD = id de archivo + variante)
Búsqueda de duplicados: HMAC-SHA256 (índice ciego) con una llave separada.
```

- Un valor cifrado copiado a otra fila, a otro campo o alterado en un bit **no descifra** (GCM + AAD).
- En S3 cada objeto además va con SSE-KMS; el bucket debe tener *Block Public Access*, versionado y política que rechace `PutObject` sin `aws:kms`.
- `encryption_keys_metadata` guarda solo id, estado (`ACTIVE`, `DECRYPT_ONLY`, `REVOKED`), proveedor, referencia KMS y **huella** (HMAC de la llave), nunca la llave. Al arrancar, el worker verifica que la llave configurada coincida con la registrada y no esté revocada.

### 9.3 Rotación y revocación de llaves (`python -m scripts.rotate_keys`)

1. Generar la llave nueva y configurarla como activa, dejando la anterior para descifrar: `KYC_MASTER_KEY_ID=2`, `KYC_MASTER_KEY=<nueva>`, `KYC_PREVIOUS_MASTER_KEYS="1:<anterior>"`.
2. `activate`: la 2 pasa a `ACTIVE` y la 1 a `DECRYPT_ONLY`. Todo lo viejo se sigue leyendo; lo nuevo se cifra con la 2.
3. `rewrap`: re-envuelve cada DEK con la llave 2, por lotes, reanudable e idempotente. **Ni los campos ni los archivos se re-cifran**: solo cambian unos bytes por expediente.
4. `revoke 1 --reason "..."`: se niega mientras quede un expediente con la llave 1.
5. Quitar la llave 1 de la configuración y destruirla en el KMS.

Otros casos: `rekey-profile <id>` si se sospecha que la DEK de un expediente se filtró (DEK nueva; se re-cifran CURP, RFC, números y FEK; los archivos no se tocan). `reindex-blind` para rotar la llave del índice ciego (en ventana de mantenimiento). Si una KEK se compromete, los pasos 1-5 se hacen de inmediato.

### 9.4 Documentos: subida → cuarentena → antivirus → bucket limpio

1. **API** (rápido): tamaño (413), tipo real por bytes mágicos (415), extensión y Content-Type coherentes con el contenido (415), dimensiones declaradas (bombas de descompresión: 413), mínimo 400 px, cuota diaria (429). El archivo se cifra con su FEK y va al bucket de **cuarentena**. Nunca se confía en la extensión.
2. **Worker** (proceso aparte, sin Internet, sin acceso a la API): descifra en memoria, ClamAV por INSTREAM (si está caído, **falla cerrado** y reintenta; tras `KYC_MAX_SCAN_ATTEMPTS` el archivo queda en error), re-codifica imágenes a JPEG **sin EXIF/GPS** ni bytes pegados al final, rechaza PDF con JavaScript, formularios, adjuntos, acciones de lanzamiento, cifrado o demasiadas páginas (incluso ofuscados con `#xx`), convierte el PDF a imagen para el revisor. Si detecta el mismo archivo o el mismo número de documento en otro expediente, lo marca como riesgo para el revisor.
3. Infectado o inválido: el objeto se borra, la FEK se destruye y se notifica al técnico por outbox.

### 9.5 Endpoints de documentos

| Método y ruta | Quién | Notas |
| --- | --- | --- |
| `POST /api/v1/technicians/me/kyc/documents` | Técnico | `type_code`, número (se valida el formato, se cifra y se devuelve enmascarado), fechas, consentimientos específicos |
| `PUT /api/v1/technicians/me/kyc/documents/{id}/files/{side}` | Técnico | multipart `file`; reemplazar un lado purga el anterior |
| `DELETE /api/v1/technicians/me/kyc/documents/{id}` | Técnico | Solo si el expediente es editable; borra objetos y llaves |
| `GET /api/v1/technicians/me/kyc/documents/{id}/files/{file_id}/preview` | Técnico | Su propia vista previa, con marca de agua; ajeno = 404 |
| `GET /api/v1/admin/kyc/cases/{c}/documents/{d}/files/{f}/content` | Revisor asignado / supervisor | Imagen con marca de agua (quién y cuándo), `no-store`, CSP sandbox; límite `KYC_FILE_VIEWS_PER_HOUR` con alerta; cada vista auditada |
| `POST .../files/{f}/view-ticket` | Revisor asignado / supervisor | URL de un solo uso, 60 s, para un `<img>` (no se pone el JWT en la URL) |
| `GET /api/v1/kyc/file-views/{ticket}` | Portador del ticket | Se quema al primer uso; al canjear se vuelven a verificar permisos; falso, vencido o usado = 404 |
| `GET /api/v1/admin/audit-logs` y `/audit-logs/integrity` | `audit:read` | Consultar la bitácora también se audita; verificación de la cadena de hashes |

No existen URLs públicas ni prefirmadas: los objetos están cifrados por la aplicación, así que una URL al bucket solo entregaría texto cifrado. Soporte, superadmin y finanzas no ven documentos.

### 9.6 Transporte, logs y producción

- `deploy/nginx/nginx.conf`: TLS 1.2/1.3, HTTP→HTTPS 301, HSTS de 2 años, `client_max_body_size 11m`, límites por IP en login y subidas, sin servir archivos, y log de accesos que **reemplaza el ticket** y la query string.
- La API en producción responde 400 `HTTPS_REQUIRED` si la petición no llegó por HTTPS (segunda barrera) y agrega HSTS.
- `log_sanitizer` enmascara CLABE (`**************4567`), tarjetas (`****1111`), CURP, RFC, JWT, `Bearer`, `password=`/`token=`, llaves `sk_`/`whsec_` y tickets, incluso en trazas de excepciones.
- La app no arranca en producción sin `STORAGE_BACKEND=s3` + `S3_KMS_KEY_ID`, `KYC_SCANNER=clamd` y `BCRYPT_ROUNDS>=12`; los tres secretos deben ser distintos.

### 9.7 Datos bancarios y pagos

No hay tabla `encrypted_bank_accounts`: la CLABE la captura y custodia Stripe (onboarding de Connect) y nosotros guardamos solo la referencia de la cuenta (`acct_...`). Las tarjetas nunca tocan nuestros servidores (componente de Stripe, PCI SAQ A). Es la forma de cumplir "nunca almacenar tarjetas ni información bancaria completa" sin cargar con esa custodia.

### 9.8 Cobertura del anexo

| Pedido del anexo | Dónde |
| --- | --- |
| Clasificación de datos | 9.1, `classification.py` + prueba de esquema |
| HTTPS/TLS, HSTS, redirección | `nginx.conf`, middleware de `main.py` |
| Cifrado en base de datos y de documentos | 9.2, `encryption_service.py`, `crypto.py` |
| Gestión, rotación y revocación de llaves | 9.3, `scripts/rotate_keys.py`, `encryption_keys_metadata` |
| Logs sin datos sensibles | `log_sanitizer.py` |
| RBAC (cliente, técnico, admin, soporte, finanzas) | `permissions.py`, `validate_access`, `access.py` |
| Enmascarado | `mask_sensitive_data` |
| Tablas pedidas | `users`, `technician_profiles`, `kyc_profiles` (datos sensibles), `kyc_documents` + `kyc_document_files` (documentos cifrados), `encryption_keys_metadata`, `audit_logs` (auditoría de seguridad). Cuentas bancarias: 9.7 |
| Pruebas de seguridad | `tests/test_data_protection.py`, `tests/test_kyc_documents.py`, `tests/test_kyc_documents_admin.py` |
| Privacidad (LFPDPPP) | Consentimientos por finalidad (incluye biométrico), aviso versionado, borrado criptográfico con retención legal, acceso mínimo auditado |

### 9.9 Limitaciones conocidas

- ClamAV se probó con un servidor falso que implementa el protocolo INSTREAM; S3 con `botocore.Stubber`. Antes de producción, una prueba de humo contra ClamAV y un bucket reales.
- El worker debe correr en un contenedor separado, sin salida a Internet y con permisos solo sobre los dos buckets y la base.
- Si se cambia a KMS real, falta un `KeyProvider` de AWS KMS (la interfaz ya está: `wrap`, `unwrap`, `active_key_id`, `fingerprints`).
- El job de retención que llama al borrado criptográfico llega en la Fase 5.


## 10. Fase 4: decisiones del revisor, órdenes de servicio y calificaciones verificadas

### 10.1 Arquitectura

```
Cliente (Flutter) ──► /orders ──► orders/service ──► orders/state_machine ──► service_orders (+ triggers)
                                        │                                         │
Técnico APROBADO ──► accept / schedule / start / finish                     order_status_history (solo inserción)
                                        │
Proveedor de pagos ──► webhook verificado ──► payments/service ──► payments (+ trigger) ──► orden PAID → READY_FOR_REVIEW
                                                                                                │
Cliente ──► POST /reviews ──► reviews/service ── elegibilidad ── antifraude ── firma ──► reviews (+ triggers)
                                   │                                                     review_ratings / review_audit_logs
                                   └── reputation.recompute ──► technician_reputation (+ campos públicos del perfil)
Moderación ──► /admin/reviews ──► moderate / resolve_report ──► review_audit_logs + audit_logs
Revisor KYC ──► /admin/kyc/cases/{id}/claim | decision ──► kyc/decisions ──► kyc state machine
worker/jobs.py ──► casos abandonados, KYC vencidos, aprobación automática 72 h, solicitudes viejas
```

Cada regla crítica vive en dos lugares: la aplicación (mensaje claro, código estable) y un trigger de PostgreSQL (última barrera ante un error de código, un script o alguien con acceso a la base). Una prueba verifica que las tablas de transiciones de la app y de los triggers sean idénticas.

### 10.2 Decisiones del revisor KYC

| Método y ruta | Permiso | Validaciones y errores |
| --- | --- | --- |
| `POST /api/v1/admin/kyc/cases/{id}/claim` | `kyc:case:claim` | Solo casos `SUBMITTED` (409 `KYC_CASE_NOT_CLAIMABLE`), dentro de su región (404), máximo `KYC_MAX_ACTIVE_CLAIMS` a la vez (409 `KYC_TOO_MANY_CLAIMS`) |
| `POST .../{id}/release` | `kyc:case:claim` | Solo quien lo tiene o un supervisor; `expected_version` |
| `PUT .../{id}/documents/{doc}/decision` | `kyc:document:decide` | Caso en revisión y asignado; rechazo con motivo del catálogo de alcance DOCUMENT (422 `KYC_REASON_INVALID`, `KYC_NOTE_REQUIRED`); no se aprueba un documento sin escaneo limpio (409) |
| `POST .../{id}/decision` | aprobar: `kyc:approve`; corrección: `kyc:request_correction`; rechazo definitivo: `kyc:reject_final` (solo supervisor) | Aprobar exige todos los documentos decididos (409 `KYC_DOCUMENTS_UNDECIDED`) y cada categoría obligatoria aprobada y vigente (409 `KYC_APPROVAL_BLOCKED` con la lista). Con señales de riesgo (mismo número o archivo en otro expediente) solo aprueba un supervisor (403 `KYC_SUPERVISOR_REQUIRED`). Versión vieja: 409 `KYC_STALE_VERSION` |
| `POST .../{id}/suspend` | `kyc:suspend` (supervisor) | Motivo de alcance SUSPENSION con nota. Las órdenes aún no iniciadas del técnico vuelven a la bolsa y sus reservas directas se abren a otros técnicos |
| `POST .../{id}/reinstate` | `kyc:reinstate` (supervisor) | Abre un ciclo de revisión nuevo; vuelve a recibir órdenes solo cuando se aprueba |

Un técnico no aprobado nunca recibe órdenes: `VerifiedTechnician` en las rutas (con `FOR SHARE` sobre el expediente), la validación del servicio y el trigger `order_technician_guard`, que rechaza asignar, agendar o iniciar con un técnico sin KYC `APPROVED` o desactivado, incluso por SQL directo. Al expirar la aprobación (identificación vencida o revalidación cumplida), `worker/jobs.py` pasa el expediente a `EXPIRED` y le quita sus órdenes no iniciadas.

### 10.3 Estados de la orden y cuáles permiten calificar

```
REQUESTED → ACCEPTED → SCHEDULED → IN_PROGRESS → AWAITING_APPROVAL → COMPLETED → PAID → READY_FOR_REVIEW → REVIEWED
   │           │           │            │                 │               │               │                 │
   └ CANCELLED ┴ CANCELLED ┴ FAILED     └ DISPUTED        └ DISPUTED      ├ FAILED        ├ DISPUTED        ├ DISPUTED
     (o caduca)  (técnico se retira → REQUESTED)                          └ DISPUTED      └ REFUNDED        └ REFUNDED
```

| Estado | ¿Calificar? | Motivo |
| --- | --- | --- |
| REQUESTED … AWAITING_APPROVAL | No | El servicio no ha terminado (`REVIEW_ORDER_NOT_COMPLETED`) |
| COMPLETED, PAID | No | El pago aún no está confirmado por el proveedor (`REVIEW_PAYMENT_NOT_CONFIRMED`) |
| **READY_FOR_REVIEW** | **Sí** | Completada + pago confirmado, dentro de `REVIEW_WINDOW_DAYS` (30) desde el pago |
| REVIEWED | No | Ya tiene su calificación (una por orden) |
| DISPUTED | No, por ahora | Congelada hasta que finanzas resuelva (`REVIEW_ORDER_DISPUTED`) |
| CANCELLED, FAILED, REFUNDED | Nunca | No hubo servicio pagado (`REVIEW_ORDER_NOT_REVIEWABLE`) |

**Integración con pagos** (`app/payments/service.py`): "pago confirmado" = `CAPTURED`, `RELEASED` o `PARTIALLY_REFUNDED`, y solo lo fija el webhook del proveedor; no existe ningún endpoint que marque una orden como pagada. Pago fallido → orden `FAILED`. Reembolso total → orden `REFUNDED` y su reseña se oculta con peso 0 (deja de contar). Reembolso parcial → la orden sigue calificable (el servicio sí ocurrió). Disputa activa → bloquea calificar y editar. Si el proveedor captura antes de la aprobación del cliente, la orden avanza en cuanto el cliente aprueba. El técnico inicia el trabajo solo con el pago autorizado.

### 10.4 Endpoints de órdenes

| Método y ruta | Quién | Notas |
| --- | --- | --- |
| `POST /api/v1/orders` | Cliente | Máximo `ORDER_MAX_OPEN_PER_CLIENT` abiertas (429). Reserva directa opcional (`requested_technician_id`) |
| `GET /api/v1/orders/{id}` | Cliente dueño o técnico asignado | Cualquier otro: 404 |
| `POST /orders/{id}/cancel` · `/approve` · `/dispute` | Cliente | Disputa hasta `ORDER_DISPUTE_WINDOW_DAYS` después del pago |
| `GET /api/v1/technicians/me/jobs-feed` | Técnico **aprobado** | Solicitudes de sus categorías, sin dirección ni datos del cliente |
| `POST /orders/{id}/accept` · `/schedule` · `/start` | Técnico **aprobado** | Aceptar usa `FOR UPDATE`: dos técnicos no ganan la misma orden |
| `POST /orders/{id}/withdraw` · `/finish` | Técnico asignado | Retirarse cuenta en su confiabilidad |
| `GET /api/v1/admin/orders` y `/{id}` | `orders:read` (soporte, finanzas) | |
| `POST /api/v1/admin/orders/{id}/dispute-resolution` | `orders:dispute:resolve` (finanzas) | `RELEASE`, `PARTIAL_REFUND` (menor a lo que queda por reembolsar) o `FULL_REFUND`; auditado |

### 10.5 Calificaciones: endpoints

| Método y ruta | Permiso | Request → Response | Errores |
| --- | --- | --- | --- |
| `POST /api/v1/reviews` | Cliente dueño de la orden | `{service_order_id, rating 1-5, comment?, ratings?: {QUALITY, PUNCTUALITY, COMMUNICATION, CLEANLINESS, PROFESSIONALISM}}` → 201 con `verification: "VERIFIED_SERVICE"` | 401; 403 (otro rol, `EMAIL_NOT_VERIFIED`); 404 `ORDER_NOT_FOUND` (ajena o inexistente); 409 `REVIEW_ALREADY_EXISTS` ("Esta orden ya tiene una calificación registrada"), `REVIEW_ORDER_NOT_COMPLETED`, `REVIEW_PAYMENT_NOT_CONFIRMED`, `REVIEW_ORDER_DISPUTED`, `REVIEW_ORDER_NOT_REVIEWABLE`, `REVIEW_WINDOW_CLOSED`; 422 campos extra, valores inválidos, `CONTENT_*`; 429 `REVIEW_RATE_LIMITED` |
| `GET /api/v1/orders/{id}/review-eligibility` | Cliente dueño | → `{can_review, reason_code, message, review_deadline}` | 404 |
| `PUT /api/v1/reviews/{id}` | Autor | `{rating?, comment?, ratings?, reason}` → 200 | 404 (ajena); 409 `REVIEW_EDIT_WINDOW_CLOSED` (24 h), `REVIEW_EDIT_LIMIT` (3), `REVIEW_LOCKED`, `REVIEW_FROZEN` (disputa o reembolso); 422 sin motivo |
| `POST /api/v1/reviews/{id}/reply` | Técnico calificado | `{reply}` → 200 (una respuesta) | 404; 409 `REVIEW_ALREADY_REPLIED`; 422 lenguaje ofensivo |
| `POST /api/v1/reviews/{id}/report` | Técnico calificado o clientes (no el autor) | `{reason: OFFENSIVE\|FALSE\|SPAM\|NOT_RELATED\|OTHER, note?}` → 201 | 404; 409 `REPORT_ALREADY_EXISTS`; 429 |
| `GET /api/v1/technicians/{id}/reviews` | Usuario autenticado | → resumen (promedio, opiniones verificadas, servicios completados, promedio por categoría, puntaje, insignia) + reseñas publicadas (nombre como "Gloria H.", sin IDs) con cursor | 404 |
| `GET /api/v1/clients/me/reviews` · `/technicians/me/reviews` | Cliente / técnico | Sus reseñas | |
| `GET /api/v1/admin/reviews` | `reviews:read` | Cola filtrable (estado, reportes abiertos, técnico), con señales y peso | 403 |
| `GET /api/v1/admin/reviews/{id}` | `reviews:read` | Detalle: reportes, historial completo, `integrity_ok` | |
| `POST /api/v1/admin/reviews/{id}/moderation` | ocultar: `reviews:moderate`; publicar o decidir peso: `reviews:publish`; eliminar: `reviews:remove` | `{action: PUBLISH\|HIDE\|REMOVE, reason, note, count_in_reputation}` | 403; 409 `REVIEW_ORDER_REFUNDED`, `REVIEW_ALREADY_REMOVED`; 422 `MODERATION_NOTE_REQUIRED` |
| `POST /api/v1/admin/review-reports/{id}/resolution` | `reviews:moderate` (mantener una reseña oculta: `reviews:publish`) | `{resolution: KEEP\|HIDE\|REMOVE, note}` | 403, 409 |
| `GET /api/v1/admin/reviews/integrity` | `reviews:read` | Reseñas cuya firma no coincide (alteradas en la base) | |

**Permisos por rol:** cliente califica solo sus órdenes; técnico ve y responde, nunca edita ni elimina; soporte ve y **oculta**; moderación de contenido publica, libera retenidas y **elimina**; finanzas resuelve disputas; superadmin solo lee la cola.

### 10.6 Defensas contra manipulación

- **En la API:** schemas con `extra="forbid"` (enviar `status`, `verification`, `weight`, `client_id`… da 422); estrellas como enteros estrictos (`"5"` o `4.5` dan 422); `FOR UPDATE` sobre la orden al calificar (dos peticiones simultáneas no crean dos reseñas).
- **En la base:** `UNIQUE(service_order_id)`; CHECK `verification = 'VERIFIED_SERVICE'`, `rating BETWEEN 1 AND 5`, `client_id <> technician_id`; trigger de inserción (orden del mismo cliente y técnico, `READY_FOR_REVIEW`, pago confirmado); trigger de actualización (orden, partes, fechas y periodo de edición inmutables; estrellas y comentario solo dentro del periodo y contando la edición); sin `DELETE` en reseñas, calificaciones por categoría ni bitácoras.
- **Firma HMAC por reseña** (`INTEGRITY_KEY`): cubre estrellas, comentario, categorías, estado, peso, motivo de moderación, señales y ediciones. Un cambio hecho por SQL sin la llave aparece en `/admin/reviews/integrity`.
- **Texto:** solo texto plano (se rechaza HTML), sin caracteres de control ni invisibles, sin teléfonos, correos ni enlaces, longitud máxima. El lenguaje ofensivo no se rechaza: se retiene para moderación (normaliza acentos, "leet" y letras repetidas).

### 10.7 Antifraude

| Señal | Efecto |
| --- | --- |
| Cliente y técnico usaron el mismo dispositivo (`X-Device-Id`, seudonimizado) | Retenida: no pública, peso 0, hasta que moderación decida |
| La misma tarjeta (huella del proveedor) pagó en otra cuenta cliente que calificó a este técnico | Retenida |
| Lenguaje ofensivo | Retenida |
| Misma red en 30 días · cuenta con menos de 7 días · orden menor a `REVIEW_MIN_ORDER_AMOUNT` · 5+ reseñas al técnico en 24 h | Publicada con peso 0.5 (dos o más señales: 0.25) |

Además: una reseña por orden, correo verificado, límite diario por cliente, reportes solo de clientes creíbles para el ocultamiento automático (correo verificado, 7 días de antigüedad y un servicio pagado; tres clientes distintos), y los reportes del propio técnico no cuentan para ocultar. IP y dispositivo se guardan como HMAC (nunca en claro). Las señales nunca se muestran al cliente ni al técnico.

### 10.8 Reputación (`app/reviews/reputation.py`)

1. **Calificación bayesiana:** `R = (C·m + Σ W_c·r̄_c) / (C + Σ W_c)` con `m = 4.0` y `C = 5`. Por reseña, `w = peso antifraude × 0.5^(edad/365 días)`; por cliente, sus reseñas al mismo técnico se promedian y su peso total se topa en 1. Una sola reseña de 5 da ≈ 4.17, no 5.0; un cliente con muchas órdenes pequeñas no infla la reputación.
2. **Confiabilidad:** `completados / (completados + retiros del técnico + disputas perdidas)`.
3. **Puntaje 0-100** (para ordenar búsquedas): `100 × [0.60·(R−1)/4 + 0.20·confiabilidad + 0.12·experiencia + 0.08·antigüedad]`, menos 10 por cada reseña positiva eliminada u ocultada por fraude en 180 días (máximo 30). Experiencia = `log(1+servicios)/log(101)`; antigüedad = meses aprobado / 24.

Lo que ve el cliente es simple y verificable: "4.8 ★ · 115 opiniones verificadas · 120 servicios completados" y el promedio por categoría. Los campos del perfil (`rating_avg`, `rating_count`, `jobs_completed`) solo los escribe el sistema.

### 10.9 Auditoría

- `review_audit_logs` (solo inserción): creación, retención, edición (valor anterior, nuevo, quién, cuándo, motivo), respuesta, reporte, ocultamiento automático, moderación, ocultamiento por reembolso.
- `audit_logs` (cadena de hashes): decisiones KYC, moderación de reseñas (`review.moderated.*`), reportes descartados, resolución de disputas, accesos denegados.
- `order_status_history` (solo inserción): cada cambio de estado de la orden con actor y motivo.

### 10.10 Panel administrativo

Rutas listas para el panel: cola de expedientes y decisiones KYC (10.2), cola de moderación con filtros y señales, detalle de reseña con historial y verificación de firma, resolución de reportes, búsqueda de órdenes y resolución de disputas, bitácora de auditoría con verificación de integridad (Fase 3).

### 10.11 Pruebas

`tests/test_kyc_decisions.py`, `tests/test_orders.py` y `tests/test_reviews.py` (129 pruebas): caso correcto; orden cancelada, pendiente, fallida, en disputa o reembolsada; pago pendiente; orden ajena; segunda calificación; campos y valores manipulados en la API; manipulación directa en la base (inserción sin orden válida, cambio de estrellas, borrado, alteración detectada por la firma); usuario no autenticado; técnico intentando autocalificarse y con cuenta cliente en su mismo teléfono; misma tarjeta en varias cuentas; edición y su bitácora; reportes y ocultamiento; eliminación administrativa auditada; separación de funciones; reputación. Una revisión independiente encontró seis fallas (reseña de orden reembolsada republicable, soporte revirtiendo a moderación, edición que deshacía el peso fijado por un moderador, orden atorada con captura anticipada, plazo para calificar sin fecha tras una disputa y ocultamiento de reseñas con cuentas recién creadas). Las seis se corrigieron y cada una tiene su prueba de regresión.

### 10.12 Limitaciones conocidas

- **Webhooks del proveedor:** las funciones de `app/payments/service.py` ya aplican los efectos; falta el endpoint que verifique la firma de Stripe y deduplique por id de evento (fase de pagos).
- **Precio:** lo propone el técnico al aceptar; la aceptación del cliente es la autorización del cobro en la pantalla del proveedor, que debe mostrar el monto. Si se quiere un paso explícito de "confirmar precio" en la app, se agrega un estado.
- **Dirección:** el técnico ve la dirección completa al aceptar. Retirarse repetidamente para obtener direcciones está penalizado en la reputación, pero no bloqueado; conviene revisar la frecuencia de retiros en monitoreo.
- **Límites por conteo** (reseñas al día, reportes, solicitudes abiertas, casos tomados): con peticiones en paralelo pueden excederse por una o dos unidades; el límite duro por IP está en Nginx.
- **`X-Device-Id`** lo envía la app: detecta el caso común (el mismo teléfono), no a alguien que lo falsifica. La huella de la tarjeta y el tope por cliente cubren ese caso.
- El autor ve si su reseña está `PENDING_MODERATION` (transparencia hacia el usuario, a cambio de revelar que se retuvo).

---

## 11. Pagos, Fase 1: modelo de datos, motor de comisiones y libro contable

Implementa la Fase 1 del documento "Módulo de pagos: Fase 0" con las decisiones del 23 de septiembre de 2026: **D1** Stripe, **D5** aprobación automática a las 72 h, **D6** precio sin IVA más IVA y retenciones con tasas configurables, **D7** autorizar cuando el técnico sale. Esta fase todavía **no habla con Stripe**: deja listas las tablas, las reglas y el cálculo sobre los que se montan las fases 2 a 7.

### 11.1 Qué cambió

- **Importes en centavos** (`BIGINT`): `payments.amount_cents`, `captured_cents`, `refunded_cents`. Nada de `float` ni de `Numeric` para dinero nuevo. El precio que acuerda el técnico (`service_orders.agreed_price`) se convierte a centavos de forma exacta; una fracción de centavo se rechaza en lugar de redondearse.
- **Estados del pago** del doc: `PENDING`, `REQUIRES_ACTION`, `PROCESSING`, `AUTHORIZED`, `PAID`, `FAILED`, `CANCELLED`, `PARTIALLY_REFUNDED`, `REFUNDED`, `DISPUTED`, `CHARGED_BACK`. `CAPTURED` y `RELEASED` se convierten en `PAID` (con cargos de destino no hay una "liberación" aparte: Stripe transfiere al capturar). "Pago confirmado" para calificar = `PAID` o `PARTIALLY_REFUNDED`.
- **Tipos de pago**: `SERVICE`, `ADJUSTMENT` (trabajo adicional) y `CANCELLATION_FEE`. Una orden puede tener varios pagos, pero solo un `SERVICE` activo (índice único parcial).
- **La comisión sale de reglas**, no de la categoría: `service_categories.commission_rate` se migró a reglas `CATEGORY` (solo las distintas de 15 %) y desapareció.
- **El reparto se congela** por pago en `commission_transactions`, con copia de la regla y de las tasas fiscales aplicadas.
- **Libro contable** de partida doble en `ledger_entries`.
- Tablas listas para las siguientes fases (sin lógica todavía): `technician_payment_accounts`, `payment_customers`, `payment_transactions`, `payment_refunds`, `payment_disputes`, `payouts`, `payment_webhook_events`, `idempotency_keys`, `cancellation_policies`. Ninguna tiene columnas para tarjeta, CVV, vencimiento ni CLABE.
- Los pagos existentes se convierten al migrar: conservan su reparto en un desglose `LEGACY`.

### 11.2 Cálculo (`app/payments/commission.py`)

El frontend solo manda el id de la orden. El motor calcula en el backend, en centavos enteros:

1. IVA del servicio sobre el precio acordado (sin IVA) → bruto = precio + IVA.
2. Comisión según la regla (half-up al centavo), con mínimo y máximo, y nunca mayor que el precio.
3. IVA de la comisión, retención de ISR y retención de IVA (half-up cada una).
4. El técnico recibe el remanente exacto.

Invariante (en código y en un `CHECK` de la base): técnico + comisión + IVA de la comisión + retenciones = bruto − descuento.

| Concepto (servicio de $1,000, comisión 15 %, técnico con RFC) | Centavos |
|---|---|
| Precio / IVA 16 % / cobro al cliente | 100 000 / 16 000 / **116 000** |
| Comisión / IVA de la comisión | 15 000 / 2 400 |
| Retención ISR 2.5 % / retención IVA 8 % | 2 500 / 8 000 |
| `application_fee_amount` (lo que retiene la plataforma) | **27 900** |
| Recibe el técnico | **88 100** |

Sin RFC las retenciones son 20 % de ISR y 16 % de IVA. Todas las tasas son variables de entorno (`TAX_IVA_BP`, `WITHHOLDING_*_BP`, en puntos base) y **debe validarlas tu contador**.

**Qué regla se aplica:** promoción → técnico → categoría → global; gana la primera vigente en la fecha de la cotización. Hay una regla `GLOBAL` inicial de 15 % con mínimo de $10.

**Reglas** (`create_rule` / `close_rule`, solo `FINANCE_ADMIN`, auditadas):
- No se editan ni se borran: una regla nueva cierra la anterior del mismo alcance, y los pagos viejos conservan la suya. La base lo impone (trigger) y no permite dos reglas del mismo alcance con fechas traslapadas (`EXCLUDE` con `btree_gist`).
- No pueden empezar en el pasado.
- **Se rechaza una regla que dé pérdida**: si en algún precio del rango admitido (`PAYMENT_MIN_SERVICE_CENTS` a `PAYMENT_MAX_SERVICE_CENTS`, de $50 a $500,000) la comisión no cubre el costo estimado de Stripe (3.6 % + $3 + IVA sobre el cobro; configurable), responde `COMMISSION_BELOW_PROVIDER_COST` con el precio donde falla. Como comisión y costo son lineales por tramos, basta revisar los extremos y los quiebres (mínimo, máximo, tope del precio).
- El técnico propone un precio fuera de ese rango → `422 ORDER_PRICE_OUT_OF_RANGE`.

**Descuentos**: en esta fase solo los que paga la plataforma. Bajan la comisión con su IVA exactamente en el monto del descuento, así que el técnico recibe lo mismo; no pueden superar la comisión con su IVA (`application_fee_amount` no puede ser negativa). Los que absorbe el técnico necesitan que él acepte la promoción y quedan para una fase posterior.

### 11.3 Máquina de estados del pago (`app/payments/state_machine.py`)

Las transiciones del doc, más tres que hacían falta: `REQUIRES_ACTION` → `PROCESSING` / `AUTHORIZED` / `FAILED` / `CANCELLED` (el cliente completa o abandona 3D Secure), `AUTHORIZED` → `FAILED` (falla la captura) y `DISPUTED` → `PARTIALLY_REFUNDED` (disputa ganada sobre un pago con reembolso parcial). Un trigger repite la tabla y además impide cambiar orden, pagador, tipo, monto, moneda o proveedor, y que lo capturado o lo reembolsado disminuya. Una prueba verifica que la tabla de la app y la del trigger sean idénticas. Repetir un evento no hace nada.

Al autorizar se guarda `capture_deadline` (`PAYMENT_AUTHORIZATION_VALID_HOURS`, 114 h por defecto: Visa sin el cliente presente). La salvaguarda que captura 24 h antes de que venza llega en la Fase 3.

### 11.4 Libro contable (`app/payments/ledger.py`)

Cada movimiento es un grupo de asientos que suma cero; la tabla es de solo inserción y un trigger diferido rechaza al confirmar cualquier grupo descuadrado, aunque se escriba por SQL directo. Signo: + abono, − cargo.

| Evento | Asientos |
|---|---|
| Cobro (`PAID`) | `CUSTOMER` −cobro · `TECHNICIAN_PAYABLE` +técnico · `PLATFORM_REVENUE` +comisión · `VAT_PAYABLE` +IVA de la comisión · `TAX_WITHHELD` +retenciones |
| Reembolso | `CUSTOMER` +monto · `REFUNDS` −monto |
| Contracargo perdido | `CUSTOMER` +pendiente · `REFUNDS` −pendiente (tipo `CHARGEBACK`) |

`REFUNDS` es provisional: quién absorbe cada reembolso (técnico, plataforma o ambos) se decide con la política de la Fase 5. `VAT_PAYABLE` se agregó a las cuentas del doc porque el IVA de la comisión no es ingreso de la plataforma.

### 11.5 Integración con órdenes y reseñas

- La intención de pago se crea al agendar (`SCHEDULED`) con el monto del motor; el técnico solo inicia con el pago `AUTHORIZED`; al cobrarse, la orden pasa a `PAID` → `READY_FOR_REVIEW`.
- Las reseñas preguntan a `payments.get_order_payment_summary(order_id)`, la única lectura que expone el módulo de pagos; el trigger de reseñas exige un pago `SERVICE` en `PAID` o `PARTIALLY_REFUNDED`.
- La señal antifraude de orden barata compara el precio sin IVA.
- Un contracargo (`DISPUTED`, `CHARGED_BACK`) todavía no mueve la orden ni afecta al técnico: eso es la Fase 5.

### 11.6 Pruebas

`tests/test_payments_commission.py` (cálculo puro: redondeo half-up, ejemplo del doc, sin RFC, mínimo, máximo y tope, 3,000 combinaciones aleatorias que siempre cuadran al centavo, descuentos, costo del proveedor y reglas que dan pérdida) y `tests/test_payments_db.py` (precedencia de reglas, cierre y programación, validaciones y permisos, auditoría, triggers de reglas, desglose y pago, un solo pago activo, asientos del cobro, reembolsos y contracargos, eventos repetidos).

### 11.7 Siguiente: Fase 2 de pagos

Hecha: ver la sección 12.

### 11.8 Limitaciones conocidas

- **Captura parcial** (cargo por visita, servicio parcial) y pagos `ADJUSTMENT`: el modelo los admite, la lógica llega en las fases 3 y 5. Hoy la captura es siempre por el total.
- **Comisión de Stripe real**: el costo del proveedor es una estimación configurable; el asiento `PROVIDER_FEES` se registra cuando la Fase 4 lea la transacción de saldo de Stripe.
- **Revisión fiscal y legal**: tasas de retención, quién emite el CFDI al cliente y si el modelo requiere licencia bajo la Ley Fintech están pendientes de validar con contador y abogado.
- El downgrade de la migración 0006 se niega si hay pagos (perdería el desglose).

---

## 12. Pagos, Fase 2: Stripe en modo prueba, cuenta del técnico y guardado de tarjeta

### 12.1 Configuración segura

| Variable | Para qué | Reglas que valida la app al arrancar |
|---|---|---|
| `PAYMENT_PROVIDER_BACKEND` | `stripe` o `fake` (en memoria, desarrollo y pruebas) | En producción solo `stripe` |
| `STRIPE_SECRET_KEY` | Clave del backend | Debe ser `sk_` o, mejor, restringida `rk_` con permisos mínimos |
| `STRIPE_PUBLISHABLE_KEY` | La única clave que va a la app | `pk_`; mismo modo (prueba/producción) que la secreta |
| `STRIPE_WEBHOOK_SECRET`, `STRIPE_CONNECT_WEBHOOK_SECRET` | Firma de los webhooks (Fase 4) | `whsec_`, distintos entre sí; obligatorios en producción |
| `STRIPE_API_VERSION` | Versión de la API fijada (`2026-08-26.dahlia`) | Un cambio de Stripe no altera el comportamiento sin un despliegue |
| `STRIPE_CONNECT_RETURN_URL` / `_REFRESH_URL` | Adónde vuelve el técnico desde el formulario de Stripe | HTTPS en producción |

La app **no arranca** si en producción las claves son de prueba (`sk_test_`/`pk_test_`) o si fuera de producción son `live`. La clave secreta nunca aparece en `repr`, logs ni respuestas; el filtro de logs enmascara claves (`sk_`, `rk_`, `whsec_`), `client_secret` de PaymentIntent/SetupIntent y enlaces de alta de `connect.stripe.com`.

**Claves restringidas sugeridas para `rk_`** (Fase 2): escritura en *Accounts*, *Account Links*, *Customers* y *SetupIntents*; lectura en *PaymentMethods*. Las fases 3 a 5 agregan *PaymentIntents*, *Refunds* y *Disputes*.

### 12.2 Capa PaymentProvider (`app/payments/providers/`)

- `base.py`: el contrato, con tipos propios (`AccountPrefill`, `AccountStatusInfo`, `OnboardingLink`, `SetupIntentInfo`, `SavedCard`) y `Capabilities` (el adaptador declara lo que soporta). Ningún objeto de Stripe sale del adaptador.
- `stripe_provider.py`: `StripePaymentProvider` sobre `stripe.StripeClient` (SDK oficial 15.x). Idempotency-Key determinista al crear la cuenta del técnico (`account-create:{técnico}`) y el cliente (`customer-create:{usuario}`). Los errores de Stripe se traducen a códigos propios sin su mensaje (puede traer datos personales o la clave):

| Error de Stripe | Código | HTTP |
|---|---|---|
| RateLimit / conexión | `PAYMENT_PROVIDER_UNAVAILABLE` (reintentable) | 503 |
| Autenticación / permisos | `PAYMENT_PROVIDER_MISCONFIGURED` (log de seguridad) | 503 |
| Solicitud inválida | `PAYMENT_PROVIDER_REJECTED` | 502 |
| Tarjeta rechazada | `PAYMENT_CARD_DECLINED` | 402 |
| Idempotencia con otro cuerpo | `PAYMENT_PROVIDER_IDEMPOTENCY` | 409 |

- `fake.py`: el mismo contrato en memoria, con utilidades para simular lo que pasa fuera de la app (el técnico completa el formulario, Stripe pide más datos o rechaza la cuenta).

### 12.3 Cuenta de pagos del técnico (`app/payments/accounts.py`)

| Método y ruta | Quién | Respuestas |
|---|---|---|
| `POST /api/v1/technicians/me/payment-account` | Técnico con KYC `APPROVED` | 201; 403 `KYC_NOT_APPROVED`; 409 `PAYMENT_ACCOUNT_EXISTS`; 503 si Stripe no responde (no queda nada a medias) |
| `GET /api/v1/technicians/me/payment-account` | Técnico | 200 (estado, pendientes, `can_receive_payments`, `in_review`) |
| `POST /api/v1/technicians/me/payment-account/onboarding-link` | Técnico con KYC `APPROVED` | 200 con URL de un solo uso; 404 sin cuenta; 409 `PAYMENT_ACCOUNT_DISABLED` |
| `POST /api/v1/technicians/me/payment-account/refresh` | Técnico | 200: vuelve a consultar a Stripe (máximo una vez cada 15 s); nunca recibe un estado |
| `POST /api/v1/admin/payment-accounts/{id}/name-review` | `KYC_SUPERVISOR` o `FINANCE_ADMIN` | Libera o rechaza una cuenta con nombre distinto al del KYC (auditado) |

Todos los cuerpos usan `extra="forbid"`: mandar `status`, `account_id` o cualquier campo da 422. Las respuestas no exponen el id de la cuenta en Stripe.

**Alta:** cuenta Express de México, persona física, con la capacidad `transfers`. Se precargan nombre legal, fecha de nacimiento, domicilio, correo y teléfono (solo en formato +52) del expediente KYC. **No se envían CURP ni RFC**: si Stripe los necesita, los pide en su formulario. Esta transferencia de datos a Stripe debe declararse en el aviso de privacidad. La CLABE la captura Stripe; nosotros no la vemos.

**Estados** (`ALLOWED_ACCOUNT_TRANSITIONS`, repetidos en un trigger de la migración 0007): `NOT_CREATED → ONBOARDING → PENDING_VERIFICATION → ENABLED ⇄ RESTRICTED`, y `DISABLED` cuando Stripe rechaza la cuenta. El estado se deriva de lo que reporta Stripe (`transfers` activa, `payouts_enabled`, requisitos pendientes, `disabled_reason`), nunca de la app. El trigger además impide borrar la fila, cambiar técnico o proveedor, o cambiar el id de la cuenta una vez asignado.

**Bloqueos de la plataforma** (independientes del estado en Stripe; una cuenta `ENABLED` pero bloqueada no recibe pagos nuevos):

| Motivo | Cuándo | Cómo se quita |
|---|---|---|
| `KYC_SUSPENDED` / `KYC_EXPIRED` | Al suspender o vencer el KYC | Solo al volver a aprobarse el KYC (reactivar no basta) |
| `NAME_MISMATCH` | El nombre en Stripe no coincide con el del KYC (se compara sin acentos ni mayúsculas; basta el apellido paterno) | Un supervisor lo revisa: lo libera o lo rechaza |
| `NAME_REJECTED` | El supervisor confirmó que no es el titular | No se quita automáticamente |

Una diferencia de nombre genera una alerta a supervisión (`payment_account.name_mismatch`); al técnico solo se le muestra "en revisión". Si Stripe no expone el nombre para ese tipo de cuenta, la comparación queda sin dato y no bloquea.

### 12.4 Tarjetas del cliente (`app/payments/customers.py`)

| Método y ruta | Quién | Respuesta |
|---|---|---|
| `POST /api/v1/clients/me/payment-methods/setup-intent` | Cliente | 201 `{client_secret, publishable_key}` |
| `GET /api/v1/clients/me/payment-methods` | Cliente | Marca, últimos 4 y vencimiento de sus tarjetas |

La app usa el `client_secret` con el componente oficial de Stripe (PaymentSheet en Flutter, Payment Element en web): la tarjeta va directo a Stripe y la plataforma queda en PCI SAQ A. El SetupIntent es `off_session` (se cobrará cuando el técnico salga, sin el cliente presente) y solo con tarjeta (decisión D3). Se crea un solo cliente en Stripe por usuario.

### 12.5 Pruebas

`tests/test_payments_provider.py` (configuración segura y producción, adaptador de Stripe con un cliente simulado que verifica los parámetros exactos y la idempotencia, traducción de errores sin filtrar datos, logs) y `tests/test_payments_accounts.py` (alta con y sin KYC, precarga sin CURP ni RFC, 409 y proveedor caído, campos colados, roles, estados según el proveedor, límite de consultas, nombre distinto y su revisión, bloqueo por suspensión y vencimiento del KYC, reaprobación por la API, trigger, tarjetas y aislamiento entre clientes).

**Prueba contra Stripe real (pendiente de tu lado):** este entorno no tiene salida a `api.stripe.com`. Con tu cuenta en modo prueba: pon `PAYMENT_PROVIDER_BACKEND=stripe` y tus claves `sk_test_`/`pk_test_` en `.env`, crea un técnico aprobado, llama a `POST /technicians/me/payment-account`, abre el enlace de `onboarding-link` y completa el formulario con los datos de prueba de Stripe; después `refresh` debe mostrar `ENABLED`.

### 12.6 Limitaciones conocidas

- **Regla crítica en órdenes:** hecha en la Fase 3 (sección 13.3).
- **Actualización automática:** el estado de la cuenta se actualiza al consultar (`refresh`); el webhook `account.updated` que lo hará solo llega en la Fase 4.
- La idempotencia de Stripe dura 24 h: un reintento de alta después de ese plazo, con la fila perdida, podría crear otra cuenta en Stripe (la base sigue teniendo una sola).
- El límite de SetupIntents por cliente lo da Nginx (por IP); no hay un conteo por usuario.

---

## 13. Pagos, Fase 3: autorización, captura, cargos de destino y regla crítica

### 13.1 Flujo del dinero

```
SCHEDULED ─ cliente: POST /orders/{id}/payment-method  (tarjeta guardada; Idempotency-Key)
    │
    ├─ técnico: POST /orders/{id}/depart  ("en camino", D7)
    │     └─► Stripe: PaymentIntent capture_method=manual, off_session, confirm,
    │           transfer_data[destination]=cuenta del técnico, application_fee_amount=comisión+IVA+retenciones
    │        ├─ requires_capture → AUTHORIZED: el técnico sale y puede iniciar
    │        ├─ rechazo          → FAILED: NO sale; la orden sigue agendada, pago nuevo, el cliente elige otra tarjeta
    │        └─ 3D Secure        → REQUIRES_ACTION: el cliente se autentica en la app y consulta (refresh)
    │
IN_PROGRESS → AWAITING_APPROVAL → COMPLETED (el cliente aprueba o pasan 72 h, D5)
    │
    └─ worker: payments.capture_due → Stripe capture (capture:{pago}) → PAID → READY_FOR_REVIEW
         Stripe transfiere al técnico en la captura: una sola vez, sin transferencias manuales.
```

La autorización se hace al salir, no al agendar, porque vence (unos 4 días y 18 horas con tarjeta guardada) y un servicio puede agendarse con semanas de anticipación. **Aprobar no depende de Stripe**: la orden queda `COMPLETED` y el worker captura; si Stripe no responde, se reintenta en la siguiente vuelta.

### 13.2 Endpoints nuevos

| Método y ruta | Quién | Respuestas |
|---|---|---|
| `POST /api/v1/orders/{id}/payment-method` | Cliente dueño | 200 con la vista del pago; `Idempotency-Key` obligatorio (422 `IDEMPOTENCY_KEY_REQUIRED`); la misma llave repite la respuesta (`Idempotent-Replayed: true`) y con otro cuerpo da 422 `IDEMPOTENCY_KEY_REUSED`; 422 `PAYMENT_METHOD_NOT_FOUND` si la tarjeta no es suya; 409 `PAYMENT_METHOD_LOCKED` si el cobro ya se procesó; 404 si la orden es ajena |
| `POST /api/v1/orders/{id}/depart` | Técnico asignado, KYC aprobado | 200 `{payment_status, can_start, failure_code}`; 409 `ORDER_PAYMENT_METHOD_MISSING` (y aviso al cliente), `PAYMENT_REQUIRES_ACTION`, `ORDER_NOT_SCHEDULED`; 403 `PAYMENT_ACCOUNT_NOT_ENABLED`; repetirlo no vuelve a cobrar |
| `GET /api/v1/orders/{id}/payment` | Cliente dueño o técnico asignado | El cliente ve total, precio, IVA, descuento y (solo en `REQUIRES_ACTION`) el `client_secret` para 3D Secure. El técnico ve comisión, retenciones y lo que recibe. Nadie más: 404 |
| `POST /api/v1/orders/{id}/payment/refresh` | Cliente dueño | Consulta el cobro en Stripe y aplica su estado; nunca recibe un estado |

El body de `payment-method` solo acepta `payment_method_id` (`extra="forbid"`): ningún monto, comisión ni cuenta viene de la app.

### 13.3 Regla crítica ampliada

Aceptar, agendar o recibir una reserva directa exige **KYC `APPROVED` y cuenta de pagos `ENABLED` sin bloqueo**. Se valida en tres capas: la ruta (`VerifiedTechnician`), el servicio (`PAYMENT_ACCOUNT_NOT_ENABLED`, 403) y el trigger `order_technician_guard` de la migración 0008, que la repite aunque se escriba por SQL directo. "En camino" vuelve a verificar la cuenta antes de autorizar. Iniciar no la exige, porque el cobro ya quedó autorizado con su cuenta destino.

Si la cuenta deja de poder cobrar (Stripe la restringe, se detecta un nombre distinto o un supervisor lo rechaza), el técnico **suelta en ese momento** sus órdenes no iniciadas: vuelven a la bolsa y sus reservas se anulan en Stripe. La suspensión o el vencimiento del KYC ya lo hacían.

### 13.4 Idempotencia en tres niveles

| Nivel | Cómo |
|---|---|
| Petición de la app | `Idempotency-Key` guardada con el hash del cuerpo y la respuesta, en la misma transacción que la operación (`app/payments/idempotency.py`); vence a las 24 h |
| Nuestra API hacia Stripe | `authorize:{pago}`, `capture:{pago}`, `cancel:{pago}`: un reintento de red no crea otro cobro ni otra captura |
| Base de datos | Un solo pago `SERVICE` activo por orden, `FOR UPDATE` sobre orden y pago, `SKIP LOCKED` en el worker |

### 13.5 Vencimiento de la autorización y worker

`python -m worker.jobs --loop --every 60` (recomendado cada minuto por la captura):

| Trabajo | Qué hace |
|---|---|
| `orders.auto_approve` | Aprobación automática a las 72 h (D5) |
| `payments.enforce_capture_deadline` | Si faltan menos de 24 h para que venza la autorización y el cliente no ha respondido, aprueba la orden (`AUTO_APPROVED_AUTH_EXPIRING`) para poder cobrar. Si el trabajo sigue en curso o hay una disputa, **no cobra**: alerta una vez a finanzas (`payment.authorization_expiring`), porque la decisión D4 sigue pendiente |
| `payments.capture_due` | Captura los pagos autorizados de órdenes `COMPLETED` |
| `payments.purge_idempotency_keys` | Borra las llaves vencidas |

Si al capturar Stripe responde que la autorización ya no existe, se consulta el estado real y se alerta a finanzas (`payment.authorization_expired`). Si el técnico se retira, el cliente cancela o se liberan las órdenes, la reserva se anula en Stripe; si Stripe no responde, el pago queda `CANCELLED` localmente (nunca se capturará), la reserva se libera sola al vencer, y queda un evento `payment.void_requested` para reintento.

### 13.6 Reconciliación

Todo cambio de estado que viene de Stripe (respuesta a una llamada o, en la Fase 4, un webhook) pasa por `payments.apply_provider_state`. Si llega un estado "adelantado" (p. ej. `PAID` sin haber visto `AUTHORIZED`), recorre las transiciones válidas intermedias; uno viejo que retrocedería se registra y se ignora.

### 13.7 Pruebas

`tests/test_payments_flow.py` (regla crítica en la API y en el trigger, cuenta bloqueada o restringida, idempotencia, tarjeta ajena, vistas por rol, autorización con la división exacta hacia el técnico, rechazo y nueva tarjeta, 3D Secure, captura única por el worker, Stripe caído, autorización vencida, aprobación automática, salvaguarda de 24 h con y sin disputa, anulación con y sin Stripe, eventos adelantados y viejos) y las pruebas del adaptador en `tests/test_payments_provider.py` (parámetros exactos del PaymentIntent, rechazos, autenticación, captura, anulación y traducción de estados). Los helpers de prueba ahora recorren el flujo real: el técnico aprobado tiene cuenta habilitada, el cliente elige tarjeta, el técnico sale y el worker captura.

### 13.8 Limitaciones y decisiones pendientes

- **D4 (reclamo abierto cuando la autorización está por vencer):** hoy se alerta a finanzas y no se cobra. Si decides "capturar y reembolsar después", es un cambio pequeño en `enforce_capture_deadline`.
- **Captura parcial** (cargo por visita, servicio parcial) y pagos `ADJUSTMENT`: Fase 5.
- **Webhooks:** hasta la Fase 4, los cambios que ocurren en Stripe sin una llamada nuestra (p. ej. el cliente completa 3D Secure) se ven al consultar (`refresh`) o en la siguiente acción.
- **OXXO y SPEI** quedan fuera (D3): solo tarjetas, que admiten captura manual.

---

## 14. Pagos, Fase 4: webhooks, worker y conciliación

### 14.1 Recepción (`app/api/routes/webhooks.py`)

| Ruta | Secreto | Eventos que se configuran en Stripe |
|---|---|---|
| `POST /api/v1/webhooks/stripe` | `STRIPE_WEBHOOK_SECRET` | `payment_intent.requires_action`, `.processing`, `.amount_capturable_updated`, `.succeeded`, `.payment_failed`, `.canceled`; `charge.refunded`, `refund.updated`, `refund.failed`, `charge.dispute.*` (se guardan para la Fase 5) |
| `POST /api/v1/webhooks/stripe-connect` | `STRIPE_CONNECT_WEBHOOK_SECRET` | `account.updated`, `account.application.deauthorized`, `payout.created`, `payout.paid`, `payout.failed` |

Sin JWT: se autentican con la firma `Stripe-Signature`.

1. Se lee el **cuerpo crudo** (la firma se calcula sobre los bytes exactos), con un tope de 512 KB (413 si se pasa).
2. Se verifica la firma con el secreto **de ese endpoint** y una tolerancia de **5 minutos** (bloquea replays). Firma inválida, ausente, de otro endpoint, vieja o sobre un cuerpo alterado → **400** `WEBHOOK_SIGNATURE_INVALID`, registro en el log de seguridad y nada más.
3. `INSERT ... ON CONFLICT (provider, provider_event_id) DO NOTHING`: un evento repetido responde 200 con `duplicate: true` sin reprocesarse.
4. **200 de inmediato**; el procesamiento lo hace el worker.

Del evento se guarda lo mínimo (id, tipo, id y tipo del objeto, cuenta conectada, modo): **nada** de correos, nombres ni datos de facturación que Stripe incluye en el objeto.

### 14.2 Procesamiento (`app/payments/webhooks.py`, trabajo `payments.process_webhooks`)

- Toma eventos pendientes con `FOR UPDATE SKIP LOCKED` (varias réplicas del worker no chocan).
- **No confía en el evento:** vuelve a consultar el objeto al proveedor y aplica ese estado. Un evento falsificado que pasara la firma, o uno viejo que llegara tarde, no puede dejar un estado incorrecto.
- Un evento cuyo modo (prueba/producción) no coincide con las claves se ignora y queda en el log de seguridad.

| Evento | Qué hace |
|---|---|
| `payment_intent.*` | Consulta el cobro y lo aplica con `apply_provider_state` (la misma vía que la respuesta de una llamada). Busca el pago por el id del cobro o por el `payment_id` que se guardó en su metadata al autorizar |
| `account.updated` | Sincroniza la cuenta del técnico (estado, requisitos, nombre) |
| `account.application.deauthorized` | Bloquea la cuenta (`PROVIDER_DEAUTHORIZED`) y el técnico suelta sus órdenes no iniciadas |
| `payout.*` | Consulta el depósito en la cuenta conectada y lo guarda en `payouts`; si falla (casi siempre una CLABE inválida), avisa al técnico |
| Reembolsos y disputas | Se guardan como `IGNORED` con `DEFERRED_PHASE_5`; una disputa o un reembolso hecho fuera de la app alertan a finanzas |

Cada evento corre en su propio savepoint. Si falla, suma un intento y se reintenta con espera creciente (1, 2, 4, 8 minutos… hasta 6 h). Al llegar a `WEBHOOK_MAX_ATTEMPTS` (8) pasa a `DEAD` y se alerta a finanzas (`payment.webhook_dead`). El error guardado es solo un código, nunca el mensaje.

Además, cada autorización, captura, anulación o rechazo queda en `payment_transactions` (solo inserción; uno por tipo y cobro).

### 14.3 Conciliación diaria (`app/payments/reconciliation.py`, trabajo `payments.reconcile`)

La red de seguridad por si un webhook nunca llega. Corre una vez cada `RECONCILIATION_INTERVAL_HOURS` (24) sobre los cobros de las últimas `RECONCILIATION_WINDOW_HOURS` (48) y todos los que siguen abiertos:

| Situación | Acción |
|---|---|
| Estado atrasado aquí (autorizado aquí, cobrado allá) | Se corrige por la vía normal (solo transiciones válidas) |
| Cobro autorizado en Stripe cuyo id no quedó guardado (caída a mitad de la llamada) | Se reconoce por la metadata y se corrige |
| Montos distintos | Alerta `AMOUNT_MISMATCH` |
| Estado que no es seguro corregir (cobrado aquí, anulado allá) | Alerta `STATUS_MISMATCH` |
| Cobro que existe solo en Stripe | Alerta `PROVIDER_ONLY` |
| Cuenta de técnico sin sincronizar en 24 h | Se vuelve a consultar |

Para Stripe, un cobro reembolsado o en disputa sigue "succeeded": eso se considera consistente y no genera alertas. Las alertas no se repiten para el mismo caso en 24 h. Cada corrida queda en `audit_logs` (`payment.reconciliation.run`) con sus conteos.

### 14.4 Anulaciones pendientes (trabajo `payments.retry_voids`)

Si Stripe no respondió al anular una reserva (Fase 3), el trabajo la reintenta hasta 8 veces.

### 14.5 Configurar los webhooks en Stripe (modo prueba)

1. En Stripe, en modo prueba: **Developers → Webhooks → Add endpoint**, con la URL `https://<tu-dominio>/api/v1/webhooks/stripe` y los eventos de la plataforma de la tabla 14.1. Copia su *Signing secret* a `STRIPE_WEBHOOK_SECRET`.
2. Agrega otro endpoint marcando **"Listen to events on Connected accounts"**, con la URL `.../webhooks/stripe-connect` y los eventos de Connect. Su secreto va en `STRIPE_CONNECT_WEBHOOK_SECRET` y debe ser distinto.
3. En desarrollo local, con Stripe CLI: `stripe listen --forward-to localhost:8000/api/v1/webhooks/stripe` (y `--forward-connect-to` para Connect); el CLI imprime el `whsec_` que va en `.env`.

### 14.6 Pruebas

`tests/test_payments_webhooks.py` (firmas reales calculadas como Stripe: válidas, falsas, sin firma, del otro endpoint, viejas y con cuerpo alterado; duplicados; tamaño; nada de datos personales guardados; cobro hecho fuera de la app; evento falso con firma válida que no cambia nada; 3D Secure completado por webhook; modo distinto; eventos diferidos; reintentos, espera y DEAD; cuentas, desautorización y depósitos; anulaciones pendientes; conciliación que corrige, alerta sin repetir, es consistente con reembolsos, corre una vez al día y sincroniza cuentas) y, en `tests/test_payments_provider.py`, la verificación de firmas del adaptador, los depósitos en la cuenta conectada y el listado de cobros.

### 14.7 Limitaciones conocidas

- **Reembolsos y disputas** (Fase 5): sus eventos se guardan y alertan, pero la lógica llega en la siguiente fase; después se pueden reprocesar los que quedaron con `DEFERRED_PHASE_5`.
- Los eventos `PROCESSED`/`IGNORED` no se borran todavía; conviene una política de retención (p. ej. 90 días) junto con las demás de la Fase 5 del KYC.
- El tope global contra inundación del endpoint de webhooks va en Nginx (por IP de Stripe), no por usuario.
