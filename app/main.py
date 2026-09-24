import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.api.routes.admin_documents import public_router as file_views_router
from app.api.routes.admin_documents import router as admin_documents_router
from app.api.routes.admin_kyc import router as admin_kyc_router
from app.api.routes.admin_kyc_decisions import router as admin_kyc_decisions_router
from app.api.routes.auth import router as auth_router
from app.api.routes.kyc_catalogs import router as kyc_catalogs_router
from app.api.routes import orders as orders_routes
from app.api.routes import payments as payments_routes
from app.api.routes import webhooks as webhooks_routes
from app.api.routes import reviews as reviews_routes
from app.api.routes.technician_kyc import router as technician_kyc_router
from app.api.routes.users import admin_router, client_router, me_router, technician_router
from app.core.config import get_settings
from app.core.errors import register_error_handlers
from app.security import log_sanitizer

settings = get_settings()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log_sanitizer.install()   # ningún log (incluidos los de acceso de uvicorn) sale con datos sensibles

app = FastAPI(
    title=settings.APP_NAME,
    version="0.1.0",
    # En producción no se expone la documentación interactiva.
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/openapi.json",
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,  # lista explícita, nunca "*" con credenciales
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # En producción TLS termina en Nginx, que redirige HTTP -> HTTPS. Como segunda barrera,
    # la API rechaza cualquier petición que no haya llegado por HTTPS.
    if settings.is_production and request.url.path != "/health" \
            and request.headers.get("x-forwarded-proto", "").lower() != "https":
        return JSONResponse({"detail": {"code": "HTTPS_REQUIRED", "message": "Usa HTTPS"}}, status_code=400)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"  # respuestas con tokens/datos personales
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


register_error_handlers(app)

for r in (auth_router, me_router, client_router, technician_router, admin_router,
          technician_kyc_router, kyc_catalogs_router, admin_kyc_router, admin_kyc_decisions_router,
          admin_documents_router, file_views_router,
          orders_routes.router, orders_routes.client_router, orders_routes.tech_router, orders_routes.admin_router,
          reviews_routes.router, reviews_routes.admin_router,
          payments_routes.tech_router, payments_routes.client_router, payments_routes.admin_router,
          webhooks_routes.router):
    app.include_router(r, prefix=settings.API_V1_PREFIX)


@app.get("/health", tags=["health"])
def health() -> dict[str, str]:
    return {"status": "ok"}
