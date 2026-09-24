# Imagen única para la API y los dos workers (cambia solo el comando en docker-compose.yml).
#  - Usuario sin privilegios, sin shell de login, sin compiladores en la imagen final.
#  - Sin secretos: todo llega por variables de entorno en tiempo de ejecución (.env nunca entra, ver .dockerignore).
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

COPY --chown=root:root app ./app
COPY --chown=root:root migrations ./migrations
COPY --chown=root:root worker ./worker
COPY --chown=root:root scripts ./scripts
COPY --chown=root:root alembic.ini ./

# El código es de root y solo lectura para la app; lo único escribible es el almacenamiento local (volumen).
RUN mkdir -p /app/var/storage && chown app:app /app/var/storage
USER app

EXPOSE 8000
# --proxy-headers: toma el esquema y la IP de Nginx (el único que llega a la API en la red interna).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header"]
