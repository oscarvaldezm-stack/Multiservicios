#!/bin/sh
# Se ejecuta UNA vez, al crear el volumen de PostgreSQL. Crea el usuario de la app con
# privilegios mínimos (no superusuario, no crea roles ni bases) y la base de la que es dueño,
# para que Alembic pueda crear tablas, triggers y la extensión confiable btree_gist.
set -eu
: "${POSTGRES_APP_PASSWORD:?Define POSTGRES_APP_PASSWORD en .env}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
     -v app_pass="$POSTGRES_APP_PASSWORD" <<'SQL'
CREATE ROLE multiservicios_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'app_pass';
CREATE DATABASE multiservicios OWNER multiservicios_app;
REVOKE ALL ON DATABASE multiservicios FROM PUBLIC;
SQL
