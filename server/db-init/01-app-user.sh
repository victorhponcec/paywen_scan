#!/bin/sh
# Inicialización de la base de datos de Paywen Scan.
#
# PostgreSQL ejecuta este script UNA sola vez: al crear el volumen de datos
# por primera vez. Si ya había datos, no se vuelve a ejecutar.
#
# Deja dos usuarios:
#   paywen_admin  superusuario (lo crea la imagen de postgres con POSTGRES_USER).
#                 Solo para administración: respaldos, cambios de contraseña…
#   paywen_app    el que usa la app. NO es superusuario ni puede crear bases ni
#                 roles; es dueño de la base "paywen" y de su esquema public,
#                 así que puede crear sus tablas y nada más.
#
# Las tablas no se crean aquí: las crea la app al arrancar desde schema.sql
# (CREATE TABLE IF NOT EXISTS), conectada como paywen_app, para que queden a
# su nombre.
set -eu

: "${APP_DB_PASSWORD:?Falta APP_DB_PASSWORD}"

psql -v ON_ERROR_STOP=1 -v app_password="$APP_DB_PASSWORD" \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
CREATE ROLE paywen_app LOGIN PASSWORD :'app_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

ALTER DATABASE paywen OWNER TO paywen_app;
ALTER SCHEMA public OWNER TO paywen_app;

-- Nadie más (rol PUBLIC) puede conectarse a esta base.
REVOKE ALL ON DATABASE paywen FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE paywen TO paywen_app;

-- Las conexiones de la app se identifican en pg_stat_activity.
ALTER ROLE paywen_app SET application_name = 'paywen-scan';
EOSQL

echo "Usuario paywen_app creado y dueño de la base paywen"
