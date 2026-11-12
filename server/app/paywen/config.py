"""Configuración y secretos.

En AWS todo sale de variables de entorno (app.env, que escribe el bootstrap de
la instancia) y de Secrets Manager, leído con el rol IAM de la instancia:

- DB_SECRET_ARN: secreto que maneja RDS (username/password). RDS lo rota cada
  7 días, así que se vuelve a leer si la autenticación falla.
- APP_SECRET_ARN: secreto de la app (agent_token, otx_api_key,
  dashboard_user, dashboard_password).

Para desarrollo local se puede saltar Secrets Manager con variables de
entorno: DATABASE_URL, AGENT_TOKEN, OTX_API_KEY, DASHBOARD_USER y
DASHBOARD_PASSWORD.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any

log = logging.getLogger(__name__)

# Cuánto se guarda en memoria el secreto de la app antes de volver a leerlo.
# Así un cambio hecho en la consola (por ejemplo, cargar la API key de OTX) se
# toma en unos minutos sin reiniciar nada.
APP_SECRET_TTL = 300

_lock = threading.Lock()
_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def region() -> str | None:
    return env("AWS_REGION") or env("AWS_DEFAULT_REGION")


def _read_secret(arn: str) -> dict[str, Any]:
    import boto3  # importado aquí para que los tests locales no lo necesiten

    client = boto3.client("secretsmanager", region_name=region())
    value = client.get_secret_value(SecretId=arn)["SecretString"]
    return json.loads(value)


def secret(arn: str, *, ttl: float = APP_SECRET_TTL, force: bool = False) -> dict[str, Any]:
    with _lock:
        cached = _cache.get(arn)
        if cached and not force and time.monotonic() - cached[0] < ttl:
            return cached[1]
    data = _read_secret(arn)
    with _lock:
        _cache[arn] = (time.monotonic(), data)
    return data


def app_secret_value(key: str, env_name: str) -> str | None:
    """Valor del secreto de la app, con override por variable de entorno."""
    override = env(env_name)
    if override is not None:
        return override
    arn = env("APP_SECRET_ARN")
    if not arn:
        return None
    try:
        value = secret(arn).get(key)
    except Exception:  # noqa: BLE001 - sin secreto la app sigue, con la función apagada
        log.exception("No se pudo leer el secreto de la app")
        return None
    return value or None


def agent_token() -> str | None:
    return app_secret_value("agent_token", "AGENT_TOKEN")


def otx_api_key() -> str | None:
    return app_secret_value("otx_api_key", "OTX_API_KEY")


def dashboard_credentials() -> tuple[str, str | None]:
    user = app_secret_value("dashboard_user", "DASHBOARD_USER") or "admin"
    password = app_secret_value("dashboard_password", "DASHBOARD_PASSWORD")
    return user, password


def database_conninfo(*, force_refresh: bool = False) -> str:
    """Cadena de conexión a PostgreSQL."""
    url = env("DATABASE_URL")
    if url:
        return url

    from psycopg.conninfo import make_conninfo

    arn = env("DB_SECRET_ARN")
    if not arn:
        raise RuntimeError("Falta DATABASE_URL o DB_SECRET_ARN")
    creds = secret(arn, ttl=3600, force=force_refresh)
    return make_conninfo(
        host=env("DB_HOST"),
        port=env("DB_PORT", "5432"),
        dbname=env("DB_NAME", "paywen"),
        user=creds["username"],
        password=creds["password"],
        sslmode=env("DB_SSLMODE", "require"),
        connect_timeout=10,
        application_name="paywen-scan",
    )


def display_tz():
    """Zona horaria para mostrar fechas y para cortar los días del histórico."""
    from zoneinfo import ZoneInfo

    return ZoneInfo(env("DISPLAY_TZ", "America/Santiago"))


def status_hours() -> tuple[float, float]:
    """Umbrales del estado del agente: atrasado (naranjo) y sin reportar (rojo)."""
    def num(name: str, default: float) -> float:
        try:
            return float(env(name, str(default)))
        except ValueError:
            return default

    warn = num("STATUS_WARN_HOURS", 2)
    return warn, max(warn, num("STATUS_OFFLINE_HOURS", 6))
