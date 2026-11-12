"""Conexión a PostgreSQL.

Una conexión por operación, sin pool: el tráfico es bajo (unos pocos agentes y
el dashboard) y así cada conexión usa la contraseña vigente, que RDS rota.
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from importlib import resources
from typing import Iterator

import psycopg
from psycopg.rows import dict_row

from . import config

log = logging.getLogger(__name__)


def _is_auth_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return "password authentication failed" in text or "authentication failed" in text


def connect() -> psycopg.Connection:
    try:
        return psycopg.connect(config.database_conninfo(), row_factory=dict_row)
    except psycopg.OperationalError as exc:
        if not _is_auth_error(exc) or config.env("DATABASE_URL"):
            raise
        # RDS rotó la contraseña: leer el secreto de nuevo e intentar otra vez.
        log.warning("Autenticación rechazada; se vuelve a leer el secreto de la base")
        return psycopg.connect(config.database_conninfo(force_refresh=True), row_factory=dict_row)


@contextmanager
def transaction() -> Iterator[psycopg.Connection]:
    """Conexión con transacción: commit al salir, rollback si hay error."""
    conn = connect()
    try:
        with conn.transaction():
            yield conn
    finally:
        conn.close()


def init_schema() -> None:
    sql = resources.files("paywen").joinpath("schema.sql").read_text(encoding="utf-8")
    with transaction() as conn:
        # Evita que dos procesos (api y worker) creen las tablas a la vez.
        conn.execute("SELECT pg_advisory_xact_lock(7243001)")
        conn.execute(sql)


def wait_for_db(attempts: int = 60, delay: float = 10.0) -> None:
    """Espera a que la base responda. Al encender a las 18:30, RDS tarda unos
    minutos en estar disponible."""
    for attempt in range(1, attempts + 1):
        try:
            init_schema()
            if attempt > 1:
                log.info("Base de datos disponible después de %s intentos", attempt)
            return
        except psycopg.OperationalError as exc:
            log.warning("Base de datos no disponible (intento %s/%s): %s", attempt, attempts, exc)
            time.sleep(delay)
    raise RuntimeError("La base de datos no respondió a tiempo")


def get_meta(conn: psycopg.Connection, key: str) -> dict | None:
    return conn.execute("SELECT value, updated_at FROM meta WHERE key = %s", (key,)).fetchone()


def set_meta(conn: psycopg.Connection, key: str, value: str) -> None:
    conn.execute(
        """
        INSERT INTO meta (key, value, updated_at) VALUES (%s, %s, now())
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()
        """,
        (key, value),
    )
