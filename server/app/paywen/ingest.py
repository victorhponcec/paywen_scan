"""Guarda el inventario que envía un agente."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import psycopg

from .sbom import Component, extract_components, inventory_hash

log = logging.getLogger(__name__)

MAX_HOSTNAME = 255


class InvalidPayload(ValueError):
    pass


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def validate(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise InvalidPayload("El cuerpo debe ser un objeto JSON")
    hostname = payload.get("hostname")
    if not isinstance(hostname, str) or not hostname.strip() or len(hostname) > MAX_HOSTNAME:
        raise InvalidPayload("Falta 'hostname' o es inválido")
    if not isinstance(payload.get("sbom"), dict):
        raise InvalidPayload("Falta 'sbom' (SBOM CycloneDX de Trivy)")
    if not isinstance(payload.get("os", {}), dict):
        raise InvalidPayload("'os' debe ser un objeto")
    ports = payload.get("ports", [])
    if not isinstance(ports, list) or not all(isinstance(p, dict) for p in ports):
        raise InvalidPayload("'ports' debe ser una lista de objetos")
    return payload


def _port_rows(ports: list[dict[str, Any]]) -> list[tuple]:
    rows = []
    for p in ports:
        port = p.get("port")
        rows.append((
            str(p.get("proto") or "")[:16],
            str(p.get("address") or "")[:128],
            port if isinstance(port, int) else None,
            str(p.get("process") or "")[:1024],
        ))
    return rows


def store(conn: psycopg.Connection, payload: dict[str, Any], source_ip: str | None) -> dict[str, Any]:
    """Inserta o actualiza el host. Los componentes solo se reemplazan si el
    inventario cambió, para no perder los hallazgos ya calculados."""
    payload = validate(payload)
    components, warnings = extract_components(payload)
    ports = payload.get("ports") or []
    new_hash = inventory_hash(components, ports)
    os_info = payload.get("os") or {}

    host = conn.execute(
        """
        INSERT INTO hosts (hostname, os_id, os_version, os_name, kernel, source_ip,
                           collected_at, inventory_hash, last_seen)
        VALUES (%(hostname)s, %(os_id)s, %(os_version)s, %(os_name)s, %(kernel)s, %(ip)s,
                %(collected)s, %(hash)s, now())
        ON CONFLICT (hostname) DO UPDATE SET
            os_id = EXCLUDED.os_id, os_version = EXCLUDED.os_version,
            os_name = EXCLUDED.os_name, kernel = EXCLUDED.kernel,
            source_ip = EXCLUDED.source_ip, collected_at = EXCLUDED.collected_at,
            inventory_hash = EXCLUDED.inventory_hash, last_seen = now()
        RETURNING id, (xmax = 0) AS inserted,
                  (SELECT inventory_hash FROM hosts WHERE hostname = %(hostname)s) AS previous_hash
        """,
        {
            "hostname": payload["hostname"].strip(),
            "os_id": os_info.get("id"),
            "os_version": os_info.get("version_id"),
            "os_name": os_info.get("name"),
            "kernel": os_info.get("kernel"),
            "ip": source_ip,
            "collected": _parse_time(payload.get("collected_at")),
            "hash": new_hash,
        },
    ).fetchone()
    host_id = host["id"]
    changed = host["inserted"] or host["previous_hash"] != new_hash

    if changed:
        _replace_components(conn, host_id, components)
    conn.execute("DELETE FROM ports WHERE host_id = %s", (host_id,))
    with conn.cursor() as cur:
        cur.executemany(
            "INSERT INTO ports (host_id, proto, address, port, process) VALUES (%s, %s, %s, %s, %s)",
            [(host_id, *row) for row in _port_rows(ports)],
        )

    log.info("Inventario de %s: %s componentes, cambio=%s", payload["hostname"], len(components), changed)
    return {
        "status": "ok",
        "host_id": host_id,
        "components": len(components),
        "changed": bool(changed),
        "warnings": warnings,
    }


def _replace_components(conn: psycopg.Connection, host_id: int, components: list[Component]) -> None:
    # Al borrar los componentes se borran sus hallazgos (ON DELETE CASCADE); el
    # worker los vuelve a calcular porque scanned_hash ya no coincide.
    conn.execute("DELETE FROM components WHERE host_id = %s", (host_id,))
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO components (host_id, kind, ecosystem, name, version, purl, binaries, location)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            [
                (host_id, c.kind, c.ecosystem, c.name, c.version, c.purl, sorted(c.binaries), c.location)
                for c in components
            ],
        )
