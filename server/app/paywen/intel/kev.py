"""CISA Known Exploited Vulnerabilities: vulnerabilidades que se están
explotando hoy, con la marca de uso en campañas de ransomware."""

from __future__ import annotations

import logging
from datetime import date

import httpx
import psycopg

from . import is_cve

log = logging.getLogger(__name__)

FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _date(value: str | None) -> date | None:
    try:
        return date.fromisoformat(value) if value else None
    except ValueError:
        return None


def refresh(conn: psycopg.Connection, client: httpx.Client) -> int:
    resp = client.get(FEED)
    resp.raise_for_status()
    data = resp.json()
    rows = [
        (
            v["cveID"],
            v.get("vendorProject"),
            v.get("product"),
            v.get("vulnerabilityName"),
            _date(v.get("dateAdded")),
            _date(v.get("dueDate")),
            v.get("knownRansomwareCampaignUse") == "Known",
            v.get("requiredAction"),
        )
        for v in data.get("vulnerabilities", [])
        if is_cve(v.get("cveID"))
    ]
    if not rows:
        raise ValueError("El catálogo KEV llegó vacío; se mantiene la copia anterior")
    conn.execute("DELETE FROM kev")
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO kev (cve, vendor, product, name, date_added, due_date, ransomware, required_action)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (cve) DO NOTHING
            """,
            rows,
        )
    log.info("KEV: %s vulnerabilidades (versión del catálogo %s)", len(rows), data.get("catalogVersion"))
    return len(rows)
