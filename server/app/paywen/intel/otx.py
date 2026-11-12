"""AlienVault OTX: campañas (pulses) que mencionan cada CVE.

Solo se consultan los CVEs que importan (en KEV, EPSS alto o CVSS crítico) y
con un tope por pasada, para no gastar la cuota de la API. Sin API key, se
omite este paso.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx
import psycopg
from psycopg.types.json import Jsonb

log = logging.getLogger(__name__)

API = "https://otx.alienvault.com/api/v1/indicators/cve/{cve}/general"
MAX_PER_RUN = 60
PULSES_KEPT = 5


def _pulse(p: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": p.get("id"),
        "name": (p.get("name") or "")[:200],
        "created": p.get("created"),
        "modified": p.get("modified") or p.get("created"),
        "adversary": p.get("adversary") or None,
        "malware": [m.get("display_name") for m in p.get("malware_families") or [] if isinstance(m, dict)][:5],
        "tags": (p.get("tags") or [])[:6],
    }


def refresh(conn: psycopg.Connection, client: httpx.Client, api_key: str | None, max_age_hours: int = 24) -> int:
    if not api_key:
        log.info("OTX: sin API key, se omite")
        return 0
    cves = [
        r["vuln_key"]
        for r in conn.execute(
            """
            SELECT f.vuln_key
            FROM findings f
            LEFT JOIN kev k ON k.cve = f.vuln_key
            LEFT JOIN epss e ON e.cve = f.vuln_key
            LEFT JOIN otx o ON o.cve = f.vuln_key
            WHERE f.vuln_key LIKE 'CVE-%%'
              AND (k.cve IS NOT NULL OR e.epss >= 0.1 OR f.cvss >= 9)
              AND (o.cve IS NULL OR o.fetched_at < now() - make_interval(hours => %s))
            GROUP BY f.vuln_key
            ORDER BY bool_or(k.cve IS NOT NULL) DESC, max(e.epss) DESC NULLS LAST
            LIMIT %s
            """,
            (max_age_hours, MAX_PER_RUN),
        )
    ]

    def get(cve: str) -> tuple | None:
        try:
            resp = client.get(API.format(cve=cve), headers={"X-OTX-API-KEY": api_key})
            if resp.status_code == 404:
                return (cve, 0, Jsonb([]))
            resp.raise_for_status()
            info = resp.json().get("pulse_info") or {}
            pulses = sorted(info.get("pulses") or [], key=lambda p: p.get("modified") or "", reverse=True)
            return (cve, int(info.get("count") or len(pulses)), Jsonb([_pulse(p) for p in pulses[:PULSES_KEPT]]))
        except httpx.HTTPError as exc:
            log.warning("OTX: no se pudo consultar %s: %s", cve, exc)
            return None

    with ThreadPoolExecutor(max_workers=3) as pool:
        rows = [r for r in pool.map(get, cves) if r]
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO otx (cve, pulse_count, pulses, fetched_at) VALUES (%s, %s, %s, now())
            ON CONFLICT (cve) DO UPDATE SET pulse_count = EXCLUDED.pulse_count, pulses = EXCLUDED.pulses,
                fetched_at = now()
            """,
            rows,
        )
    log.info("OTX: %s CVEs consultados", len(rows))
    return len(rows)
