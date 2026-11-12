"""FIRST EPSS: probabilidad de explotación de cada CVE en los próximos 30 días.

La API acepta varios CVEs separados por coma, con un máximo de 2000
caracteres en el parámetro: se envían en lotes que respetan ese límite.
"""

from __future__ import annotations

import logging
from typing import Iterable, Iterator

import httpx
import psycopg

log = logging.getLogger(__name__)

API = "https://api.first.org/data/v1/epss"
MAX_PARAM_CHARS = 1900


def chunks(cves: Iterable[str], max_chars: int = MAX_PARAM_CHARS) -> Iterator[list[str]]:
    batch: list[str] = []
    size = 0
    for cve in cves:
        if batch and size + len(cve) + 1 > max_chars:
            yield batch
            batch, size = [], 0
        batch.append(cve)
        size += len(cve) + 1
    if batch:
        yield batch


def refresh(conn: psycopg.Connection, client: httpx.Client, max_age_hours: int = 24) -> int:
    cves = [
        r["vuln_key"]
        for r in conn.execute(
            """
            SELECT DISTINCT f.vuln_key FROM findings f
            LEFT JOIN epss e ON e.cve = f.vuln_key
            WHERE f.vuln_key LIKE 'CVE-%%'
              AND (e.cve IS NULL OR e.fetched_at < now() - make_interval(hours => %s))
            ORDER BY 1
            """,
            (max_age_hours,),
        )
    ]
    rows = []
    for batch in chunks(cves):
        resp = client.get(API, params={"cve": ",".join(batch), "limit": len(batch)})
        resp.raise_for_status()
        for d in resp.json().get("data", []):
            rows.append((d["cve"], float(d["epss"]), float(d["percentile"]), d.get("date")))
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO epss (cve, epss, percentile, score_date, fetched_at) VALUES (%s, %s, %s, %s, now())
            ON CONFLICT (cve) DO UPDATE SET epss = EXCLUDED.epss, percentile = EXCLUDED.percentile,
                score_date = EXCLUDED.score_date, fetched_at = now()
            """,
            rows,
        )
    log.info("EPSS: %s CVEs consultados, %s con puntaje", len(cves), len(rows))
    return len(rows)
