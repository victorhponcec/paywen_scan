"""Worker de enriquecimiento. Una pasada completa:

1. Actualiza el catálogo CISA KEV (cada 12 h).
2. Cruza con OSV los hosts cuyo inventario cambió (o que no se revisan hace
   más de 24 h) y reconstruye sus hallazgos.
3. Actualiza EPSS de los CVEs encontrados (cada 24 h).
4. Consulta OTX para los CVEs relevantes (si hay API key).
5. Recalcula prioridad, exposición y puntaje de riesgo de cada host.
6. Guarda la foto diaria de cada host y las vulnerabilidades nuevas/resueltas.

Si un paso falla (por ejemplo, una API no responde), se registra y se sigue
con los demás; el proceso termina con código 1 para que systemd lo marque.
"""

from __future__ import annotations

import logging
import sys
from collections import defaultdict
from datetime import datetime

import httpx

from . import config, db, scoring
from .intel import epss, http_client, kev, osv, otx
from .sbom import process_names

log = logging.getLogger("paywen.worker")

KEV_MAX_AGE_HOURS = 12
RESCAN_HOURS = 24


def step_kev(client: httpx.Client) -> None:
    with db.transaction() as conn:
        meta = conn.execute(
            "SELECT 1 FROM meta WHERE key = 'kev_refreshed' AND updated_at > now() - make_interval(hours => %s)",
            (KEV_MAX_AGE_HOURS,),
        ).fetchone()
        if meta:
            log.info("KEV: catálogo al día")
            return
        count = kev.refresh(conn, client)
        db.set_meta(conn, "kev_refreshed", str(count))


def hosts_to_scan() -> list[dict]:
    with db.transaction() as conn:
        return conn.execute(
            """
            SELECT id, hostname, inventory_hash FROM hosts
            WHERE scanned_hash IS DISTINCT FROM inventory_hash
               OR last_enriched IS NULL
               OR last_enriched < now() - make_interval(hours => %s)
            ORDER BY id
            """,
            (RESCAN_HOURS,),
        ).fetchall()


COMPONENT_CHUNK = 50


def scan_host(client: httpx.Client, host: dict) -> int:
    with db.transaction() as conn:
        comps = conn.execute(
            # Lo que es solo inventario (programas de Windows, KB) no existe en OSV.
            "SELECT id, ecosystem, name, version FROM components WHERE host_id = %s AND kind <> 'inventory' "
            "ORDER BY id",
            (host["id"],),
        ).fetchall()
    queries = [{"package": {"ecosystem": c["ecosystem"], "name": c["name"]}, "version": c["version"]} for c in comps]
    results = osv.query_batch(client, queries) if queries else []

    refs = {v["id"]: v.get("modified") for res in results for v in res}
    osv.cache_details(db.transaction, client, refs)

    # Los hallazgos se arman por bloques de componentes: así nunca están todos
    # los registros de OSV en memoria a la vez (el kernel solo trae miles).
    rows = []
    pairs = [(c, r) for c, r in zip(comps, results) if r]
    for start in range(0, len(pairs), COMPONENT_CHUNK):
        chunk = pairs[start:start + COMPONENT_CHUNK]
        ids = list({v["id"] for _, res in chunk for v in res})
        with db.transaction() as conn:
            records = {
                r["id"]: r["data"]
                for r in conn.execute("SELECT id, data FROM osv_vulns WHERE id = ANY(%s)", (ids,))
            }
        for comp, res in chunk:
            recs = [records[v["id"]] for v in res if v["id"] in records]
            for f in osv.findings_for(recs, comp["ecosystem"], comp["name"], comp["version"]):
                rows.append((
                    host["id"], comp["id"], f.vuln_key, sorted(f.osv_ids), f.summary,
                    f.cvss, f.severity_label, f.fixed_version,
                ))
        del records

    with db.transaction() as conn:
        conn.execute("DELETE FROM findings WHERE host_id = %s", (host["id"],))
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO findings (host_id, component_id, vuln_key, osv_ids, summary, cvss,
                                      severity_label, fixed_version)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (component_id, vuln_key) DO NOTHING
                """,
                rows,
            )
        conn.execute(
            "UPDATE hosts SET scanned_hash = %s, last_enriched = now() WHERE id = %s",
            (host["inventory_hash"], host["id"]),
        )
    log.info("OSV: %s → %s componentes, %s hallazgos", host["hostname"], len(comps), len(rows))
    return len(rows)


def step_epss(client: httpx.Client) -> None:
    with db.transaction() as conn:
        epss.refresh(conn, client)


def step_otx(client: httpx.Client) -> None:
    key = config.otx_api_key()
    with db.transaction() as conn:
        otx.refresh(conn, client, key)


LOCAL_PREFIXES = ("127.", "[::1]", "::1")


def is_local(address: str | None) -> bool:
    return (address or "").startswith(LOCAL_PREFIXES)


def step_priorities() -> None:
    with db.transaction() as conn:
        # Solo cuentan los puertos que escuchan fuera de localhost.
        procs: dict[int, set[str]] = defaultdict(set)
        port_matchers: dict[int, list[tuple[int, object]]] = defaultdict(list)
        for row in conn.execute("SELECT host_id, address, port, process FROM ports"):
            if is_local(row["address"]) or row["port"] is None:
                continue
            names = set(process_names(row["process"]))
            procs[row["host_id"]].update(names)
            if names:
                port_matchers[row["host_id"]].append((row["port"], scoring.exposed_matcher(names)))

        rows = conn.execute(
            """
            SELECT f.id, f.host_id, c.kind, c.ecosystem, c.name, c.binaries, f.cvss, f.severity_label,
                   (k.cve IS NOT NULL) AS in_kev, e.epss
            FROM findings f
            JOIN components c ON c.id = f.component_id
            LEFT JOIN kev k ON k.cve = f.vuln_key
            LEFT JOIN epss e ON e.cve = f.vuln_key
            """
        ).fetchall()

        matchers = {}
        updates = []
        ranks_by_host: dict[int, list[int]] = defaultdict(list)
        for r in rows:
            matcher = matchers.setdefault(r["host_id"], scoring.exposed_matcher(procs[r["host_id"]]))
            args = (r["kind"], r["ecosystem"], r["name"], r["binaries"] or [])
            exposed = matcher(*args)
            ports = sorted({p for p, m in port_matchers[r["host_id"]] if m(*args)}) if exposed else []
            rank = scoring.final_rank(
                scoring.base_rank(r["in_kev"], r["epss"], r["cvss"], r["severity_label"]), exposed
            )
            updates.append((exposed, ports, rank, r["id"]))
            ranks_by_host[r["host_id"]].append(rank)

        with conn.cursor() as cur:
            cur.executemany(
                "UPDATE findings SET exposed = %s, exposed_ports = %s, priority_rank = %s WHERE id = %s", updates
            )
        for host in conn.execute("SELECT id FROM hosts").fetchall():
            conn.execute(
                "UPDATE hosts SET risk_score = %s WHERE id = %s",
                (scoring.host_score(ranks_by_host.get(host["id"], [])), host["id"]),
            )
        db.set_meta(conn, "last_worker_run", "ok")
    log.info("Prioridades recalculadas para %s hallazgos", len(rows))


SNAPSHOT_SQL = """
INSERT INTO host_snapshots (host_id, day, critica, alta, media, baja, kev, ransomware, unique_vulns,
                            fixable, risk_score, components, new_vulns, resolved_vulns, synthetic, taken_at)
SELECT h.id, %(day)s,
       count(f.id) FILTER (WHERE f.priority_rank = 3),
       count(f.id) FILTER (WHERE f.priority_rank = 2),
       count(f.id) FILTER (WHERE f.priority_rank = 1),
       count(f.id) FILTER (WHERE f.priority_rank = 0),
       count(DISTINCT f.vuln_key) FILTER (WHERE k.cve IS NOT NULL),
       count(DISTINCT f.vuln_key) FILTER (WHERE k.ransomware),
       count(DISTINCT f.vuln_key),
       count(DISTINCT f.vuln_key) FILTER (WHERE f.fixed_version IS NOT NULL),
       h.risk_score,
       (SELECT count(*) FROM components c WHERE c.host_id = h.id),
       (SELECT count(*) FROM vuln_history v WHERE v.host_id = h.id AND NOT v.baseline
          AND (v.first_seen AT TIME ZONE %(tz)s)::date = %(day)s),
       (SELECT count(*) FROM vuln_history v WHERE v.host_id = h.id
          AND (v.resolved_at AT TIME ZONE %(tz)s)::date = %(day)s),
       false, now()
FROM hosts h
LEFT JOIN findings f ON f.host_id = h.id
LEFT JOIN kev k ON k.cve = f.vuln_key
WHERE h.last_enriched IS NOT NULL
GROUP BY h.id
ON CONFLICT (host_id, day) DO UPDATE SET
    critica = EXCLUDED.critica, alta = EXCLUDED.alta, media = EXCLUDED.media, baja = EXCLUDED.baja,
    kev = EXCLUDED.kev, ransomware = EXCLUDED.ransomware, unique_vulns = EXCLUDED.unique_vulns,
    fixable = EXCLUDED.fixable, risk_score = EXCLUDED.risk_score, components = EXCLUDED.components,
    new_vulns = EXCLUDED.new_vulns, resolved_vulns = EXCLUDED.resolved_vulns,
    synthetic = false, taken_at = now()
"""


def step_history() -> None:
    """Registra qué vulnerabilidades aparecieron o se resolvieron y guarda la
    foto del día de cada host (base del histórico y de los gráficos)."""
    tz = config.display_tz()
    day = datetime.now(tz).date()
    with db.transaction() as conn:
        # La primera vez que se ve un host, todo lo que tiene es la línea base.
        conn.execute(
            """
            INSERT INTO vuln_history (host_id, vuln_key, max_rank, baseline)
            SELECT f.host_id, f.vuln_key, max(f.priority_rank),
                   NOT EXISTS (SELECT 1 FROM vuln_history v WHERE v.host_id = f.host_id)
            FROM findings f
            GROUP BY f.host_id, f.vuln_key
            ON CONFLICT (host_id, vuln_key) DO UPDATE SET
                last_seen = now(), max_rank = EXCLUDED.max_rank, resolved_at = NULL
            """
        )
        resolved = conn.execute(
            """
            UPDATE vuln_history v SET resolved_at = now()
            WHERE v.resolved_at IS NULL
              AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.host_id = v.host_id AND f.vuln_key = v.vuln_key)
            """
        ).rowcount
        conn.execute(SNAPSHOT_SQL, {"day": day, "tz": str(tz)})
    log.info("Histórico: foto del %s guardada (%s vulnerabilidades resueltas en esta pasada)", day, resolved)


def run(client: httpx.Client | None = None) -> int:
    failed = []
    own_client = client is None
    client = client or http_client()
    try:
        def attempt(name, fn, *args):
            try:
                fn(*args)
            except Exception:  # noqa: BLE001 - un paso que falla no detiene a los demás
                log.exception("Falló el paso %s", name)
                failed.append(name)

        attempt("kev", step_kev, client)
        for host in hosts_to_scan():
            attempt(f"osv:{host['hostname']}", scan_host, client, host)
        attempt("epss", step_epss, client)
        attempt("otx", step_otx, client)
        attempt("prioridades", step_priorities)
        attempt("historico", step_history)
    finally:
        if own_client:
            client.close()
    if failed:
        log.error("Pasada terminada con errores en: %s", ", ".join(failed))
        return 1
    log.info("Pasada terminada sin errores")
    return 0


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # Sin esto, httpx escribe una línea por cada request (miles por pasada).
    logging.getLogger("httpx").setLevel(logging.WARNING)
    db.wait_for_db(attempts=30)
    sys.exit(run())


if __name__ == "__main__":
    main()
