"""Consultas del dashboard. Los filtros se arman con fragmentos fijos y
parámetros (nunca concatenando valores del usuario)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any

import psycopg

from . import config
from .scoring import LEVEL_SLUG

LOCAL_ADDR = ("127.", "[::1]", "::1")


EPSS_CHOICES = {"0.01": "≥ 1 %", "0.1": "≥ 10 %", "0.5": "≥ 50 %"}
CVSS_CHOICES = {"7": "≥ 7 (alta)", "9": "≥ 9 (crítica)"}
NEW_CHOICES = {"1": "Últimas 24 h", "7": "Últimos 7 días", "30": "Últimos 30 días"}


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None


@dataclass
class Filters:
    priority: str | None = None   # critica | alta | media | baja
    kev: bool = False
    ransomware: bool = False
    exposed: bool = False
    fixable: bool = False
    epss_min: str | None = None   # clave de EPSS_CHOICES
    cvss_min: str | None = None   # clave de CVSS_CHOICES
    new_days: str | None = None   # clave de NEW_CHOICES
    host_id: int | None = None
    os_name: str | None = None
    port: int | None = None
    ecosystem: str | None = None
    q: str | None = None
    fixed_host: bool = False      # el host viene de la URL (/hosts/{id}), no del filtro

    @classmethod
    def from_query(cls, params: dict[str, str], host_id: int | None = None) -> "Filters":
        def flag(name: str) -> bool:
            return params.get(name) in ("1", "on", "true")

        def text(name: str, size: int = 100) -> str | None:
            return (params.get(name) or "").strip()[:size] or None

        def choice(name: str, choices: dict) -> str | None:
            value = params.get(name)
            return value if value in choices else None

        priority = params.get("priority")
        epss_min = choice("epss_min", EPSS_CHOICES)
        if params.get("epss") in ("1", "on", "true") and not epss_min:   # enlace antiguo: EPSS ≥ 10 %
            epss_min = "0.1"
        port = _int(params.get("port"))
        return cls(
            priority=priority if priority in LEVEL_SLUG else None,
            kev=flag("kev"),
            ransomware=flag("ransomware"),
            exposed=flag("exposed"),
            fixable=flag("fixable"),
            epss_min=epss_min,
            cvss_min=choice("cvss_min", CVSS_CHOICES),
            new_days=choice("new", NEW_CHOICES),
            host_id=host_id if host_id is not None else _int(params.get("host")),
            os_name=text("os"),
            port=port if port and 0 < port < 65536 else None,
            ecosystem=text("eco"),
            q=text("q"),
            fixed_host=host_id is not None,
        )

    @property
    def advanced(self) -> bool:
        """Hay filtros del panel "Más filtros" activos (para dejarlo abierto)."""
        return any([self.epss_min, self.cvss_min, self.new_days, self.os_name, self.port, self.ecosystem,
                    self.ransomware, self.host_id and not self.fixed_host])

    def where(self) -> tuple[str, list[Any]]:
        clauses, params = ["TRUE"], []
        if self.host_id is not None:
            clauses.append("f.host_id = %s")
            params.append(self.host_id)
        if self.priority:
            clauses.append("f.priority_rank = %s")
            params.append(LEVEL_SLUG.index(self.priority))
        if self.kev:
            clauses.append("k.cve IS NOT NULL")
        if self.ransomware:
            clauses.append("k.ransomware")
        if self.epss_min:
            clauses.append("e.epss >= %s")
            params.append(float(self.epss_min))
        if self.cvss_min:
            clauses.append("f.cvss >= %s")
            params.append(float(self.cvss_min))
        if self.exposed:
            clauses.append("f.exposed")
        if self.port:
            clauses.append("%s = ANY(f.exposed_ports)")
            params.append(self.port)
        if self.fixable:
            clauses.append("f.fixed_version IS NOT NULL")
        if self.os_name:
            clauses.append("h.os_name = %s")
            params.append(self.os_name)
        if self.ecosystem:
            clauses.append("c.ecosystem = %s")
            params.append(self.ecosystem)
        if self.new_days:
            clauses.append(
                "EXISTS (SELECT 1 FROM vuln_history v WHERE v.host_id = f.host_id AND v.vuln_key = f.vuln_key"
                " AND NOT v.baseline AND v.first_seen > now() - make_interval(days => %s))"
            )
            params.append(int(self.new_days))
        if self.q:
            clauses.append("(f.vuln_key ILIKE %s OR c.name ILIKE %s)")
            like = f"%{self.q}%"
            params += [like, like]
        return " AND ".join(clauses), params

    def query_string(self, **override: Any) -> str:
        from urllib.parse import urlencode

        items = {
            "priority": self.priority,
            "kev": "1" if self.kev else None,
            "ransomware": "1" if self.ransomware else None,
            "exposed": "1" if self.exposed else None,
            "fixable": "1" if self.fixable else None,
            "epss_min": self.epss_min,
            "cvss_min": self.cvss_min,
            "new": self.new_days,
            "host": self.host_id if not self.fixed_host else None,
            "os": self.os_name,
            "port": self.port,
            "eco": self.ecosystem,
            "q": self.q,
        }
        items.update(override)
        return urlencode({k: v for k, v in items.items() if v})


FINDINGS_SQL = """
SELECT f.vuln_key,
       c.ecosystem,
       c.kind,
       c.name                                                   AS package,
       max(f.priority_rank)                                     AS rank,
       string_agg(DISTINCT h.hostname, ', ' ORDER BY h.hostname) AS hosts,
       count(DISTINCT h.id)                                     AS host_count,
       string_agg(DISTINCT c.version, ', ' ORDER BY c.version)  AS versions,
       max(f.cvss)                                              AS cvss,
       min(f.fixed_version)                                     AS fixed_version,
       bool_or(f.exposed)                                       AS exposed,
       max(f.summary)                                           AS summary,
       max(f.severity_label)                                    AS severity_label,
       (k.cve IS NOT NULL)                                      AS in_kev,
       coalesce(k.ransomware, false)                            AS ransomware,
       k.due_date                                               AS kev_due,
       e.epss,
       e.percentile,
       coalesce(o.pulse_count, 0)                               AS pulses,
       string_agg(DISTINCT array_to_string(f.exposed_ports, ','), ',') AS ports_raw
FROM findings f
JOIN components c ON c.id = f.component_id
JOIN hosts h ON h.id = f.host_id
LEFT JOIN kev k ON k.cve = f.vuln_key
LEFT JOIN epss e ON e.cve = f.vuln_key
LEFT JOIN otx o ON o.cve = f.vuln_key
WHERE {where}
GROUP BY f.vuln_key, c.ecosystem, c.kind, c.name, k.cve, k.ransomware, k.due_date, e.epss, e.percentile, o.pulse_count
ORDER BY rank DESC, in_kev DESC, ransomware DESC, e.epss DESC NULLS LAST, cvss DESC NULLS LAST, f.vuln_key
LIMIT %s
"""


def findings(conn: psycopg.Connection, filters: Filters, limit: int = 300) -> list[dict]:
    where, params = filters.where()
    rows = conn.execute(FINDINGS_SQL.format(where=where), [*params, limit]).fetchall()
    for r in rows:
        raw = (r.pop("ports_raw") or "").split(",")
        r["ports"] = sorted({int(p) for p in raw if p.isdigit()})
    return rows


def overview(conn: psycopg.Connection) -> dict:
    return conn.execute(
        """
        SELECT
          (SELECT count(*) FROM hosts)                                                       AS hosts,
          (SELECT count(*) FROM hosts WHERE last_seen < now() - interval '24 hours')         AS stale_hosts,
          (SELECT count(*) FROM findings)                                                    AS findings,
          (SELECT count(DISTINCT vuln_key) FROM findings)                                    AS unique_vulns,
          (SELECT count(DISTINCT vuln_key) FROM findings WHERE fixed_version IS NOT NULL)    AS unique_fixable,
          (SELECT count(DISTINCT f.vuln_key) FROM findings f JOIN kev k ON k.cve = f.vuln_key) AS kev_vulns,
          (SELECT count(DISTINCT f.host_id) FROM findings f JOIN kev k ON k.cve = f.vuln_key)  AS kev_hosts,
          (SELECT count(DISTINCT f.vuln_key) FROM findings f JOIN kev k ON k.cve = f.vuln_key
             WHERE k.ransomware)                                                             AS ransomware_vulns,
          (SELECT count(DISTINCT p->>'id') FROM otx o
             CROSS JOIN LATERAL jsonb_array_elements(o.pulses) p
             WHERE o.cve IN (SELECT vuln_key FROM findings))                                 AS campaigns,
          (SELECT max(last_seen) FROM hosts)                                                 AS last_ingest,
          (SELECT updated_at FROM meta WHERE key = 'last_worker_run')                        AS last_worker,
          (SELECT updated_at FROM meta WHERE key = 'kev_refreshed')                          AS kev_refreshed,
          (SELECT value FROM meta WHERE key = 'kev_refreshed')                               AS kev_size
        """
    ).fetchone()


HOSTS_SQL = """
SELECT h.id, h.hostname, h.os_name, h.os_id, h.os_version, h.source_ip, h.last_seen, h.last_enriched,
       h.risk_score, h.kernel, h.first_seen,
       (h.scanned_hash IS DISTINCT FROM h.inventory_hash)                   AS pending,
       count(f.id) FILTER (WHERE f.priority_rank = 3)                       AS critica,
       count(f.id) FILTER (WHERE f.priority_rank = 2)                       AS alta,
       count(f.id) FILTER (WHERE f.priority_rank = 1)                       AS media,
       count(f.id) FILTER (WHERE f.priority_rank = 0)                       AS baja,
       count(DISTINCT f.vuln_key) FILTER (WHERE k.cve IS NOT NULL)          AS kev,
       (SELECT count(*) FROM components c WHERE c.host_id = h.id)           AS components,
       (SELECT count(*) FROM components c WHERE c.host_id = h.id AND c.kind <> 'inventory') AS crossable,
       (SELECT string_agg(port::text, ', ' ORDER BY port)
          FROM (SELECT DISTINCT p.port FROM ports p
                WHERE p.host_id = h.id AND p.port IS NOT NULL
                  AND p.address NOT LIKE '127.%%' AND p.address NOT LIKE '[::1]%%') s) AS open_ports
FROM hosts h
LEFT JOIN findings f ON f.host_id = h.id
LEFT JOIN kev k ON k.cve = f.vuln_key
WHERE {where}
GROUP BY h.id
ORDER BY h.risk_score DESC, h.hostname
"""


def hosts(conn: psycopg.Connection, os_name: str | None = None, q: str | None = None,
          status: str | None = None) -> list[dict]:
    clauses, params = ["TRUE"], []
    if os_name:
        clauses.append("h.os_name = %s")
        params.append(os_name)
    if q:
        clauses.append("(h.hostname ILIKE %s OR h.source_ip ILIKE %s)")
        params += [f"%{q}%", f"%{q}%"]
    rows = conn.execute(HOSTS_SQL.format(where=" AND ".join(clauses)), params).fetchall()
    for r in rows:
        r["status"] = agent_status(r["last_seen"])
    if status in STATUS_LABELS:
        rows = [r for r in rows if r["status"]["key"] == status]
    return rows


def host(conn: psycopg.Connection, host_id: int) -> dict | None:
    row = conn.execute(HOSTS_SQL.format(where="h.id = %s"), [host_id]).fetchone()
    if row:
        row["status"] = agent_status(row["last_seen"])
    return row


def host_ports(conn: psycopg.Connection, host_id: int) -> list[dict]:
    return conn.execute(
        "SELECT proto, address, port, process FROM ports WHERE host_id = %s ORDER BY port NULLS LAST, proto",
        (host_id,),
    ).fetchall()


def host_component_counts(conn: psycopg.Connection, host_id: int) -> list[dict]:
    return conn.execute(
        """
        SELECT c.ecosystem, count(DISTINCT c.id) AS components, count(DISTINCT f.component_id) AS affected,
               bool_and(c.kind = 'inventory') AS inventory_only
        FROM components c LEFT JOIN findings f ON f.component_id = c.id
        WHERE c.host_id = %s GROUP BY c.ecosystem ORDER BY components DESC
        """,
        (host_id,),
    ).fetchall()


def campaigns(conn: psycopg.Connection, limit: int = 50) -> list[dict]:
    return conn.execute(
        """
        SELECT p->>'id'                                         AS id,
               max(p->>'name')                                  AS name,
               max(p->>'modified')                              AS modified,
               max(p->>'adversary')                             AS adversary,
               (array_agg(p->'malware'))[1]                     AS malware,
               (array_agg(p->'tags'))[1]                        AS tags,
               array_agg(DISTINCT o.cve ORDER BY o.cve)         AS cves,
               string_agg(DISTINCT h.hostname, ', ' ORDER BY h.hostname) AS hosts,
               count(DISTINCT f.host_id)                        AS host_count
        FROM otx o
        CROSS JOIN LATERAL jsonb_array_elements(o.pulses) p
        JOIN findings f ON f.vuln_key = o.cve
        JOIN hosts h ON h.id = f.host_id
        GROUP BY p->>'id'
        ORDER BY max(p->>'modified') DESC NULLS LAST
        LIMIT %s
        """,
        (limit,),
    ).fetchall()


def kev_detail(conn: psycopg.Connection, cve: str) -> dict | None:
    return conn.execute("SELECT * FROM kev WHERE cve = %s", (cve,)).fetchone()



# ─── Estado de los agentes ────────────────────────────────────────────────────
# El agente no mantiene una conexión abierta: envía el inventario cada cierto
# tiempo. El estado se deduce de cuánto hace que llegó el último inventario.
# Si el servidor estuvo apagado (por ejemplo, de noche), los agentes no
# pudieron reportar: el atraso se cuenta desde que el servidor está arriba.

STARTED_AT = datetime.now(timezone.utc)
STATUS_LABELS = {"online": "En línea", "late": "Atrasado", "offline": "Sin reportar"}


def agent_status(last_seen: datetime | None, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    warn_h, offline_h = config.status_hours()
    if last_seen is None:
        key, hours = "offline", None
    else:
        hours = (now - max(last_seen, STARTED_AT)).total_seconds() / 3600
        key = "online" if hours < warn_h else "late" if hours < offline_h else "offline"
    return {
        "key": key,
        "label": STATUS_LABELS[key],
        "hours": hours,
        "hint": f"En línea: menos de {warn_h:g} h desde el último inventario · Atrasado: {warn_h:g}–{offline_h:g} h · "
                f"Sin reportar: {offline_h:g} h o más",
    }


def status_counts(rows: list[dict]) -> dict:
    counts = {k: 0 for k in STATUS_LABELS}
    for r in rows:
        counts[r["status"]["key"]] += 1
    return counts


# ─── Opciones de los filtros ──────────────────────────────────────────────────

def filter_options(conn: psycopg.Connection) -> dict:
    return {
        "hosts": conn.execute("SELECT id, hostname FROM hosts ORDER BY hostname").fetchall(),
        "os": [r["os_name"] for r in conn.execute(
            "SELECT DISTINCT os_name FROM hosts WHERE os_name IS NOT NULL ORDER BY os_name")],
        "ports": [r["port"] for r in conn.execute(
            "SELECT DISTINCT unnest(exposed_ports) AS port FROM findings ORDER BY port")],
        "ecosystems": [r["ecosystem"] for r in conn.execute(
            "SELECT DISTINCT ecosystem FROM components ORDER BY ecosystem")],
    }


# ─── Gráficos del momento actual ──────────────────────────────────────────────

def distribution(conn: psycopg.Connection, host_id: int | None = None) -> list[int]:
    """Hallazgos por prioridad: [baja, media, alta, crítica]."""
    rows = conn.execute(
        "SELECT priority_rank, count(*) AS n FROM findings WHERE (%(h)s::bigint IS NULL OR host_id = %(h)s) "
        "GROUP BY priority_rank",
        {"h": host_id},
    ).fetchall()
    out = [0, 0, 0, 0]
    for r in rows:
        out[r["priority_rank"]] = r["n"]
    return out


def top_packages(conn: psycopg.Connection, host_id: int | None = None, limit: int = 8) -> list[dict]:
    return conn.execute(
        """
        SELECT c.name, c.ecosystem,
               count(DISTINCT f.vuln_key) FILTER (WHERE f.priority_rank = 3) AS critica,
               count(DISTINCT f.vuln_key) FILTER (WHERE f.priority_rank = 2) AS alta
        FROM findings f JOIN components c ON c.id = f.component_id
        WHERE f.priority_rank >= 2 AND (%(h)s::bigint IS NULL OR f.host_id = %(h)s)
        GROUP BY c.name, c.ecosystem
        ORDER BY critica DESC, alta DESC, c.name
        LIMIT %(limit)s
        """,
        {"h": host_id, "limit": limit},
    ).fetchall()


# ─── Histórico ────────────────────────────────────────────────────────────────

HISTORY_FIELDS = ("critica", "alta", "media", "baja", "kev", "ransomware", "unique_vulns", "fixable",
                  "risk_score", "new_vulns", "resolved_vulns")
CARRY_FIELDS = HISTORY_FIELDS[:9]   # nuevas/resueltas no se arrastran a días sin foto


def history(conn: psycopg.Connection, days: int = 30, host_id: int | None = None) -> dict:
    """Serie diaria para los gráficos. Si un día no tiene foto (el servidor
    estuvo apagado), se repite el último valor conocido de cada host."""
    today = datetime.now(config.display_tz()).date()
    start = today - timedelta(days=days - 1)
    rows = conn.execute(
        """
        SELECT s.* FROM host_snapshots s
        WHERE (%(h)s::bigint IS NULL OR s.host_id = %(h)s)
          AND (s.day >= %(start)s
               OR s.day = (SELECT max(day) FROM host_snapshots p WHERE p.host_id = s.host_id AND p.day < %(start)s))
          AND s.day <= %(today)s
        ORDER BY s.day
        """,
        {"h": host_id, "start": start, "today": today},
    ).fetchall()
    by_host: dict[int, dict[date, dict]] = {}
    for r in rows:
        by_host.setdefault(r["host_id"], {})[r["day"]] = r

    dates = [start + timedelta(days=i) for i in range(days)]
    series = {f: [] for f in HISTORY_FIELDS}
    per_host: dict[int, list] = {hid: [] for hid in by_host}
    synthetic = False
    for d in dates:
        totals = dict.fromkeys(HISTORY_FIELDS, 0)
        seen = False
        for hid, snaps in by_host.items():
            exact = snaps.get(d)
            prior = [k for k in snaps if k <= d]
            last = snaps[max(prior)] if prior else None
            if last is None:
                per_host[hid].append(None)
                continue
            seen = True
            synthetic |= bool(last["synthetic"])
            for f in CARRY_FIELDS:
                totals[f] += last[f]
            if exact:
                totals["new_vulns"] += exact["new_vulns"]
                totals["resolved_vulns"] += exact["resolved_vulns"]
            per_host[hid].append(last["critica"] + last["alta"])
        for f in HISTORY_FIELDS:
            series[f].append(totals[f] if seen else None)
    if host_id is None:
        # El puntaje consolidado es el promedio de los hosts (la suma no tiene sentido con tope 100).
        counts = [sum(1 for h in per_host.values() if h[i] is not None) for i in range(days)]
        series["risk_score"] = [round(v / c) if v is not None and c else None
                                for v, c in zip(series["risk_score"], counts)]
    has_data = any(v is not None for v in series["critica"])
    return {
        "dates": dates,
        "labels": [d.strftime("%d-%m") for d in dates],
        "series": series,
        "per_host": per_host,
        "synthetic": synthetic,
        "has_data": has_data,
        "points": sum(1 for v in series["critica"] if v is not None),
    }


def trend(values: list, back: int = 7) -> dict | None:
    """Variación del último valor respecto de hace `back` días (o del primer dato)."""
    known = [v for v in values if v is not None]
    if len(known) < 2:
        return None
    current = known[-1]
    idx = max(0, len(values) - 1 - back)
    past = next((v for v in values[idx:] if v is not None), known[0])
    return {"delta": current - past, "current": current, "past": past}



def host_inventory(conn: psycopg.Connection, host_id: int, limit: int = 2000) -> dict[str, list[dict]]:
    """Programas y parches que son solo inventario (agente de Windows)."""
    rows = conn.execute(
        """
        SELECT ecosystem, name, version, location AS publisher FROM components
        WHERE host_id = %s AND kind = 'inventory'
        ORDER BY ecosystem, lower(name), version
        LIMIT %s
        """,
        (host_id, limit),
    ).fetchall()
    out: dict[str, list[dict]] = {}
    for r in rows:
        out.setdefault(r["ecosystem"], []).append(r)
    return out
