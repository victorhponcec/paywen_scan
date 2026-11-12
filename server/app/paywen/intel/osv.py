"""OSV.dev: qué vulnerabilidades afectan exactamente a cada paquete y versión.

1. POST /v1/querybatch con todos los componentes (hasta 1000 por llamada).
   Devuelve solo IDs y fecha de modificación.
2. GET /v1/vulns/{id} para el detalle, con caché en la tabla osv_vulns: solo
   se vuelve a pedir si OSV indica que el registro cambió. Se guarda una
   versión recortada (ver trim) y por lotes, para no agotar la memoria con los
   miles de registros del kernel.
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Iterable

import httpx
from psycopg.types.json import Jsonb

from . import is_cve

log = logging.getLogger(__name__)

API = "https://api.osv.dev/v1"
BATCH_SIZE = 1000
DETAIL_WORKERS = 8
DETAIL_CHUNK = 200


def query_batch(client: httpx.Client, queries: list[dict[str, Any]]) -> list[list[dict[str, str]]]:
    """Para cada consulta, la lista de {id, modified} que la afectan."""
    results: list[list[dict[str, str]]] = [[] for _ in queries]
    pending = list(range(len(queries)))
    tokens: dict[int, str] = {}
    while pending:
        for start in range(0, len(pending), BATCH_SIZE):
            chunk = pending[start:start + BATCH_SIZE]
            body = {"queries": [dict(queries[i], **({"page_token": tokens[i]} if i in tokens else {})) for i in chunk]}
            resp = client.post(f"{API}/querybatch", json=body)
            resp.raise_for_status()
            for i, res in zip(chunk, resp.json().get("results", [])):
                results[i].extend(res.get("vulns") or [])
                if res.get("next_page_token"):
                    tokens[i] = res["next_page_token"]
                else:
                    tokens.pop(i, None)
        pending = sorted(tokens)
    return results


def trim(record: dict[str, Any]) -> dict[str, Any]:
    """Deja solo lo que usa la app. Los registros del kernel de Ubuntu traen la
    lista completa de versiones afectadas de cada variante (linux-aws,
    linux-azure…) y pesan cientos de KB; sin "versions" quedan en pocos KB."""
    keep = {k: record[k] for k in ("id", "modified", "withdrawn", "aliases", "upstream", "summary", "severity")
            if k in record}
    if record.get("details"):
        keep["details"] = record["details"][:1000]
    affected = []
    for a in record.get("affected") or []:
        item = {k: a[k] for k in ("package", "ranges") if k in a}
        eco = a.get("ecosystem_specific") or {}
        if isinstance(eco.get("ubuntu_priority"), str):
            item["ecosystem_specific"] = {"ubuntu_priority": eco["ubuntu_priority"]}
        if item.get("ranges"):
            item["ranges"] = [
                {"type": r.get("type"), "events": r.get("events") or []}
                for r in item["ranges"] if r.get("type") != "GIT"
            ]
        affected.append(item)
    keep["affected"] = affected
    return keep


def cache_details(conn_factory, client: httpx.Client, refs: dict[str, str | None], chunk_size: int = DETAIL_CHUNK) -> int:
    """Asegura que osv_vulns tenga el detalle de cada ID (refs: id → modified).

    Descarga por lotes y guarda cada lote en su propia transacción: la memoria
    no crece con la cantidad de registros y, si el proceso se corta, lo ya
    descargado queda en caché para la próxima pasada.
    """
    if not refs:
        return 0
    with conn_factory() as conn:
        cached = {
            row["id"]: row["modified"]
            for row in conn.execute("SELECT id, modified FROM osv_vulns WHERE id = ANY(%s)", (list(refs),))
        }
    missing = [vid for vid, mod in refs.items() if vid not in cached or (mod and cached[vid] != mod)]
    if not missing:
        return 0
    log.info("OSV: descargando %s registros (%s ya en caché)", len(missing), len(refs) - len(missing))

    def get(vid: str) -> dict[str, Any] | None:
        try:
            resp = client.get(f"{API}/vulns/{vid}")
            resp.raise_for_status()
            return trim(resp.json())
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("OSV: no se pudo leer %s: %s", vid, exc)
            return None

    saved = 0
    with ThreadPoolExecutor(max_workers=DETAIL_WORKERS) as pool:
        for start in range(0, len(missing), chunk_size):
            records = [r for r in pool.map(get, missing[start:start + chunk_size]) if r]
            with conn_factory() as conn, conn.cursor() as cur:
                cur.executemany(
                    """
                    INSERT INTO osv_vulns (id, modified, data, fetched_at) VALUES (%s, %s, %s, now())
                    ON CONFLICT (id) DO UPDATE SET modified = EXCLUDED.modified, data = EXCLUDED.data,
                        fetched_at = now()
                    """,
                    [(r["id"], r.get("modified"), Jsonb(r)) for r in records],
                )
            saved += len(records)
            log.info("OSV: %s/%s registros descargados", min(start + chunk_size, len(missing)), len(missing))
    return saved


# ─── Interpretación de un registro de OSV ──────────────────────────────────────

_UBUNTU_CVE = re.compile(r"^UBUNTU-(CVE-\d{4}-\d{4,})$")
_UBUNTU_PRIORITY = {"negligible": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def cves_of(record: dict[str, Any]) -> list[str]:
    """CVEs a los que corresponde un registro (ID propio, alias o upstream)."""
    out: set[str] = set()
    vid = record.get("id", "")
    if is_cve(vid):
        out.add(vid)
    m = _UBUNTU_CVE.match(vid)
    if m:
        out.add(m.group(1))
    for alias in (record.get("aliases") or []) + (record.get("upstream") or []):
        if is_cve(alias):
            out.add(alias)
    return sorted(out)


def cvss_score(record: dict[str, Any]) -> float | None:
    from cvss import CVSS3, CVSS4

    best: float | None = None
    for sev in record.get("severity") or []:
        vector = sev.get("score") or ""
        try:
            if sev.get("type") == "CVSS_V3" and vector.startswith("CVSS:3"):
                score = float(CVSS3(vector).base_score)
            elif sev.get("type") == "CVSS_V4" and vector.startswith("CVSS:4"):
                score = float(CVSS4(vector).base_score)
            else:
                continue
        except Exception:  # noqa: BLE001 - vector mal formado: se ignora
            continue
        best = score if best is None else max(best, score)
    return best


def severity_label(record: dict[str, Any]) -> str | None:
    """Prioridad que asigna la distro (Ubuntu: negligible…critical), si existe."""
    labels = [s.get("score", "").lower() for s in record.get("severity") or [] if s.get("type") == "Ubuntu"]
    for affected in record.get("affected") or []:
        eco = affected.get("ecosystem_specific") or {}
        if isinstance(eco.get("ubuntu_priority"), str):
            labels.append(eco["ubuntu_priority"].lower())
    labels = [label for label in labels if label in _UBUNTU_PRIORITY]
    return max(labels, key=_UBUNTU_PRIORITY.get) if labels else None


def _vkey(version: str) -> tuple:
    """Clave genérica para comparar versiones (suficiente para elegir el fix)."""
    parts = re.split(r"[^0-9A-Za-z]+", version)
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in parts if p)


def fixed_version(record: dict[str, Any], ecosystem: str, name: str, version: str) -> str | None:
    """La primera versión que corrige, para este paquete, mayor que la instalada."""
    same_pkg = [
        a for a in record.get("affected") or []
        if (a.get("package") or {}).get("name", "").lower() == name.lower()
    ]
    # Un registro puede traer el mismo paquete para varias versiones de la
    # distro (Ubuntu:22.04:LTS, Ubuntu:24.04:LTS…): primero el ecosistema exacto.
    exact = [a for a in same_pkg if (a.get("package") or {}).get("ecosystem", "").lower() == ecosystem.lower()]
    family = ecosystem.lower().split(":")[0]
    candidates = exact or [
        a for a in same_pkg if (a.get("package") or {}).get("ecosystem", "").lower().startswith(family)
    ]
    fixes: list[str] = []
    for affected in candidates:
        for rng in affected.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue
            fixes += [e["fixed"] for e in rng.get("events") or [] if e.get("fixed")]
    if not fixes:
        return None
    current = _vkey(version)
    newer = [f for f in fixes if _vkey(f) > current]
    return min(newer, key=_vkey) if newer else fixes[0]


def summary(record: dict[str, Any]) -> str | None:
    text = record.get("summary") or (record.get("details") or "").strip().split("\n")[0]
    return text[:300] or None


@dataclass
class Finding:
    vuln_key: str
    osv_ids: set[str] = field(default_factory=set)
    summary: str | None = None
    cvss: float | None = None
    severity_label: str | None = None
    fixed_version: str | None = None

    def merge(self, record: dict[str, Any], ecosystem: str, name: str, version: str) -> None:
        self.osv_ids.add(record["id"])
        rec_cvss = cvss_score(record)
        if rec_cvss is not None:
            self.cvss = rec_cvss if self.cvss is None else max(self.cvss, rec_cvss)
        label = severity_label(record)
        if label and (not self.severity_label or _UBUNTU_PRIORITY[label] > _UBUNTU_PRIORITY[self.severity_label]):
            self.severity_label = label
        fix = fixed_version(record, ecosystem, name, version)
        if fix and not self.fixed_version:
            self.fixed_version = fix
        # El texto del registro del propio CVE suele ser más claro que el de un USN.
        rec_summary = summary(record)
        if rec_summary and (not self.summary or is_cve(record["id"]) or record["id"].startswith("UBUNTU-CVE")):
            self.summary = rec_summary


def findings_for(records: Iterable[dict[str, Any]], ecosystem: str, name: str, version: str) -> list[Finding]:
    """Agrupa los registros de OSV de un componente por CVE (o por ID si no hay CVE)."""
    by_key: dict[str, Finding] = {}
    for record in records:
        if record.get("withdrawn"):
            continue
        for key in cves_of(record) or [record["id"]]:
            by_key.setdefault(key, Finding(key)).merge(record, ecosystem, name, version)
    return list(by_key.values())
