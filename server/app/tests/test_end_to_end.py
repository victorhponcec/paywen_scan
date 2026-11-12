"""Prueba de punta a punta contra un PostgreSQL real y APIs simuladas.

    DATABASE_URL=postgresql://... pytest -q tests

Recorre: ingesta → worker (OSV, KEV, EPSS, OTX) → prioridades → dashboard.
"""

from __future__ import annotations

import base64
import copy
import os

import psycopg
import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"), reason="requiere DATABASE_URL")

os.environ.setdefault("AGENT_TOKEN", "test-agent-token")
os.environ.setdefault("DASHBOARD_USER", "admin")
os.environ.setdefault("DASHBOARD_PASSWORD", "test-dashboard-pass")
os.environ.setdefault("OTX_API_KEY", "test-otx-key")

from fastapi.testclient import TestClient  # noqa: E402

from paywen import worker  # noqa: E402
from paywen.main import app  # noqa: E402
from tests.make_payload import build  # noqa: E402
from tests.mock_intel import Recorder  # noqa: E402

NGINX_DEB = {
    "type": "library", "name": "nginx", "version": "1.24.0-2ubuntu7",
    "purl": "pkg:deb/ubuntu/nginx@1.24.0-2ubuntu7?arch=amd64&distro=ubuntu-24.04",
    "properties": [{"name": "aquasecurity:trivy:SrcName", "value": "nginx"},
                   {"name": "aquasecurity:trivy:SrcVersion", "value": "1.24.0"},
                   {"name": "aquasecurity:trivy:SrcRelease", "value": "2ubuntu7"}],
}
AGENT = {"Authorization": "Bearer test-agent-token"}
AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:test-dashboard-pass").decode()}


@pytest.fixture(scope="module")
def client():
    with psycopg.connect(os.environ["DATABASE_URL"], autocommit=True) as conn:
        conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def payload():
    return build("paywen-scan-target", extra_debs=[NGINX_DEB])


def q(sql, *args):
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        return conn.execute(sql, args).fetchall()


def test_ingest_requires_token(client, payload):
    assert client.post("/api/v1/ingest", json=payload).status_code == 401
    assert client.post("/api/v1/ingest", json=payload, headers={"Authorization": "Bearer malo"}).status_code == 401


def test_ingest_validates(client):
    r = client.post("/api/v1/ingest", json={"hostname": "x"}, headers=AGENT)
    assert r.status_code == 422 and "sbom" in r.json()["detail"]
    r = client.post("/api/v1/ingest", content=b"no-json", headers=AGENT)
    assert r.status_code == 400


def test_ingest_ok(client, payload):
    r = client.post("/api/v1/ingest", json=payload, headers=AGENT)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["changed"] is True and body["components"] > 100
    again = client.post("/api/v1/ingest", json=payload, headers=AGENT).json()
    assert again["changed"] is False, "el mismo inventario no debe reemplazar componentes"
    [(curl,)] = q("SELECT binaries FROM components WHERE name = 'curl'")
    assert "libcurl4t64" in curl


def test_worker_enriches(client):
    rec = Recorder()
    assert worker.run(rec.client()) == 0
    assert any("querybatch" in c for c in rec.calls)

    rows = {r[0]: r for r in q(
        """SELECT f.vuln_key, c.name, f.priority_rank, f.fixed_version, f.exposed, f.osv_ids, f.cvss
           FROM findings f JOIN components c ON c.id = f.component_id"""
    )}
    # sudo: en KEV → Crítica; fix del ecosistema exacto (24.04, no 22.04); USN y CVE fusionados.
    sudo = rows["CVE-2025-32463"]
    assert sudo[2] == 3 and sudo[3] == "1.9.15p5-3ubuntu5.24.04.9"
    assert set(sudo[5]) == {"UBUNTU-CVE-2025-32463", "USN-7604-1"}
    assert round(sudo[6], 1) == 8.8
    # CVE que solo viene del USN: sin CVSS, sin KEV, EPSS bajo → Baja.
    assert rows["CVE-2025-32462"][2] == 0
    # log4j: KEV + ransomware → Crítica; fix del rango correcto (2.13.0 → 2.15.0).
    assert rows["CVE-2021-44228"][2] == 3 and rows["CVE-2021-44228"][3] == "2.15.0"
    # Django: CVSS 9.8 / EPSS 31 % → Alta; fix 3.2.5.
    assert rows["CVE-2021-35042"][2] == 2 and rows["CVE-2021-35042"][3] == "3.2.5"
    # nginx: CVSS 5.3 → Baja, pero escucha en el 80 → sube a Media.
    assert rows["CVE-2025-23419"][4] is True and rows["CVE-2025-23419"][2] == 1
    # openssl: paginación de OSV (dos páginas) y sin parche.
    assert "CVE-2024-0001" in rows and "CVE-2024-0002" in rows and rows["CVE-2024-0001"][3] is None
    # Registro retirado: no genera hallazgo.
    assert "CVE-2023-9999" not in rows
    # La caché guarda registros recortados (sin "versions" ni "references").
    [(trimmed,)] = q("SELECT data FROM osv_vulns WHERE id = 'UBUNTU-CVE-2024-0001'")
    assert "versions" not in trimmed["affected"][0] and "references" not in trimmed
    assert len(str(trimmed)) < 2000

    [(score,)] = q("SELECT risk_score FROM hosts WHERE hostname = 'paywen-scan-target'")
    assert score >= 50
    [(pulses,)] = q("SELECT pulse_count FROM otx WHERE cve = 'CVE-2021-44228'")
    assert pulses == 2


def test_worker_uses_cache(client):
    rec = Recorder()
    assert worker.run(rec.client()) == 0
    assert not any("/v1/vulns/" in c for c in rec.calls), "no debe volver a descargar registros en caché"
    assert not any("querybatch" in c for c in rec.calls), "host sin cambios y recién revisado: no se recruza"


def test_inventory_change_triggers_rescan(client, payload):
    changed = copy.deepcopy(payload)
    changed["sbom"]["components"] = [c for c in changed["sbom"]["components"] if c.get("name") != "lodash"]
    assert client.post("/api/v1/ingest", json=changed, headers=AGENT).json()["changed"] is True
    rec = Recorder()
    assert worker.run(rec.client()) == 0
    assert any("querybatch" in c for c in rec.calls)
    assert q("SELECT count(*) FROM findings WHERE vuln_key = 'CVE-2021-44228'")[0][0] == 1


def test_dashboard_auth(client):
    assert client.get("/").status_code == 401
    bad = {"Authorization": "Basic " + base64.b64encode(b"admin:mala").decode()}
    assert client.get("/", headers=bad).status_code == 401


def test_dashboard_pages(client):
    r = client.get("/", headers=AUTH)
    assert r.status_code == 200
    assert "paywen-scan-target" in r.text and "CVE-2021-44228" in r.text
    assert "Content-Security-Policy" in r.headers
    host_id = q("SELECT id FROM hosts WHERE hostname = 'paywen-scan-target'")[0][0]
    for path in ["/findings", "/findings?kev=1", "/findings?priority=critica&exposed=1",
                 "/findings?q=log4j", f"/hosts/{host_id}", f"/hosts/{host_id}?priority=alta", "/campaigns"]:
        assert client.get(path, headers=AUTH).status_code == 200, path
    kev_only = client.get("/findings?kev=1", headers=AUTH).text
    assert "CVE-2025-32463" in kev_only and "CVE-2021-35042" not in kev_only
    assert "Log4Shell exploitation" in client.get("/campaigns", headers=AUTH).text
    assert client.get("/hosts/999999", headers=AUTH).status_code == 404


def test_csv_export_is_safe(client):
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        conn.execute("UPDATE findings SET summary = '=HYPERLINK(\"http://evil\")' WHERE vuln_key = 'CVE-2021-44228'")
    r = client.get("/findings.csv?kev=1", headers=AUTH)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "'=HYPERLINK" in r.text and ",=HYPERLINK" not in r.text
    assert r.text.splitlines()[0].lstrip("﻿").startswith("prioridad,vulnerabilidad")


# ─── v1.1: histórico, exposición por puerto, filtros, estado, docs ────────────

def test_history_snapshot_and_baseline(client):
    rows = q("SELECT critica, kev, ransomware, unique_vulns, new_vulns, synthetic FROM host_snapshots")
    assert len(rows) == 1, "una foto por host y por día, aunque el worker corra varias veces"
    critica, kev, ransomware, unique, new, synthetic = rows[0]
    assert critica >= 2 and kev >= 2 and ransomware >= 1 and unique > 5 and not synthetic
    assert new == 0, "lo que había en el primer cruce es línea base, no 'nuevas'"
    assert q("SELECT count(*) FROM vuln_history WHERE NOT baseline")[0][0] == 0


def test_resolved_and_new(client, payload):
    # Sacar log4j del inventario → sus CVEs quedan resueltos.
    changed = copy.deepcopy(payload)
    changed["sbom"]["components"] = [c for c in changed["sbom"]["components"]
                                     if "log4j" not in (c.get("purl") or "")]
    assert client.post("/api/v1/ingest", json=changed, headers=AGENT).json()["changed"] is True
    assert worker.run(Recorder().client()) == 0
    [(resolved_at,)] = q("SELECT resolved_at FROM vuln_history WHERE vuln_key = 'CVE-2021-44228'")
    assert resolved_at is not None
    [(resolved,)] = q("SELECT resolved_vulns FROM host_snapshots")
    assert resolved >= 1
    # Volver a instalarlo → reaparece (ya no resuelto) y cuenta como hallazgo de nuevo.
    assert client.post("/api/v1/ingest", json=payload, headers=AGENT).json()["changed"] is True
    assert worker.run(Recorder().client()) == 0
    [(resolved_at,)] = q("SELECT resolved_at FROM vuln_history WHERE vuln_key = 'CVE-2021-44228'")
    assert resolved_at is None


def test_exposed_ports(client):
    [(ports, exposed)] = q("SELECT exposed_ports, exposed FROM findings WHERE vuln_key = 'CVE-2025-23419'")
    assert exposed and ports == [80]
    # Un puerto que solo escucha en 127.0.0.1 no expone nada.
    assert q("SELECT count(*) FROM findings WHERE 3306 = ANY(exposed_ports)")[0][0] == 0


def test_new_filters(client):
    host_id = q("SELECT id FROM hosts WHERE hostname = 'paywen-scan-target'")[0][0]
    os_name = q("SELECT os_name FROM hosts")[0][0]
    by_port = client.get("/findings?port=80", headers=AUTH).text
    assert "CVE-2025-23419" in by_port and "CVE-2021-44228" not in by_port
    assert "80" in by_port and "tag-exposed" in by_port
    maven = client.get("/findings?eco=Maven", headers=AUTH).text
    assert "CVE-2021-44228" in maven and "CVE-2025-32463" not in maven
    ransom = client.get("/findings?ransomware=1", headers=AUTH).text
    assert "CVE-2021-44228" in ransom and "CVE-2025-32463" not in ransom
    epss = client.get("/findings?epss_min=0.1", headers=AUTH).text
    assert "CVE-2021-35042" in epss and "CVE-2025-32462" not in epss
    assert "CVE-2025-32462" not in client.get("/findings?cvss_min=9", headers=AUTH).text
    for path in [f"/findings?host={host_id}", f"/findings?os={os_name}", "/findings?new=7", "/findings?epss=1",
                 f"/hosts/{host_id}?port=80", "/findings.csv?port=80&eco=Maven"]:
        assert client.get(path, headers=AUTH).status_code == 200, path
    # El panel "Más filtros" queda abierto si hay filtros avanzados.
    assert "<details class=\"more\" open" in client.get("/findings?port=80", headers=AUTH).text


def test_agent_status():
    from datetime import datetime, timedelta, timezone

    from paywen import queries

    now = datetime.now(timezone.utc) + timedelta(days=1)   # después de que "arrancó" la app
    assert queries.agent_status(now - timedelta(minutes=30), now)["key"] == "online"
    assert queries.agent_status(now - timedelta(hours=3), now)["key"] == "late"
    assert queries.agent_status(now - timedelta(hours=7), now)["key"] == "offline"
    assert queries.agent_status(None, now)["key"] == "offline"
    # Si el servidor estuvo apagado, no se culpa al agente: el atraso parte cuando arrancó la app.
    just_started = queries.STARTED_AT + timedelta(minutes=20)
    assert queries.agent_status(queries.STARTED_AT - timedelta(hours=20), just_started)["key"] == "online"


def test_new_pages(client):
    host_id = q("SELECT id FROM hosts WHERE hostname = 'paywen-scan-target'")[0][0]
    pages = ["/hosts", "/hosts?status=online", "/hosts?q=target", "/history", "/history?days=7",
             f"/history?host={host_id}&days=90", "/docs", "/docs/descripcion", "/docs/servidor", "/docs/agente",
             "/docs/agente-windows", "/docs/changelog"]
    for path in pages:
        r = client.get(path, headers=AUTH)
        assert r.status_code == 200, path
        assert "<script" not in r.text, f"{path}: el dashboard no usa JavaScript"
    overview = client.get("/", headers=AUTH).text
    assert 'class="chart donut"' in overview and "trend-card" in overview and "status status-" in overview
    assert "En línea" in client.get("/hosts", headers=AUTH).text
    from paywen import __version__
    assert f"v{__version__}" in client.get("/docs/changelog", headers=AUTH).text
    assert client.get("/docs/no-existe", headers=AUTH).status_code == 404
    assert client.get("/history?host=abc&days=999", headers=AUTH).status_code == 200
    assert client.get("/logout").status_code == 401
    assert client.get("/healthz").json()["version"] == __version__


def test_demo_history(client):
    from paywen import demo

    assert demo.generate(10) == 10
    assert demo.generate(10) == 0, "no duplica días ya generados"
    hist = client.get("/history?days=30", headers=AUTH).text
    assert "datos de ejemplo" in hist and 'class="chart"' in hist
    assert q("SELECT count(*) FROM host_snapshots WHERE NOT synthetic")[0][0] == 1, "no pisa la foto real"
    assert demo.clear() == 10
    assert "datos de ejemplo" not in client.get("/history?days=30", headers=AUTH).text


# ─── v1.2: agente de Windows ──────────────────────────────────────────────────
# tests/windows/payload.json lo generó el agente real (paywen-agent-windows/install.ps1)
# con tests/windows/harness.ps1: programas, parches KB, puertos y librerías de Trivy.

def test_windows_agent_inventory(client):
    import json
    from pathlib import Path

    payload = json.loads(Path(__file__).with_name("windows").joinpath("payload.json").read_text(encoding="utf-8-sig"))
    r = client.post("/api/v1/ingest", json=payload, headers=AGENT).json()
    assert r["components"] == 12, "4 programas + 2 KB + 6 librerías"
    assert any("solo como inventario" in w for w in r["warnings"])
    rec = Recorder()
    assert worker.run(rec.client()) == 0
    assert "NuGet" in rec.ecosystems and "npm" in rec.ecosystems
    assert not rec.ecosystems & {"Windows", "Windows KB"}, "lo que es solo inventario no se consulta en OSV"
    host_id, ports = q("SELECT h.id, (SELECT count(*) FROM ports p WHERE p.host_id = h.id) FROM hosts h "
                       "WHERE hostname = 'srv-win-01'")[0]
    assert ports == 6, "todos los puertos (el prototipo enviaba uno solo)"
    page = client.get(f"/hosts/{host_id}", headers=AUTH).text
    for text in ("Software instalado", "Google Chrome", "Igor Pavlov", "KB5034439", "solo inventario"):
        assert text in page, text
    assert "CVE-2021-35042" in page, "las librerías de Trivy en Windows sí se cruzan"


def test_windows_inventory_only_host(client):
    import json
    from pathlib import Path

    payload = json.loads(Path(__file__).with_name("windows").joinpath("payload.json").read_text(encoding="utf-8-sig"))
    payload["hostname"] = "srv-win-02"
    payload["sbom"]["components"] = [c for c in payload["sbom"]["components"] if c["purl"].startswith("pkg:generic/")]
    assert client.post("/api/v1/ingest", json=payload, headers=AGENT).json()["components"] == 6
    assert worker.run(Recorder().client()) == 0
    assert "solo inventario" in client.get("/hosts?q=srv-win-02", headers=AUTH).text
