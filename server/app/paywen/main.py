"""API y dashboard de Paywen Scan.

- POST /api/v1/ingest  → recibe el inventario de un agente (Bearer token).
- GET  /healthz        → chequeo de vida (sin base de datos).
- Dashboard (usuario y contraseña, HTTP Basic sobre HTTPS):
    /                  resumen
    /findings          hallazgos con filtros   (/findings.csv para exportar)
    /hosts             servidores y estado de sus agentes
    /hosts/{id}        detalle de un servidor
    /history           histórico (consolidado o por servidor)
    /campaigns         campañas de OTX que tocan el inventario
    /docs              documentación y novedades (changelog)
"""

from __future__ import annotations

import csv
import io
import json
import logging
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from . import __version__, charts, config, db, docs, ingest, queries
from .icons import icon
from .scoring import LEVEL_SLUG, LEVELS

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("paywen.api")
logging.getLogger("httpx").setLevel(logging.WARNING)

BASE = Path(__file__).parent
MAX_BODY_BYTES = 50 * 1024 * 1024  # un SBOM grande pesa unos pocos MB
DISPLAY_TZ = ZoneInfo(config.env("DISPLAY_TZ", "America/Santiago"))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    await run_in_threadpool(db.wait_for_db)
    yield


app = FastAPI(title="Paywen Scan", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")


# ─── Formato para las plantillas ──────────────────────────────────────────────

def fmt_dt(value: datetime | None) -> str:
    if not value:
        return "—"
    return value.astimezone(DISPLAY_TZ).strftime("%d-%m-%Y %H:%M")


def time_ago(value: datetime | None) -> str:
    if not value:
        return "nunca"
    seconds = int((datetime.now(timezone.utc) - value).total_seconds())
    if seconds < 60:
        return "hace segundos"
    if seconds < 3600:
        return f"hace {seconds // 60} min"
    if seconds < 86400:
        return f"hace {seconds // 3600} h"
    return f"hace {seconds // 86400} d"


def fmt_pct(value: float | None, digits: int = 1) -> str:
    if value is None:
        return "—"
    return f"{value * 100:.{digits}f} %".replace(".", ",")


def fmt_score(value: float | None) -> str:
    return "—" if value is None else f"{value:.1f}".replace(".", ",")


templates.env.filters.update(dt=fmt_dt, ago=time_ago, pct=fmt_pct, score=fmt_score)
def fmt_int(value) -> str:
    return "—" if value is None else f"{int(value):,}".replace(",", ".")


def fmt_delta(value) -> str:
    if value is None:
        return ""
    value = int(round(value))
    return ("+" if value > 0 else "") + fmt_int(value) if value else "sin cambio"


def package_rows(packages: list[dict], base: str = "/findings") -> list:
    from urllib.parse import urlencode

    sep = "&" if "?" in base else "?"
    return [
        (p["name"], f"{base}{sep}{urlencode({'q': p['name']})}",
         [("Crítica", "s-critica", p["critica"]), ("Alta", "s-alta", p["alta"])])
        for p in packages
    ]


templates.env.filters.update(n=fmt_int, delta=fmt_delta)
templates.env.globals.update(
    LEVELS=LEVELS, LEVEL_SLUG=LEVEL_SLUG, version=__version__, icon=icon, charts=charts,
    STATUS_LABELS=queries.STATUS_LABELS, EPSS_CHOICES=queries.EPSS_CHOICES,
    CVSS_CHOICES=queries.CVSS_CHOICES, NEW_CHOICES=queries.NEW_CHOICES, trend=queries.trend,
    package_rows=package_rows,
)
RANGES = (7, 30, 90)


# ─── Seguridad ────────────────────────────────────────────────────────────────

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    )
    if request.url.path != "/healthz" and not request.url.path.startswith("/static"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


basic = HTTPBasic(auto_error=False, realm="Paywen Scan")


def require_user(credentials: HTTPBasicCredentials | None = Depends(basic)) -> str:
    user, password = config.dashboard_credentials()
    if not password:
        raise HTTPException(503, "El dashboard no tiene contraseña configurada (dashboard_password en el secreto de la app)")
    ok = credentials is not None and secrets.compare_digest(
        credentials.username.encode(), user.encode()
    ) & secrets.compare_digest(credentials.password.encode(), password.encode())
    if not ok:
        raise HTTPException(401, "Credenciales inválidas", headers={"WWW-Authenticate": 'Basic realm="Paywen Scan"'})
    return user


def require_agent(request: Request) -> None:
    expected = config.agent_token()
    if not expected:
        raise HTTPException(503, "La app no tiene token de agentes configurado")
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(token.strip().encode(), expected.encode()):
        raise HTTPException(401, "Token inválido", headers={"WWW-Authenticate": "Bearer"})


# ─── API ──────────────────────────────────────────────────────────────────────

@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "version": __version__}


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response((BASE / "static" / "favicon.svg").read_bytes(), media_type="image/svg+xml")


@app.post("/api/v1/ingest", dependencies=[Depends(require_agent)])
async def ingest_inventory(request: Request) -> JSONResponse:
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY_BYTES:
        raise HTTPException(413, "Inventario demasiado grande")
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(413, "Inventario demasiado grande")
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(400, "El cuerpo no es JSON válido") from None

    source_ip = request.client.host if request.client else None

    def save() -> dict:
        with db.transaction() as conn:
            return ingest.store(conn, payload, source_ip)

    try:
        result = await run_in_threadpool(save)
    except ingest.InvalidPayload as exc:
        raise HTTPException(422, str(exc)) from None
    return JSONResponse(result)


# ─── Dashboard ────────────────────────────────────────────────────────────────

def _read(fn, *args):
    conn = db.connect()
    try:
        return fn(conn, *args)
    finally:
        conn.close()


@app.get("/", response_class=HTMLResponse)
def overview(request: Request, user: str = Depends(require_user)):
    def load(conn):
        hosts = queries.hosts(conn)
        return {
            "kpi": queries.overview(conn),
            "hosts": hosts,
            "status": queries.status_counts(hosts),
            "hist": queries.history(conn, days=30),
            "dist": queries.distribution(conn),
            "packages": queries.top_packages(conn),
            "top": queries.findings(conn, queries.Filters(), limit=12),
            "campaigns": queries.campaigns(conn, limit=8),
        }

    data = _read(load)
    return templates.TemplateResponse(request, "overview.html", {"nav": "resumen", "user": user, **data})


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request, user: str = Depends(require_user)):
    filters = queries.Filters.from_query(dict(request.query_params))

    def load(conn):
        return {"rows": queries.findings(conn, filters), "options": queries.filter_options(conn)}

    data = _read(load)
    return templates.TemplateResponse(
        request, "findings.html", {"nav": "hallazgos", "user": user, "f": filters, **data}
    )


@app.get("/findings.csv")
def findings_csv(request: Request, user: str = Depends(require_user)) -> Response:
    filters = queries.Filters.from_query(dict(request.query_params))
    rows = _read(queries.findings, filters, 5000)

    def cell(value) -> str:
        text = "" if value is None else str(value)
        # Evita inyección de fórmulas al abrir el CSV en Excel/Sheets.
        return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow([
        "prioridad", "vulnerabilidad", "paquete", "ecosistema", "versiones", "hosts", "cvss",
        "epss", "percentil_epss", "kev", "ransomware", "expuesto", "puertos", "version_que_corrige",
        "pulses_otx", "resumen",
    ])
    for r in rows:
        writer.writerow([cell(v) for v in (
            LEVELS[r["rank"]], r["vuln_key"], r["package"], r["ecosystem"], r["versions"], r["hosts"],
            r["cvss"], r["epss"], r["percentile"], "sí" if r["in_kev"] else "no",
            "sí" if r["ransomware"] else "no", "sí" if r["exposed"] else "no",
            " ".join(str(p) for p in r["ports"]), r["fixed_version"], r["pulses"], r["summary"],
        )])
    stamp = datetime.now(DISPLAY_TZ).strftime("%Y%m%d-%H%M")
    return Response(
        "﻿" + out.getvalue(),  # BOM para que Excel lea bien los acentos
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="paywen-hallazgos-{stamp}.csv"'},
    )


@app.get("/hosts/{host_id}", response_class=HTMLResponse)
def host_page(host_id: int, request: Request, user: str = Depends(require_user)):
    filters = queries.Filters.from_query(dict(request.query_params), host_id=host_id)

    def load(conn):
        host = queries.host(conn, host_id)
        if not host:
            return None
        return {
            "host": host,
            "ports": queries.host_ports(conn, host_id),
            "ecosystems": queries.host_component_counts(conn, host_id),
            "inventory": queries.host_inventory(conn, host_id),
            "rows": queries.findings(conn, filters, limit=500),
            "options": queries.filter_options(conn),
            "hist": queries.history(conn, days=30, host_id=host_id),
            "dist": queries.distribution(conn, host_id),
            "packages": queries.top_packages(conn, host_id),
        }

    data = _read(load)
    if data is None:
        raise HTTPException(404, "Host no encontrado")
    return templates.TemplateResponse(request, "host.html", {"nav": "servidores", "user": user, "f": filters, **data})


@app.get("/hosts", response_class=HTMLResponse)
def hosts_page(request: Request, user: str = Depends(require_user)):
    params = dict(request.query_params)
    f = {
        "os": (params.get("os") or "").strip()[:100] or None,
        "status": params.get("status") if params.get("status") in queries.STATUS_LABELS else None,
        "q": (params.get("q") or "").strip()[:100] or None,
    }

    def load(conn):
        everyone = queries.hosts(conn)
        rows = queries.hosts(conn, os_name=f["os"], q=f["q"], status=f["status"])
        return {"rows": rows, "status": queries.status_counts(everyone), "total": len(everyone),
                "options": queries.filter_options(conn), "hint": queries.agent_status(None)["hint"]}

    data = _read(load)
    return templates.TemplateResponse(request, "hosts.html", {"nav": "servidores", "user": user, "f": f, **data})


@app.get("/history", response_class=HTMLResponse)
def history_page(request: Request, user: str = Depends(require_user)):
    params = dict(request.query_params)
    days = int(params["days"]) if params.get("days", "").isdigit() and int(params["days"]) in RANGES else 30
    host_id = int(params["host"]) if params.get("host", "").isdigit() else None

    def load(conn):
        options = queries.filter_options(conn)
        selected = next((h for h in options["hosts"] if h["id"] == host_id), None)
        hist = queries.history(conn, days=days, host_id=selected["id"] if selected else None)
        names = {h["id"]: h["hostname"] for h in options["hosts"]}
        return {"hist": hist, "options": options, "selected": selected, "names": names}

    data = _read(load)
    return templates.TemplateResponse(
        request, "history.html", {"nav": "historico", "user": user, "days": days, "ranges": RANGES, **data}
    )


@app.get("/docs", response_class=HTMLResponse)
def docs_index(request: Request, user: str = Depends(require_user)):
    return templates.TemplateResponse(
        request, "docs.html", {"nav": "docs", "user": user, "pages": docs.PAGES, "page": None}
    )


@app.get("/docs/{slug}", response_class=HTMLResponse)
def docs_page(slug: str, request: Request, user: str = Depends(require_user)):
    page = docs.render(slug)
    if page is None:
        raise HTTPException(404, "Página de documentación no encontrada")
    return templates.TemplateResponse(
        request, "docs.html", {"nav": "docs", "user": user, "pages": docs.PAGES, "page": page}
    )


@app.get("/logout", response_class=HTMLResponse)
def logout(request: Request):
    # Con HTTP Basic el navegador guarda la contraseña; un 401 hace que la olvide.
    return templates.TemplateResponse(
        request, "logout.html", {"nav": None}, status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="Paywen Scan"'},
    )


@app.get("/campaigns", response_class=HTMLResponse)
def campaigns_page(request: Request, user: str = Depends(require_user)):
    rows = _read(queries.campaigns, 100)
    return templates.TemplateResponse(request, "campaigns.html", {"nav": "campanas", "user": user, "rows": rows})


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/") or exc.status_code == 401:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)
    return templates.TemplateResponse(
        request, "error.html", {"status": exc.status_code, "detail": exc.detail, "nav": None},
        status_code=exc.status_code, headers=exc.headers,
    )
