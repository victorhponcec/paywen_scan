# Paywen Scan — código de la aplicación

Plataforma de inteligencia de amenazas del Curso 5. Cruza el inventario de cada servidor con OSV, CISA KEV, FIRST EPSS y AlienVault OTX, y prioriza lo que hay que parchar primero.

Para instalar el servidor completo, ver [`../README.md`](../README.md) (en la carpeta `server/`). Las novedades están en [`paywen/manual/CHANGELOG.md`](paywen/manual/CHANGELOG.md).

```
server/app/
├── Dockerfile               imagen única: API (CMD) y worker (python -m worker)
├── requirements.txt
├── worker.py                entrada del worker
├── paywen/
│   ├── main.py              FastAPI: /api/v1/ingest y dashboard
│   ├── worker.py            una pasada: KEV → OSV → EPSS → OTX → prioridades → histórico
│   ├── sbom.py              SBOM de Trivy → componentes consultables en OSV
│   ├── ingest.py            guarda el inventario de un agente
│   ├── scoring.py           regla de prioridad y puntaje por host
│   ├── queries.py           consultas del dashboard (filtros, estado de agentes, histórico)
│   ├── charts.py            gráficos SVG generados en el servidor (sin JavaScript)
│   ├── icons.py             íconos de Lucide incrustados (static/icons, licencia ISC)
│   ├── docs.py, manual/     sección Docs: manuales en Markdown y CHANGELOG
│   ├── demo.py              datos de ejemplo para el histórico (python -m paywen.demo)
│   ├── intel/               clientes de OSV, KEV, EPSS y OTX
│   ├── schema.sql           esquema (se aplica solo al arrancar)
│   ├── templates/, static/  dashboard (sin JavaScript ni recursos externos)
├── tests/                   prueba de punta a punta con APIs simuladas
│   └── windows/             harness.ps1 (prueba el agente de Windows con pwsh) y su inventario
└── compose.dev.yaml         entorno local con PostgreSQL
```

## Regla de prioridad

1. En **CISA KEV** → **Crítica**.
2. **EPSS ≥ 10 %** → **Alta**.
3. El resto según CVSS: ≥ 9 Alta, ≥ 7 Media, menor Baja. Sin CVSS, se usa la prioridad de la distro.
4. **+1 nivel** si el paquete está detrás de un puerto en escucha.

El puntaje del host (0–100) suma 25 por cada hallazgo Crítico, 8 por Alto, 2 por Medio y 0,2 por Bajo, con un tope de 100.

## Pruebas

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
DATABASE_URL=postgresql://usuario:clave@localhost:5432/paywen_test pytest -q tests
```

La prueba **borra el esquema** de esa base: usa una base de prueba.

## Construir la imagen

```bash
docker build -t paywen-scan:1.2.0 .
```

La misma imagen sirve para la API (comando por omisión) y para el worker (`python -m worker`).

## Probar el agente de Windows sin Windows

Con PowerShell 7 (`pwsh`) y, opcionalmente, Trivy:

```bash
pwsh -File tests/windows/harness.ps1 -Script ../../agent-windows/install.ps1 -Out /tmp/payload.json [-Trivy trivy -ScanPath carpeta]
```

El harness reemplaza los comandos propios de Windows por datos de ejemplo y arma el inventario con las funciones reales del agente. `tests/windows/payload.json` se generó así y lo usa la prueba de punta a punta.
