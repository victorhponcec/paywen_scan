-- Esquema de Paywen Scan. Se aplica en cada arranque (todo es IF NOT EXISTS),
-- así que no hace falta una herramienta de migraciones para el curso.

CREATE TABLE IF NOT EXISTS hosts (
    id              BIGSERIAL PRIMARY KEY,
    hostname        TEXT UNIQUE NOT NULL,
    os_id           TEXT,
    os_version      TEXT,
    os_name         TEXT,
    kernel          TEXT,
    source_ip       TEXT,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    collected_at    TIMESTAMPTZ,
    inventory_hash  TEXT,           -- hash del inventario recibido
    scanned_hash    TEXT,           -- hash del inventario ya cruzado con OSV
    last_enriched   TIMESTAMPTZ,
    risk_score      INTEGER NOT NULL DEFAULT 0
);

-- Un componente por (ecosistema, nombre, versión). Para paquetes del sistema
-- se usa el paquete fuente (así lo indexa OSV) y se guardan los binarios.
CREATE TABLE IF NOT EXISTS components (
    id         BIGSERIAL PRIMARY KEY,
    host_id    BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,                  -- os | lang | inventory (solo se muestra)
    ecosystem  TEXT NOT NULL,                  -- ecosistema de OSV (o Windows / Windows KB)
    name       TEXT NOT NULL,
    version    TEXT NOT NULL,
    purl       TEXT,
    binaries   TEXT[] NOT NULL DEFAULT '{}',
    location   TEXT,                           -- ruta (lang) o fabricante (inventory)
    UNIQUE (host_id, ecosystem, name, version)
);
CREATE INDEX IF NOT EXISTS components_host_idx ON components(host_id);

CREATE TABLE IF NOT EXISTS ports (
    host_id  BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    proto    TEXT,
    address  TEXT,
    port     INTEGER,
    process  TEXT
);
CREATE INDEX IF NOT EXISTS ports_host_idx ON ports(host_id);

-- Caché de registros de OSV.
CREATE TABLE IF NOT EXISTS osv_vulns (
    id          TEXT PRIMARY KEY,
    modified    TEXT,
    data        JSONB NOT NULL,
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS kev (
    cve              TEXT PRIMARY KEY,
    vendor           TEXT,
    product          TEXT,
    name             TEXT,
    date_added       DATE,
    due_date         DATE,
    ransomware       BOOLEAN NOT NULL DEFAULT false,
    required_action  TEXT
);

CREATE TABLE IF NOT EXISTS epss (
    cve         TEXT PRIMARY KEY,
    epss        DOUBLE PRECISION NOT NULL,
    percentile  DOUBLE PRECISION NOT NULL,
    score_date  DATE,
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS otx (
    cve          TEXT PRIMARY KEY,
    pulse_count  INTEGER NOT NULL DEFAULT 0,
    pulses       JSONB NOT NULL DEFAULT '[]',
    fetched_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Un hallazgo = un componente afectado por una vulnerabilidad (por CVE si
-- tiene; si no, por el ID de OSV). La prioridad se recalcula en cada pasada
-- del worker, porque EPSS y KEV cambian a diario.
CREATE TABLE IF NOT EXISTS findings (
    id              BIGSERIAL PRIMARY KEY,
    host_id         BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    component_id    BIGINT NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    vuln_key        TEXT NOT NULL,
    osv_ids         TEXT[] NOT NULL DEFAULT '{}',
    summary         TEXT,
    cvss            DOUBLE PRECISION,
    severity_label  TEXT,
    fixed_version   TEXT,
    exposed         BOOLEAN NOT NULL DEFAULT false,
    priority_rank   SMALLINT NOT NULL DEFAULT 0,   -- 0 baja · 1 media · 2 alta · 3 crítica
    UNIQUE (component_id, vuln_key)
);
CREATE INDEX IF NOT EXISTS findings_host_idx ON findings(host_id);
CREATE INDEX IF NOT EXISTS findings_vuln_idx ON findings(vuln_key);

CREATE TABLE IF NOT EXISTS meta (
    key         TEXT PRIMARY KEY,
    value       TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─── v1.1 ─────────────────────────────────────────────────────────────────────
-- Puertos (no locales) por los que un hallazgo queda expuesto.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS exposed_ports INTEGER[] NOT NULL DEFAULT '{}';
CREATE INDEX IF NOT EXISTS findings_host_vuln_idx ON findings(host_id, vuln_key);

-- Ciclo de vida de cada vulnerabilidad en cada host: cuándo apareció y cuándo
-- se resolvió (dejó de aparecer en el inventario). "baseline" marca las que ya
-- estaban en el primer cruce del host: no cuentan como "nuevas".
CREATE TABLE IF NOT EXISTS vuln_history (
    host_id      BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    vuln_key     TEXT NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at  TIMESTAMPTZ,
    baseline     BOOLEAN NOT NULL DEFAULT false,
    max_rank     SMALLINT NOT NULL DEFAULT 0,
    PRIMARY KEY (host_id, vuln_key)
);

-- Una foto por host y por día (la última pasada del worker del día la
-- reemplaza). Es la base de los gráficos del histórico.
CREATE TABLE IF NOT EXISTS host_snapshots (
    host_id         BIGINT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    day             DATE NOT NULL,
    critica         INTEGER NOT NULL DEFAULT 0,
    alta            INTEGER NOT NULL DEFAULT 0,
    media           INTEGER NOT NULL DEFAULT 0,
    baja            INTEGER NOT NULL DEFAULT 0,
    kev             INTEGER NOT NULL DEFAULT 0,
    ransomware      INTEGER NOT NULL DEFAULT 0,
    unique_vulns    INTEGER NOT NULL DEFAULT 0,
    fixable         INTEGER NOT NULL DEFAULT 0,
    risk_score      INTEGER NOT NULL DEFAULT 0,
    components      INTEGER NOT NULL DEFAULT 0,
    new_vulns       INTEGER NOT NULL DEFAULT 0,
    resolved_vulns  INTEGER NOT NULL DEFAULT 0,
    synthetic       BOOLEAN NOT NULL DEFAULT false,   -- datos de ejemplo (paywen.demo)
    taken_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host_id, day)
);
