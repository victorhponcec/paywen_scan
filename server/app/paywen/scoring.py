"""Regla de priorización (la misma de la ficha y la presentación):

1. En CISA KEV (se explota hoy)             → Crítica
2. EPSS ≥ 10 % (probable en 30 días)        → Alta
3. El resto según gravedad:
   CVSS ≥ 9 → Alta · CVSS ≥ 7 → Media · menor → Baja
   (sin CVSS, se usa la prioridad de la distro: critical → Alta, high → Media)
4. +1 nivel si el componente está detrás de un puerto en escucha.

Puntaje de riesgo del host (0–100): suma de pesos por hallazgo, con tope.
"""

from __future__ import annotations

LEVELS = ["Baja", "Media", "Alta", "Crítica"]
LEVEL_SLUG = ["baja", "media", "alta", "critica"]
EPSS_HIGH = 0.10
HOST_WEIGHTS = {3: 25.0, 2: 8.0, 1: 2.0, 0: 0.2}


def base_rank(in_kev: bool, epss: float | None, cvss: float | None, distro_label: str | None) -> int:
    if in_kev:
        return 3
    if epss is not None and epss >= EPSS_HIGH:
        return 2
    if cvss is not None:
        return 2 if cvss >= 9 else 1 if cvss >= 7 else 0
    return {"critical": 2, "high": 1}.get((distro_label or "").lower(), 0)


def final_rank(base: int, exposed: bool) -> int:
    return min(3, base + 1) if exposed else base


def host_score(ranks: list[int]) -> int:
    return int(min(100, round(sum(HOST_WEIGHTS[r] for r in ranks))))


# ─── Exposición: qué componente está detrás de cada proceso que escucha ────────
# Heurística simple: nombre del proceso (de `ss -p`) → paquete fuente. Para
# lenguajes, un proceso java/node/python que escucha marca ese ecosistema.

PROCESS_TO_SOURCE = {
    "sshd": "openssh",
    "nginx": "nginx",
    "apache2": "apache2",
    "httpd": "httpd",
    "mysqld": "mysql-8.0",
    "mariadbd": "mariadb",
    "postgres": "postgresql-16",
    "php-fpm8.3": "php8.3",
    "named": "bind9",
    "dockerd": "docker.io",
    "containerd": "containerd",
    "master": "postfix",
    "exim4": "exim4",
    "redis-server": "redis",
    "memcached": "memcached",
    "vsftpd": "vsftpd",
    "smbd": "samba",
    "systemd-resolve": "systemd",
    "chronyd": "chrony",
}
PROCESS_TO_ECOSYSTEM = {
    "java": "Maven",
    "node": "npm",
    "python": "PyPI",
    "python3": "PyPI",
    "gunicorn": "PyPI",
    "uvicorn": "PyPI",
    # Windows
    "javaw": "Maven",
    "tomcat9": "Maven",
    "pythonw": "PyPI",
    "w3wp": "NuGet",
    "dotnet": "NuGet",
}


def exposed_matcher(process_names: set[str]):
    sources = {PROCESS_TO_SOURCE.get(p, p) for p in process_names}
    ecosystems = {PROCESS_TO_ECOSYSTEM[p] for p in process_names if p in PROCESS_TO_ECOSYSTEM}

    def is_exposed(kind: str, ecosystem: str, name: str, binaries: list[str]) -> bool:
        if kind == "lang":
            return ecosystem in ecosystems
        return name in sources or bool(set(binaries) & process_names)

    return is_exposed
