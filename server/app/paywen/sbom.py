"""Traduce el inventario del agente (SBOM CycloneDX de Trivy) a componentes
que se pueden consultar en OSV.

Reglas importantes:
- Paquetes del sistema (deb/rpm/apk): OSV los indexa por PAQUETE FUENTE, no
  por binario (libcurl4t64 → curl). Trivy deja el nombre y la versión fuente
  en las propiedades aquasecurity:trivy:SrcName/SrcVersion/SrcRelease/SrcEpoch.
  Se agrupan los binarios de una misma fuente en un solo componente.
- El ecosistema del sistema sale del os-release que envía el agente:
  Ubuntu 24.04 → "Ubuntu:24.04:LTS", Debian 12 → "Debian:12", etc.
- Paquetes de lenguajes: el ecosistema sale del tipo de purl (pypi → PyPI,
  maven → Maven con nombre grupo:artefacto, npm con @scope, …).
- Programas de Windows y parches KB (purl pkg:generic, los envía el agente de
  Windows): se guardan como inventario (kind = "inventory"). OSV no tiene datos
  de Windows, así que se muestran en el dashboard pero no se cruzan.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator
from urllib.parse import unquote

TRIVY = "aquasecurity:trivy:"

LANG_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
    "pub": "Pub",
    "hex": "Hex",
    "conan": "ConanCenter",
}
OS_PURL_TYPES = {"deb", "rpm", "apk"}
HOTFIX_NAMESPACE = "microsoft-hotfix"
# Ecosistemas que solo son inventario: no existen en OSV y no se consultan.
INVENTORY_ECOSYSTEMS = {"Windows", "Windows KB", "Software"}


@dataclass
class Purl:
    type: str
    namespace: str | None
    name: str
    version: str | None
    qualifiers: dict[str, str] = field(default_factory=dict)


def parse_purl(purl: str) -> Purl | None:
    """Parser mínimo de Package URL (pkg:tipo/espacio/nombre@versión?q=v#sub)."""
    if not purl or not purl.startswith("pkg:"):
        return None
    rest = purl[4:].split("#", 1)[0]
    qualifiers: dict[str, str] = {}
    if "?" in rest:
        rest, query = rest.split("?", 1)
        for pair in query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[k.lower()] = unquote(v)
    version = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version)
    parts = rest.strip("/").split("/")
    if len(parts) < 2:
        return None
    ptype = parts[0].lower()
    name = unquote(parts[-1])
    namespace = "/".join(unquote(p) for p in parts[1:-1]) or None
    return Purl(ptype, namespace, name, version, qualifiers)


def os_ecosystem(os_id: str | None, version_id: str | None) -> str | None:
    """Ecosistema de OSV para el sistema operativo, o None si no se soporta."""
    if not os_id or not version_id:
        return None
    os_id = os_id.lower()
    major = version_id.split(".")[0]
    if os_id == "ubuntu":
        # Las LTS son las .04 de años pares (20.04, 22.04, 24.04…).
        lts = version_id.endswith(".04") and major.isdigit() and int(major) % 2 == 0
        return f"Ubuntu:{version_id}" + (":LTS" if lts else "")
    if os_id == "debian":
        return f"Debian:{major}"
    if os_id == "alpine":
        return "Alpine:v" + ".".join(version_id.split(".")[:2])
    if os_id == "almalinux":
        return f"AlmaLinux:{major}"
    if os_id == "rocky":
        return f"Rocky Linux:{major}"
    return None


def _props(component: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for prop in component.get("properties") or []:
        name = prop.get("name", "")
        if name.startswith(TRIVY):
            out[name[len(TRIVY):]] = str(prop.get("value", ""))
    return out


def _source_version(props: dict[str, str], fallback: str) -> str:
    """Versión del paquete fuente en formato del gestor (epoch:versión-release)."""
    version = props.get("SrcVersion")
    if not version:
        return fallback
    release = props.get("SrcRelease")
    if release and not version.endswith("-" + release):
        version = f"{version}-{release}"
    epoch = props.get("SrcEpoch")
    if epoch and epoch != "0" and not version.startswith(epoch + ":"):
        version = f"{epoch}:{version}"
    return version


def iter_components(bom: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Recorre todos los componentes, incluidos los anidados."""
    stack = list(bom.get("components") or [])
    while stack:
        comp = stack.pop()
        yield comp
        stack.extend(comp.get("components") or [])


@dataclass
class Component:
    kind: str           # os | lang
    ecosystem: str
    name: str
    version: str
    purl: str | None
    binaries: set[str] = field(default_factory=set)
    location: str | None = None

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)


def extract_components(payload: dict[str, Any]) -> tuple[list[Component], list[str]]:
    """Devuelve (componentes, avisos)."""
    os_info = payload.get("os") or {}
    os_eco = os_ecosystem(os_info.get("id"), os_info.get("version_id"))
    warnings: list[str] = []
    found: dict[tuple[str, str, str], Component] = {}
    skipped_os = 0

    is_windows = (os_info.get("id") or "").lower() == "windows"
    inventory = 0

    for comp in iter_components(payload.get("sbom") or {}):
        purl_text = comp.get("purl") or ""
        purl = parse_purl(purl_text)
        if not purl:
            continue
        if purl.type == "generic":
            # Programa instalado o parche KB: solo inventario.
            name = str(comp.get("name") or purl.name)[:300]
            version = str(comp.get("version") or purl.version or "")[:120]
            if not name or not version:
                continue
            if purl.namespace == HOTFIX_NAMESPACE:
                ecosystem = "Windows KB"
            else:
                ecosystem = "Windows" if is_windows else "Software"
            item = Component("inventory", ecosystem, name, version, purl_text[:1000],
                             location=purl.qualifiers.get("publisher", "")[:200] or None)
            found.setdefault(item.key, item)
            inventory += 1
            continue
        if comp.get("type") not in (None, "library"):
            continue  # operating-system, application, etc.
        props = _props(comp)
        version = comp.get("version") or purl.version
        if not version:
            continue

        if purl.type in OS_PURL_TYPES:
            if not os_eco:
                skipped_os += 1
                continue
            name = props.get("SrcName") or purl.name
            src_version = _source_version(props, version)
            item = Component("os", os_eco, name, src_version, purl_text)
            item = found.setdefault(item.key, item)
            item.binaries.add(purl.name)
            continue

        ecosystem = LANG_ECOSYSTEMS.get(purl.type)
        if not ecosystem:
            continue
        if purl.type == "maven" and purl.namespace:
            name = f"{purl.namespace}:{purl.name}"
        elif purl.type == "npm" and purl.namespace:
            name = f"{purl.namespace}/{purl.name}"
        elif purl.type == "golang" and purl.namespace:
            name = f"{purl.namespace}/{purl.name}"
        else:
            name = purl.name
        item = Component("lang", ecosystem, name, version, purl_text, location=props.get("FilePath"))
        item = found.setdefault(item.key, item)
        if not item.location and props.get("FilePath"):
            item.location = props.get("FilePath")

    if inventory:
        warnings.append(
            f"{inventory} programas o parches se guardaron solo como inventario: OSV no tiene datos de "
            "vulnerabilidades para ellos (las librerías con purl, por ejemplo de Trivy, sí se cruzan)"
        )
    if skipped_os:
        warnings.append(
            f"Sistema operativo no soportado para cruce con OSV "
            f"({os_info.get('id')} {os_info.get('version_id')}): se omitieron {skipped_os} paquetes"
        )
    return sorted(found.values(), key=lambda c: c.key), warnings


PROCESS_RE = re.compile(r'\("([^"]+)"')


def process_names(process_field: str | None) -> list[str]:
    """'users:(("nginx",pid=1,fd=6),("nginx",pid=2,fd=6))' → ['nginx']"""
    if not process_field:
        return []
    return sorted({name.lower() for name in PROCESS_RE.findall(process_field)})


def inventory_hash(components: Iterable[Component], ports: Iterable[dict[str, Any]]) -> str:
    data = {
        "components": [list(c.key) for c in components],
        "ports": sorted(
            f"{p.get('proto')}|{p.get('port')}|{','.join(process_names(p.get('process')))}" for p in ports
        ),
    }
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
