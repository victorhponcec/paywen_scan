"""Genera un inventario de prueba con el mismo formato que envía el agente:
SBOM CycloneDX con las propiedades que agrega Trivy, a partir de los paquetes
.deb instalados en la máquina donde se corre (pensado para Ubuntu/Debian).

Sirve para probar la app sin Trivy ni un agente real:

    python tests/make_payload.py > /tmp/payload.json
    curl -k -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
         --data-binary @/tmp/payload.json https://<app>/api/v1/ingest
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone

EXTRA_LANG = [
    ("pkg:pypi/django@3.2.0", "django", "3.2.0", "python-pkg", "opt/legacy-python/venv/lib/python3.12/site-packages/Django-3.2.dist-info/METADATA"),
    ("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "org.apache.logging.log4j:log4j-core", "2.14.1", "jar", "opt/legacy-java/lib/log4j-core-2.14.1.jar"),
    ("pkg:npm/lodash@4.17.15", "lodash", "4.17.15", "node-pkg", "opt/legacy-node/node_modules/lodash/package.json"),
]


def split_deb_version(version: str) -> tuple[str | None, str, str | None]:
    epoch = None
    if ":" in version:
        epoch, version = version.split(":", 1)
    release = None
    if "-" in version:
        version, release = version.rsplit("-", 1)
    return epoch, version, release


def deb_components(os_id: str, version_id: str) -> list[dict]:
    out = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\n"],
        check=True, capture_output=True, text=True,
    ).stdout
    comps = []
    for line in out.splitlines():
        name, version, src, src_version, arch = line.split("\t")
        epoch, upstream, release = split_deb_version(src_version or version)
        purl = f"pkg:deb/{os_id}/{name}@{version.replace(':', '%3A')}?arch={arch}&distro={os_id}-{version_id}"
        props = [
            {"name": "aquasecurity:trivy:PkgID", "value": f"{name}@{version}"},
            {"name": "aquasecurity:trivy:PkgType", "value": os_id},
            {"name": "aquasecurity:trivy:SrcName", "value": src or name},
            {"name": "aquasecurity:trivy:SrcVersion", "value": upstream},
        ]
        if release:
            props.append({"name": "aquasecurity:trivy:SrcRelease", "value": release})
        if epoch:
            props.append({"name": "aquasecurity:trivy:SrcEpoch", "value": epoch})
        comps.append({"bom-ref": purl, "type": "library", "name": name, "version": version, "purl": purl, "properties": props})
    return comps


def build(hostname: str = "paywen-test", extra_debs: list[dict] | None = None) -> dict:
    osr = dict(
        line.split("=", 1) for line in open("/etc/os-release").read().splitlines() if "=" in line
    )
    os_id = osr["ID"].strip('"')
    version_id = osr["VERSION_ID"].strip('"')
    components = deb_components(os_id, version_id) + (extra_debs or [])
    for purl, name, version, pkg_type, path in EXTRA_LANG:
        components.append({
            "bom-ref": purl, "type": "library", "name": name.split(":")[-1], "version": version, "purl": purl,
            "properties": [
                {"name": "aquasecurity:trivy:PkgType", "value": pkg_type},
                {"name": "aquasecurity:trivy:FilePath", "value": path},
            ],
        })
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": "trivy", "group": "aquasecurity", "version": "0.69.3"}]},
                     "component": {"type": "container", "name": "/"}},
        "components": [{"bom-ref": "os", "type": "operating-system", "name": os_id, "version": version_id}] + components,
    }
    return {
        "hostname": hostname,
        "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "os": {"id": os_id, "version_id": version_id, "name": osr.get("PRETTY_NAME", "").strip('"'), "kernel": "6.8.0-test"},
        "ports": [
            {"proto": "tcp", "address": "0.0.0.0:22", "port": 22, "process": 'users:(("sshd",pid=900,fd=3))'},
            {"proto": "tcp", "address": "0.0.0.0:80", "port": 80, "process": 'users:(("nginx",pid=1200,fd=6),("nginx",pid=1201,fd=6))'},
            {"proto": "tcp", "address": "127.0.0.1:3306", "port": 3306, "process": 'users:(("mysqld",pid=1300,fd=21))'},
        ],
        "sbom": sbom,
    }


if __name__ == "__main__":
    json.dump(build(sys.argv[1] if len(sys.argv) > 1 else "paywen-test"), sys.stdout)
