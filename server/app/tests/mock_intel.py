"""Respuestas simuladas de OSV, CISA KEV, FIRST EPSS y OTX, con el mismo
formato que las APIs reales. Incluye casos difíciles: paginación de OSV,
un registro de Ubuntu con arreglos para 22.04 y 24.04, un USN que agrupa
varios CVEs, un registro retirado y log4j con varios rangos de versiones."""

from __future__ import annotations

import json
from urllib.parse import parse_qs

import httpx

U24 = "Ubuntu:24.04:LTS"

RECORDS = {
    "UBUNTU-CVE-2025-32463": {
        "id": "UBUNTU-CVE-2025-32463",
        "modified": "2025-09-30T00:00:00Z",
        "upstream": ["CVE-2025-32463"],
        "details": "Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.",
        "severity": [
            {"type": "Ubuntu", "score": "high"},
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"},
        ],
        "affected": [
            {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "sudo"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.9.9-1ubuntu2.5"}]}]},
            {"package": {"ecosystem": U24, "name": "sudo"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.9.15p5-3ubuntu5.24.04.9"}]}]},
        ],
    },
    "USN-7604-1": {
        "id": "USN-7604-1",
        "modified": "2025-07-01T00:00:00Z",
        "summary": "sudo vulnerabilities",
        "upstream": ["CVE-2025-32462", "CVE-2025-32463"],
        "affected": [
            {"package": {"ecosystem": U24, "name": "sudo"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.9.15p5-3ubuntu5.24.04.9"}]}]},
        ],
    },
    "GHSA-jfh8-c2jp-5v3q": {
        "id": "GHSA-jfh8-c2jp-5v3q",
        "modified": "2025-01-01T00:00:00Z",
        "aliases": ["CVE-2021-44228"],
        "summary": "Remote code injection in Log4j",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
        "affected": [{
            "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
            "ranges": [{"type": "ECOSYSTEM", "events": [
                {"introduced": "2.0-beta9"}, {"fixed": "2.3.1"},
                {"introduced": "2.4"}, {"fixed": "2.12.2"},
                {"introduced": "2.13.0"}, {"fixed": "2.15.0"},
            ]}],
        }],
    },
    "GHSA-xpfp-f569-q3p2": {
        "id": "GHSA-xpfp-f569-q3p2",
        "modified": "2024-01-01T00:00:00Z",
        "aliases": ["CVE-2021-35042", "PYSEC-2021-111"],
        "summary": "SQL Injection in Django",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{
            "package": {"ecosystem": "PyPI", "name": "django"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.1"}, {"fixed": "3.1.13"}, {"introduced": "3.2"}, {"fixed": "3.2.5"}]}],
        }],
    },
    "UBUNTU-CVE-2025-23419": {
        "id": "UBUNTU-CVE-2025-23419",
        "modified": "2025-03-01T00:00:00Z",
        "upstream": ["CVE-2025-23419"],
        "details": "TLS session resumption can bypass client certificate authentication.",
        "severity": [{"type": "Ubuntu", "score": "medium"},
                     {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"}],
        "affected": [{"package": {"ecosystem": U24, "name": "nginx"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.24.0-2ubuntu7.3"}]}]}],
    },
    "UBUNTU-CVE-2024-0001": {
        "id": "UBUNTU-CVE-2024-0001",
        "modified": "2024-05-01T00:00:00Z",
        "upstream": ["CVE-2024-0001"],
        "details": "Low priority issue without fix yet.",
        "severity": [{"type": "Ubuntu", "score": "low"}],
        "affected": [{"package": {"ecosystem": U24, "name": "openssl"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                      # Como los registros reales del kernel: listas enormes que la app descarta.
                      "versions": [f"3.0.{i}-0ubuntu{j}" for i in range(50) for j in range(40)],
                      "database_specific": {"source": "https://example.invalid/" + "x" * 2000}}],
        "references": [{"type": "WEB", "url": f"https://example.invalid/{i}"} for i in range(200)],
    },
    "UBUNTU-CVE-2024-0002": {
        "id": "UBUNTU-CVE-2024-0002",
        "modified": "2024-05-01T00:00:00Z",
        "upstream": ["CVE-2024-0002"],
        "details": "Second page vulnerability (tests pagination).",
        "severity": [{"type": "Ubuntu", "score": "negligible"}],
        "affected": [{"package": {"ecosystem": U24, "name": "openssl"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}],
    },
    "UBUNTU-CVE-2023-9999": {
        "id": "UBUNTU-CVE-2023-9999",
        "modified": "2024-01-01T00:00:00Z",
        "withdrawn": "2024-01-02T00:00:00Z",
        "upstream": ["CVE-2023-9999"],
        "affected": [{"package": {"ecosystem": U24, "name": "curl"}}],
    },
}

# Qué IDs devuelve querybatch para cada (ecosistema, nombre).
MATCHES = {
    (U24, "sudo"): ["UBUNTU-CVE-2025-32463", "USN-7604-1"],
    ("Maven", "org.apache.logging.log4j:log4j-core"): ["GHSA-jfh8-c2jp-5v3q"],
    ("PyPI", "django"): ["GHSA-xpfp-f569-q3p2"],
    (U24, "nginx"): ["UBUNTU-CVE-2025-23419"],
    (U24, "openssl"): ["UBUNTU-CVE-2024-0001", "UBUNTU-CVE-2024-0002"],
    (U24, "curl"): ["UBUNTU-CVE-2023-9999"],
}

KEV = {
    "catalogVersion": "2026.10.29",
    "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2", "vulnerabilityName": "Apache Log4j2 RCE",
         "dateAdded": "2021-12-10", "dueDate": "2021-12-24", "knownRansomwareCampaignUse": "Known",
         "requiredAction": "Apply updates per vendor instructions."},
        {"cveID": "CVE-2025-32463", "vendorProject": "Sudo", "product": "Sudo", "vulnerabilityName": "Sudo chroot",
         "dateAdded": "2025-09-29", "dueDate": "2025-10-20", "knownRansomwareCampaignUse": "Unknown",
         "requiredAction": "Apply mitigations per vendor instructions."},
    ],
}

EPSS = {
    "CVE-2021-44228": (0.94358, 0.99962),
    "CVE-2025-32463": (0.12, 0.93),
    "CVE-2025-32462": (0.004, 0.55),
    "CVE-2021-35042": (0.31, 0.97),
    "CVE-2025-23419": (0.002, 0.40),
}

OTX = {
    "CVE-2021-44228": [
        {"id": "61b9a0f0f1c3e9a5b0a1c001", "name": "Log4Shell exploitation by ransomware operators",
         "created": "2025-11-01T00:00:00", "modified": "2026-10-20T10:00:00", "adversary": "Conti",
         "malware_families": [{"display_name": "Khonsari"}], "tags": ["log4j", "ransomware"]},
        {"id": "61b9a0f0f1c3e9a5b0a1c002", "name": "Log4j scanning activity", "created": "2025-06-01T00:00:00",
         "modified": "2026-09-01T00:00:00", "adversary": "", "malware_families": [], "tags": ["scanning"]},
    ],
    "CVE-2025-32463": [
        {"id": "68e0a0f0f1c3e9a5b0a1c003", "name": "Linux privilege escalation via sudo chroot (CVE-2025-32463)",
         "created": "2025-10-01T00:00:00", "modified": "2026-10-10T00:00:00", "adversary": "",
         "malware_families": [], "tags": ["linux", "privesc"]},
    ],
}


class Recorder:
    def __init__(self):
        self.calls: list[str] = []
        self.ecosystems: set[str] = set()   # ecosistemas consultados en OSV
        self.paged_once = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.calls.append(f"{request.method} {request.url.host}{request.url.path}")
        if url == "https://api.osv.dev/v1/querybatch":
            body = json.loads(request.content)
            results = []
            for q in body["queries"]:
                key = (q["package"]["ecosystem"], q["package"]["name"])
                self.ecosystems.add(key[0])
                ids = MATCHES.get(key, [])
                if key == (U24, "openssl"):
                    # Primera página con un resultado y token; segunda con el resto.
                    if "page_token" not in q:
                        results.append({"vulns": [{"id": ids[0], "modified": RECORDS[ids[0]]["modified"]}],
                                        "next_page_token": "page-2"})
                        continue
                    ids = ids[1:]
                results.append({"vulns": [{"id": i, "modified": RECORDS[i]["modified"]} for i in ids]} if ids else {})
            return httpx.Response(200, json={"results": results})
        if url.startswith("https://api.osv.dev/v1/vulns/"):
            vid = url.rsplit("/", 1)[1]
            return httpx.Response(200, json=RECORDS[vid]) if vid in RECORDS else httpx.Response(404)
        if url.startswith("https://www.cisa.gov/"):
            return httpx.Response(200, json=KEV)
        if url.startswith("https://api.first.org/data/v1/epss"):
            cves = parse_qs(request.url.query.decode())["cve"][0].split(",")
            assert len(",".join(cves)) <= 2000
            data = [{"cve": c, "epss": str(EPSS[c][0]), "percentile": str(EPSS[c][1]), "date": "2026-10-29"}
                    for c in cves if c in EPSS]
            return httpx.Response(200, json={"status": "OK", "total": len(data), "data": data})
        if url.startswith("https://otx.alienvault.com/api/v1/indicators/cve/"):
            assert request.headers.get("X-OTX-API-KEY") == "test-otx-key"
            cve = request.url.path.split("/")[-2]
            pulses = OTX.get(cve, [])
            return httpx.Response(200, json={"pulse_info": {"count": len(pulses), "pulses": pulses}})
        return httpx.Response(599, text=f"URL no simulada: {url}")

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))
