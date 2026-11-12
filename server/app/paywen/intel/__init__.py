"""Clientes de las fuentes de inteligencia: OSV, CISA KEV, FIRST EPSS y OTX."""

from __future__ import annotations

import re

import httpx

from .. import __version__

USER_AGENT = f"paywen-scan/{__version__} (+proyecto academico)"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def http_client(**kwargs) -> httpx.Client:
    """Cliente HTTP con timeouts y reintentos de conexión."""
    kwargs.setdefault("timeout", httpx.Timeout(30.0, connect=10.0))
    kwargs.setdefault("headers", {"User-Agent": USER_AGENT})
    kwargs.setdefault("transport", httpx.HTTPTransport(retries=3))
    kwargs.setdefault("follow_redirects", True)
    return httpx.Client(**kwargs)


def is_cve(value: str | None) -> bool:
    return bool(value and CVE_RE.match(value))
