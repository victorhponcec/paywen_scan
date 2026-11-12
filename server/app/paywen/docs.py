"""Documentación dentro de la app (sección Docs).

Los manuales son archivos Markdown que viajan dentro de la imagen
(paywen/manual/*.md). Son contenido propio, no de los usuarios, así que se
pueden mostrar como HTML. El mismo texto se usa para generar los PDF.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import markdown
from markupsafe import Markup

MANUAL_DIR = Path(__file__).parent / "manual"


@dataclass(frozen=True)
class Page:
    slug: str
    title: str
    file: str
    icon: str
    summary: str


PAGES = (
    Page("descripcion", "Descripción general", "descripcion.md", "book-open",
         "Qué hace Paywen Scan, de dónde saca la información, cómo prioriza y sus limitaciones."),
    Page("servidor", "Instalar el servidor", "instalar-servidor.md", "server",
         "Servidor completo con Docker en cualquier Ubuntu 24.04: dashboard, worker y base de datos."),
    Page("agente", "Instalar el agente de Linux", "instalar-agente.md", "package",
         "Agente con Trivy para cada servidor Linux que se quiere monitorear."),
    Page("agente-windows", "Instalar el agente de Windows", "instalar-agente-windows.md", "monitor",
         "Agente de PowerShell: programas, parches KB, puertos y librerías con Trivy."),
    Page("changelog", "Novedades", "CHANGELOG.md", "tag",
         "Cambios de cada versión."),
)
BY_SLUG = {p.slug: p for p in PAGES}


@lru_cache(maxsize=None)
def render(slug: str) -> dict | None:
    page = BY_SLUG.get(slug)
    path = MANUAL_DIR / page.file if page else None
    if not page or not path.is_file():
        return None
    md = markdown.Markdown(extensions=["tables", "fenced_code", "sane_lists", "toc"],
                           extension_configs={"toc": {"toc_depth": "2-3", "permalink": False}})
    html = md.convert(path.read_text(encoding="utf-8"))
    # El primer título ya lo muestra la plantilla.
    html = re.sub(r"^\s*<h1[^>]*>.*?</h1>", "", html, count=1, flags=re.S)
    # Los diagramas de texto no se cortan (el resto de los bloques sí).
    html = re.sub(r"<pre>(<code>(?:(?!</code>).)*?[┌│─▶◀└┐┘├]+(?:(?!</code>).)*?</code>)</pre>",
                  r'<pre class="diagram">\1</pre>', html, flags=re.S)
    toc = [t for t in md.toc_tokens[0]["children"]] if md.toc_tokens and md.toc_tokens[0].get("level") == 1 \
        else list(md.toc_tokens)
    return {"page": page, "html": Markup(html), "toc": toc}
