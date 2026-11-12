"""Íconos de Lucide (ISC), incrustados como SVG en el HTML.

Se leen una vez desde static/icons/*.svg. Al ir dentro del HTML no requieren
pedidos extra ni chocan con la CSP (no hay scripts ni estilos en línea).
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from markupsafe import Markup, escape

ICON_DIR = Path(__file__).parent / "static" / "icons"
_INNER = re.compile(r"<svg[^>]*>(.*)</svg>", re.S)


@lru_cache(maxsize=None)
def _inner(name: str) -> str:
    path = ICON_DIR / f"{name}.svg"
    if not re.fullmatch(r"[a-z0-9-]+", name) or not path.is_file():
        return ""
    match = _INNER.search(path.read_text(encoding="utf-8"))
    return match.group(1).strip() if match else ""


def icon(name: str, size: int = 18, cls: str = "", label: str | None = None) -> Markup:
    inner = _inner(name)
    if not inner:
        return Markup("")
    a11y = f'role="img" aria-label="{escape(label)}"' if label else 'aria-hidden="true" focusable="false"'
    return Markup(
        f'<svg class="icon {escape(cls)}" width="{int(size)}" height="{int(size)}" viewBox="0 0 24 24" '
        f'fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" '
        f'stroke-linejoin="round" {a11y}>{inner}</svg>'
    )
