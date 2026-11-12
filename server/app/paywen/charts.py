"""Gráficos en SVG generados en el servidor.

El dashboard no usa JavaScript (la CSP lo impide a propósito), así que los
gráficos se arman aquí como SVG y van dentro del HTML. Los colores salen de
clases CSS (style.css), nunca de atributos style. El detalle de cada punto se
ve al pasar el mouse gracias a <title> (tooltip nativo del navegador), y cada
gráfico tiene su tabla de datos al lado.
"""

from __future__ import annotations

import math
from html import escape

from markupsafe import Markup


def _t(text) -> str:
    return escape(str(text), quote=True)


def _fmt(n: float) -> str:
    n = round(n)
    return f"{n:,}".replace(",", ".")


def nice_ticks(vmax: float, count: int = 4) -> list[float]:
    if vmax <= 0:
        return [0, 1]
    raw = vmax / count
    mag = 10 ** math.floor(math.log10(raw))
    step = next(m * mag for m in (1, 2, 5, 10) if m * mag >= raw)
    top = step * math.ceil(vmax / step)
    ticks, v = [], 0.0
    while v <= top + 1e-9:
        ticks.append(v)
        v += step
    return ticks


# ─── Mini gráfico de área (tarjetas de tendencia) ─────────────────────────────

def spark(values: list[float], labels: list[str], cls: str, name: str, width: int = 260, height: int = 64) -> Markup:
    pts = [(i, v) for i, v in enumerate(values) if v is not None]
    if not pts:
        return Markup("")
    pad_x, pad_top, pad_bottom = 4, 8, 4
    vmax = max(v for _, v in pts) or 1
    vmin = min(v for _, v in pts)
    # La escala parte de un poco bajo el mínimo para que la tendencia se note,
    # pero el área se rellena hasta abajo para no exagerar el cambio.
    low = max(0.0, vmin - (vmax - vmin) * 0.6) if vmax != vmin else 0.0
    span = (vmax - low) or 1
    n = max(len(values) - 1, 1)

    def x(i): return pad_x + (width - 2 * pad_x) * (i / n)
    def y(v): return pad_top + (height - pad_top - pad_bottom) * (1 - (v - low) / span)

    out = [f'<svg class="chart spark" viewBox="0 0 {width} {height}" role="img" '
           f'aria-label="{_t(name)}: tendencia de {len(pts)} días" preserveAspectRatio="none">']
    if len(pts) > 1:
        line = " ".join(f"{'M' if k == 0 else 'L'}{x(i):.1f},{y(v):.1f}" for k, (i, v) in enumerate(pts))
        area = f"{line} L{x(pts[-1][0]):.1f},{height - pad_bottom} L{x(pts[0][0]):.1f},{height - pad_bottom} Z"
        out.append(f'<path class="area {cls}" d="{area}"/>')
        out.append(f'<path class="line {cls}" d="{line}"/>')
    i, v = pts[-1]
    out.append(f'<circle class="dot {cls}" cx="{x(i):.1f}" cy="{y(v):.1f}" r="3.5"/>')
    # Zonas de hover: una franja por día con su tooltip.
    band = (width - 2 * pad_x) / max(len(values), 1)
    for i, v in pts:
        out.append(f'<rect class="hit" x="{x(i) - band / 2:.1f}" y="0" width="{band:.1f}" height="{height}">'
                   f'<title>{_t(labels[i])}: {_fmt(v)} {_t(name.lower())}</title></rect>')
    out.append("</svg>")
    return Markup("".join(out))


# ─── Gráfico de líneas con ejes ───────────────────────────────────────────────

def lines(labels: list[str], series: list[tuple[str, str, list[float]]], width: int = 720, height: int = 240,
          unit: str = "") -> Markup:
    left, right, top, bottom = 46, 96, 14, 28
    values = [v for _, _, vals in series for v in vals if v is not None]
    if not values or not labels:
        return Markup("")
    ticks = nice_ticks(max(values))
    vmax = ticks[-1] or 1
    n = max(len(labels) - 1, 1)
    pw, ph = width - left - right, height - top - bottom

    def x(i): return left + pw * (i / n) if len(labels) > 1 else left + pw / 2
    def y(v): return top + ph * (1 - v / vmax)

    out = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{_t(", ".join(s[0] for s in series))} en el tiempo">']
    for t in ticks:
        out.append(f'<line class="grid" x1="{left}" x2="{left + pw}" y1="{y(t):.1f}" y2="{y(t):.1f}"/>')
        out.append(f'<text class="axis" x="{left - 8}" y="{y(t) + 4:.1f}" text-anchor="end">{_fmt(t)}</text>')
    for i in _label_positions(len(labels)):
        out.append(f'<text class="axis" x="{x(i):.1f}" y="{height - 8}" text-anchor="middle">{_t(labels[i])}</text>')

    ends = []
    for name, cls, vals in series:
        pts = [(i, v) for i, v in enumerate(vals) if v is not None]
        if len(pts) > 1:
            d = " ".join(f"{'M' if k == 0 else 'L'}{x(i):.1f},{y(v):.1f}" for k, (i, v) in enumerate(pts))
            out.append(f'<path class="line {cls}" d="{d}"/>')
        if pts:
            i, v = pts[-1]
            out.append(f'<circle class="dot {cls} ring" cx="{x(i):.1f}" cy="{y(v):.1f}" r="4"/>')
            ends.append([y(v), name, v, cls])
    # Etiquetas directas al final de cada línea, separadas para no chocar.
    ends.sort()
    for k in range(1, len(ends)):
        ends[k][0] = max(ends[k][0], ends[k - 1][0] + 15)
    for ly, name, v, cls in ends:
        out.append(f'<text class="label" x="{left + pw + 10}" y="{ly + 4:.1f}">'
                   f'<tspan class="label-strong">{_fmt(v)}</tspan> {_t(name)}</text>')

    band = pw / max(len(labels), 1)
    for i, lab in enumerate(labels):
        detail = " · ".join(f"{name}: {_fmt(vals[i])}{unit}" for name, _, vals in series if vals[i] is not None)
        out.append(f'<rect class="hit" x="{x(i) - band / 2:.1f}" y="{top}" width="{band:.1f}" height="{ph}">'
                   f'<title>{_t(lab)} — {_t(detail)}</title></rect>')
    out.append("</svg>")
    return Markup("".join(out))


def _label_positions(n: int, maximum: int = 6) -> list[int]:
    if n <= maximum:
        return list(range(n))
    step = (n - 1) / (maximum - 1)
    return sorted({round(k * step) for k in range(maximum)})


# ─── Barras agrupadas por día (nuevas vs resueltas) ───────────────────────────

def bars(labels: list[str], series: list[tuple[str, str, list[float]]], width: int = 720, height: int = 220) -> Markup:
    left, right, top, bottom = 46, 12, 14, 28
    values = [v for _, _, vals in series for v in vals if v is not None]
    if not labels:
        return Markup("")
    ticks = nice_ticks(max(values or [0]))
    vmax = ticks[-1] or 1
    pw, ph = width - left - right, height - top - bottom
    group = pw / len(labels)
    gap = 2
    bar_w = max(2.0, min(18.0, (group * 0.7 - gap * (len(series) - 1)) / len(series)))

    def y(v): return top + ph * (1 - v / vmax)

    out = [f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{_t(", ".join(s[0] for s in series))} por día">']
    for t in ticks:
        out.append(f'<line class="grid" x1="{left}" x2="{left + pw}" y1="{y(t):.1f}" y2="{y(t):.1f}"/>')
        out.append(f'<text class="axis" x="{left - 8}" y="{y(t) + 4:.1f}" text-anchor="end">{_fmt(t)}</text>')
    for i in _label_positions(len(labels), 8):
        cx = left + group * (i + 0.5)
        out.append(f'<text class="axis" x="{cx:.1f}" y="{height - 8}" text-anchor="middle">{_t(labels[i])}</text>')
    total_w = bar_w * len(series) + gap * (len(series) - 1)
    for i, lab in enumerate(labels):
        x0 = left + group * (i + 0.5) - total_w / 2
        for k, (name, cls, vals) in enumerate(series):
            v = vals[i] or 0
            bx = x0 + k * (bar_w + gap)
            hgt = max(ph * v / vmax, 0)
            if v:
                r = min(3.0, bar_w / 2, hgt)
                yb = top + ph
                yt = yb - hgt
                # Barra con la punta redondeada y la base recta.
                d = (f"M{bx:.1f},{yb:.1f} L{bx:.1f},{yt + r:.1f} Q{bx:.1f},{yt:.1f} {bx + r:.1f},{yt:.1f} "
                     f"L{bx + bar_w - r:.1f},{yt:.1f} Q{bx + bar_w:.1f},{yt:.1f} {bx + bar_w:.1f},{yt + r:.1f} "
                     f"L{bx + bar_w:.1f},{yb:.1f} Z")
                out.append(f'<path class="mark {cls}" d="{d}"/>')
        detail = " · ".join(f"{name}: {_fmt(vals[i] or 0)}" for name, _, vals in series)
        out.append(f'<rect class="hit" x="{left + group * i:.1f}" y="{top}" width="{group:.1f}" height="{ph}">'
                   f'<title>{_t(lab)} — {_t(detail)}</title></rect>')
    out.append(f'<line class="baseline" x1="{left}" x2="{left + pw}" y1="{top + ph}" y2="{top + ph}"/>')
    out.append("</svg>")
    return Markup("".join(out))


# ─── Barras horizontales apiladas (top paquetes) ──────────────────────────────

def hbars(rows: list[tuple[str, str, list[tuple[str, str, float]]]], width: int = 840) -> Markup:
    """rows: (etiqueta, enlace, [(nombre, clase, valor), ...])."""
    if not rows:
        return Markup("")
    label_w, value_w, row_h, bar_h = 220, 60, 30, 12
    height = row_h * len(rows) + 4
    vmax = max(sum(v for _, _, v in segs) for _, _, segs in rows) or 1
    pw = width - label_w - value_w
    out = [f'<svg class="chart hbars" viewBox="0 0 {width} {height}" role="img" aria-label="Paquetes con más hallazgos">']
    for k, (label, href, segs) in enumerate(rows):
        cy = k * row_h + row_h / 2
        short = label if len(label) <= 27 else "…" + label[-26:]
        out.append(f'<a href="{_t(href)}"><text class="label link" x="{label_w - 10}" y="{cy + 4:.1f}" text-anchor="end">'
                   f'{_t(short)}<title>{_t(label)}</title></text></a>')
        x0 = float(label_w)
        total = 0.0
        for name, cls, v in segs:
            if not v:
                continue
            w = pw * v / vmax
            out.append(f'<rect class="mark {cls}" x="{x0:.1f}" y="{cy - bar_h / 2:.1f}" width="{max(w - 2, 1):.1f}" '
                       f'height="{bar_h}" rx="3"><title>{_t(label)} — {_t(name)}: {_fmt(v)}</title></rect>')
            x0 += w
            total += v
        out.append(f'<text class="label label-strong" x="{x0 + 6:.1f}" y="{cy + 4:.1f}">{_fmt(total)}</text>')
    out.append("</svg>")
    return Markup("".join(out))


# ─── Dona (distribución actual) ───────────────────────────────────────────────

def donut(segments: list[tuple[str, str, float]], size: int = 180, center_label: str = "hallazgos") -> Markup:
    total = sum(v for _, _, v in segments)
    r_out, r_in = size / 2 - 2, size / 2 - 26
    c = size / 2
    out = [f'<svg class="chart donut" viewBox="0 0 {size} {size}" role="img" aria-label="Distribución por prioridad">']
    if total <= 0:
        out.append(f'<circle class="track" cx="{c}" cy="{c}" r="{(r_out + r_in) / 2}" stroke-width="{r_out - r_in}" fill="none"/>')
    else:
        angle = -math.pi / 2
        visible = [s for s in segments if s[2] > 0]
        gap = 0.025 if len(visible) > 1 else 0.0
        for name, cls, v in visible:
            sweep = 2 * math.pi * v / total
            # Los segmentos muy chicos igual se ven (mínimo ~2°).
            a0, a1 = angle + gap / 2, angle + max(sweep, 0.035) - gap / 2
            large = 1 if a1 - a0 > math.pi else 0
            if len(visible) == 1:
                a1 = a0 + 2 * math.pi - 0.0001
                large = 1
            p = [(c + r_out * math.cos(a0), c + r_out * math.sin(a0)), (c + r_out * math.cos(a1), c + r_out * math.sin(a1)),
                 (c + r_in * math.cos(a1), c + r_in * math.sin(a1)), (c + r_in * math.cos(a0), c + r_in * math.sin(a0))]
            d = (f"M{p[0][0]:.2f},{p[0][1]:.2f} A{r_out},{r_out} 0 {large} 1 {p[1][0]:.2f},{p[1][1]:.2f} "
                 f"L{p[2][0]:.2f},{p[2][1]:.2f} A{r_in},{r_in} 0 {large} 0 {p[3][0]:.2f},{p[3][1]:.2f} Z")
            pct = 100 * v / total
            out.append(f'<path class="seg {cls}" d="{d}"><title>{_t(name)}: {_fmt(v)} ({pct:.1f} %)</title></path>'.replace(".", ",", 0))
            angle += sweep
    out.append(f'<text class="donut-value" x="{c}" y="{c + 4}" text-anchor="middle">{_fmt(total)}</text>')
    out.append(f'<text class="donut-label" x="{c}" y="{c + 22}" text-anchor="middle">{_t(center_label)}</text>')
    out.append("</svg>")
    return Markup("".join(out))
