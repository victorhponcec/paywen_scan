"""Datos de ejemplo para el histórico (opcional, para demos).

El histórico real se llena solo: una foto por host y por día en cada pasada
del worker. Para mostrar cómo se ven los gráficos antes de tener semanas de
datos, este comando genera fotos SIMULADAS hacia atrás, partiendo de los
valores actuales de cada host:

    python -m paywen.demo --days 30      # genera 30 días previos (no pisa fotos reales)
    python -m paywen.demo --clear        # borra todos los datos de ejemplo

Las fotos simuladas quedan marcadas (synthetic = true) y el dashboard avisa
cuando las está mostrando.
"""

from __future__ import annotations

import argparse
import logging
import random
import sys
from datetime import date, timedelta

from . import db

log = logging.getLogger("paywen.demo")

FIELDS = ("critica", "alta", "media", "baja", "kev", "ransomware", "unique_vulns", "fixable")


def clear() -> int:
    with db.transaction() as conn:
        return conn.execute("DELETE FROM host_snapshots WHERE synthetic").rowcount


def generate(days: int, seed: int = 7) -> int:
    rng = random.Random(seed)
    inserted = 0
    with db.transaction() as conn:
        hosts = conn.execute(
            """
            SELECT s.* FROM host_snapshots s
            JOIN (SELECT host_id, min(day) AS day FROM host_snapshots WHERE NOT synthetic GROUP BY host_id) first
              ON first.host_id = s.host_id AND first.day = s.day
            """
        ).fetchall()
        for base in hosts:
            current = {f: float(base[f]) for f in FIELDS}
            day: date = base["day"]
            for _ in range(days):
                day -= timedelta(days=1)
                # Hacia atrás: antes había algo más de vulnerabilidades (se fueron
                # parchando) y de vez en cuando aparecían tandas nuevas.
                prev = {}
                for f in FIELDS:
                    drift = rng.uniform(-0.002, 0.008) if f not in ("kev", "ransomware") else 0.0
                    prev[f] = current[f] * (1 + drift)
                if rng.random() < 0.15:
                    prev["critica"] = max(0.0, prev["critica"] - rng.randint(1, 3))
                    prev["kev"] = max(0.0, prev["kev"] - rng.randint(0, 1))
                new_vulns = max(0, round(current["unique_vulns"] - prev["unique_vulns"]) + rng.randint(2, 40))
                resolved = max(0, round(prev["unique_vulns"] - current["unique_vulns"] + new_vulns))
                ranks = [prev["critica"], prev["alta"], prev["media"], prev["baja"]]
                score = min(100, round(ranks[0] * 25 + ranks[1] * 8 + ranks[2] * 2 + ranks[3] * 0.2))
                inserted += conn.execute(
                    """
                    INSERT INTO host_snapshots (host_id, day, critica, alta, media, baja, kev, ransomware,
                        unique_vulns, fixable, risk_score, components, new_vulns, resolved_vulns, synthetic)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, true)
                    ON CONFLICT (host_id, day) DO NOTHING
                    """,
                    (
                        base["host_id"], day, *(round(prev[f]) for f in FIELDS), score,
                        base["components"], 0, 0,
                    ),
                ).rowcount
                # "Nuevas" y "resueltas" se registran en el día siguiente.
                conn.execute(
                    """
                    UPDATE host_snapshots SET new_vulns = %s, resolved_vulns = %s
                    WHERE host_id = %s AND day = %s AND synthetic
                    """,
                    (new_vulns, resolved, base["host_id"], day + timedelta(days=1)),
                )
                current = prev
    return inserted


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(description="Datos de ejemplo para el histórico de Paywen Scan")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--days", type=int, help="días simulados hacia atrás (1–180)")
    group.add_argument("--clear", action="store_true", help="borra los datos de ejemplo")
    args = parser.parse_args()
    db.wait_for_db(attempts=5, delay=3)
    if args.clear:
        log.info("Datos de ejemplo borrados: %s fotos", clear())
        return
    if not 1 <= args.days <= 180:
        sys.exit("--days debe estar entre 1 y 180")
    count = generate(args.days)
    if count == 0:
        log.warning("No se generó nada: hace falta al menos una pasada del worker con hosts cruzados")
    else:
        log.info("Fotos de ejemplo generadas: %s (borrar con: python -m paywen.demo --clear)", count)


if __name__ == "__main__":
    main()
