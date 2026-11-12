#!/bin/bash
# Agente de Paywen Scan: arma el inventario del servidor (SBOM de Trivy +
# sistema operativo + puertos en escucha) y lo envía a la API de la app.
#
# Configuración: /etc/paywen-agent/agent.env (APP_URL y AGENT_NAME) y
# /etc/paywen-agent/curlrc (token). El último inventario enviado queda en
# /var/lib/paywen-agent/last-payload.json.
#
# Qué envía: nombre del host, sistema operativo, kernel, la lista de paquetes
# y librerías instaladas (nombre y versión) y los puertos en escucha. NO envía
# contenido de archivos, usuarios, contraseñas ni variables de entorno.
set -euo pipefail

APP_URL=""
AGENT_NAME=""
# shellcheck source=/dev/null
source /etc/paywen-agent/agent.env
[ -n "$APP_URL" ] || { echo "Falta APP_URL en /etc/paywen-agent/agent.env" >&2; exit 1; }
HOST_NAME="$AGENT_NAME"
[ -n "$HOST_NAME" ] || HOST_NAME=$(hostname)

OUT=/var/lib/paywen-agent
SBOM="$OUT/sbom.json"
PAYLOAD="$OUT/last-payload.json"

# Evita dos ejecuciones a la vez (por ejemplo, el timer y una manual).
exec 9>"$OUT/agent.lock"
flock -n 9 || { echo "El agente ya se está ejecutando" >&2; exit 0; }

trivy rootfs --quiet --cache-dir /var/cache/trivy \
  --format cyclonedx --output "$SBOM" \
  --skip-dirs /proc --skip-dirs /sys --skip-dirs /dev --skip-dirs /run \
  --skip-dirs /snap --skip-dirs /var/lib/docker --skip-dirs /var/cache/trivy \
  --skip-dirs "$OUT" \
  /

# shellcheck source=/dev/null
. /etc/os-release

PORTS=$(ss -H -tulnp | awk '{print $1, $5, $7}' | jq -R -s -c '
  split("\n") | map(select(length > 0) | split(" ") | {
    proto: .[0],
    address: .[1],
    port: (.[1] | split(":") | last | tonumber? // null),
    process: (.[2] // "")
  })')

jq -n \
  --arg hostname "$HOST_NAME" \
  --arg collected_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg os_id "$ID" \
  --arg os_version "$VERSION_ID" \
  --arg os_name "$PRETTY_NAME" \
  --arg kernel "$(uname -r)" \
  --argjson ports "$PORTS" \
  --slurpfile sbom "$SBOM" \
  '{
    hostname: $hostname,
    collected_at: $collected_at,
    os: {id: $os_id, version_id: $os_version, name: $os_name, kernel: $kernel},
    ports: $ports,
    sbom: $sbom[0]
  }' > "$PAYLOAD"

COMPONENTS=$(jq '[.sbom.components[]? | select(.purl != null)] | length' "$PAYLOAD")
echo "Inventario de $HOST_NAME: $COMPONENTS componentes. Enviando a $APP_URL…"

curl -fsS -K /etc/paywen-agent/curlrc \
  --retry 3 --retry-delay 10 --max-time 300 \
  --data-binary "@$PAYLOAD" \
  "$APP_URL/api/v1/ingest"
echo
echo "Inventario enviado a $APP_URL"
