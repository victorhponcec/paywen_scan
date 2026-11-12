#!/bin/bash
# Instalador del agente de Paywen Scan (probado para Ubuntu 24.04 LTS).
#
#   sudo ./install.sh --url https://paywen.ejemplo.cl --token <TOKEN> --name srv-web-01
#   sudo ./install.sh --uninstall
#
# Opciones:
#   --url URL            URL base de la app, sin /api/v1/ingest (obligatoria)
#   --token TOKEN        token de agentes que entrega el administrador (obligatoria)
#   --name NOMBRE        nombre con que aparece en el dashboard (por omisión, el hostname).
#                        Usa uno único: dos equipos con el mismo nombre se pisan.
#   --insecure           no validar el certificado (solo si usas la IP con certificado autofirmado)
#   --interval 6h        cada cuánto se envía el inventario (formato systemd: 30min, 2h, 6h…)
#   --trivy-version V    versión de Trivy (por omisión 0.69.3; la 0.69.4 está prohibida)
#   --force              instalar aunque el sistema no sea Ubuntu 24.04
#   --uninstall          desinstala el agente (Trivy se mantiene)
#
# Lo que hace: instala curl, jq, iproute2 y Trivy (versión fijada); copia el
# agente a /opt/paywen-agent; guarda la configuración en /etc/paywen-agent
# (permisos 600); crea un timer de systemd que corre 15 min después de cada
# arranque y luego cada --interval; prueba la conexión y envía el primer inventario.

set -euo pipefail

VERSION="1.1.0"
URL=""
TOKEN=""
NAME=""
INSECURE=0
INTERVAL="6h"
TRIVY_VERSION="0.69.3"
FORCE=0
UNINSTALL=0
HERE=$(cd "$(dirname "$0")" && pwd)

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
info() { printf '\n==> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --name) NAME="${2:-}"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    --interval) INTERVAL="${2:-}"; shift 2 ;;
    --trivy-version) TRIVY_VERSION="${2:-}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "Opción desconocida: $1" >&2; usage 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "Ejecutar con sudo"

# ─── Desinstalar ──────────────────────────────────────────────────────────────
if [ "$UNINSTALL" -eq 1 ]; then
  systemctl disable --now paywen-agent.timer 2>/dev/null || true
  systemctl stop paywen-agent.service 2>/dev/null || true
  rm -f /etc/systemd/system/paywen-agent.service /etc/systemd/system/paywen-agent.timer /usr/local/bin/paywen-agent
  systemctl daemon-reload
  rm -rf /opt/paywen-agent /etc/paywen-agent /var/lib/paywen-agent
  echo "Agente desinstalado. Trivy y su caché (/var/cache/trivy) se mantienen:"
  echo "  sudo apt-mark unhold trivy && sudo apt-get remove -y trivy && sudo rm -rf /var/cache/trivy"
  exit 0
fi

# ─── Validaciones ─────────────────────────────────────────────────────────────
[ -n "$URL" ] && [ -n "$TOKEN" ] || { echo "Faltan --url y --token" >&2; usage 1; }
case "$URL" in https://*) ;; *) die "La URL debe empezar con https://" ;; esac
URL="${URL%/}"
URL="${URL%/api/v1/ingest}"
[ -n "$NAME" ] || NAME=$(hostname)
[[ "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]] || die "--name solo admite letras, números, punto, guion y guion bajo (máx. 63)"
[[ "$TOKEN" =~ ^[A-Za-z0-9._~+/=-]{16,}$ ]] || die "El token no tiene el formato esperado; revisa que esté completo"
[[ "$INTERVAL" =~ ^[0-9]+(s|min|h|d)$ ]] || die "--interval debe ser como 30min, 2h o 6h"
[ "$TRIVY_VERSION" != "0.69.4" ] || die "Trivy 0.69.4 fue comprometida (CVE-2026-33634). Usa 0.69.3."
[ -f "$HERE/paywen-agent.sh" ] || die "No encuentro paywen-agent.sh junto a install.sh"

# shellcheck source=/dev/null
. /etc/os-release
if [ "${ID:-}" != "ubuntu" ] || [ "${VERSION_ID:-}" != "24.04" ]; then
  echo "Este sistema es ${PRETTY_NAME:-desconocido}; el agente está probado en Ubuntu 24.04 LTS."
  [ "$FORCE" -eq 1 ] || die "Usa --force para instalar de todas formas"
fi
command -v systemctl >/dev/null || die "Se necesita systemd"
command -v apt-get >/dev/null || die "Se necesita apt (Ubuntu/Debian)"

echo "Paywen Scan agente $VERSION"
echo "  URL:      $URL"
echo "  Nombre:   $NAME"
echo "  Interval: $INTERVAL"
echo "  Trivy:    $TRIVY_VERSION"

# ─── 1. Dependencias ──────────────────────────────────────────────────────────
info "1/5 Instalando dependencias (curl, jq, iproute2, gnupg)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q ca-certificates curl gnupg jq iproute2 util-linux

# ─── 2. Trivy (versión fijada) ────────────────────────────────────────────────
info "2/5 Instalando Trivy $TRIVY_VERSION"
if trivy --version 2>/dev/null | grep -q "Version: $TRIVY_VERSION\$"; then
  echo "Trivy $TRIVY_VERSION ya estaba instalado"
else
  curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
    | gpg --dearmor --yes -o /usr/share/keyrings/trivy.gpg
  echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
    > /etc/apt/sources.list.d/trivy.list
  apt-get update -q
  if ! apt-get install -y -q --allow-downgrades --allow-change-held-packages "trivy=$TRIVY_VERSION"; then
    echo "La versión $TRIVY_VERSION no está en el repo apt; se descarga del release de GitHub y se verifica su checksum"
    TMP=$(mktemp -d)
    BASE="https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION"
    DEB="trivy_${TRIVY_VERSION}_Linux-64bit.deb"
    curl -fsSL -o "$TMP/$DEB" "$BASE/$DEB"
    curl -fsSL -o "$TMP/checksums.txt" "$BASE/trivy_${TRIVY_VERSION}_checksums.txt"
    (cd "$TMP" && grep " $DEB\$" checksums.txt | sha256sum -c -) || die "El checksum de Trivy no coincide"
    apt-get install -y -q --allow-downgrades "$TMP/$DEB"
    rm -rf "$TMP"
  fi
  apt-mark hold trivy >/dev/null
fi
trivy --version | head -1

# ─── 3. Agente y configuración ────────────────────────────────────────────────
info "3/5 Instalando el agente en /opt/paywen-agent"
install -d -m 700 /etc/paywen-agent /var/lib/paywen-agent
install -d -m 755 /opt/paywen-agent /var/cache/trivy
install -m 750 "$HERE/paywen-agent.sh" /opt/paywen-agent/agent.sh
echo "$VERSION" > /opt/paywen-agent/VERSION

printf 'APP_URL=%s\nAGENT_NAME=%s\n' "$URL" "$NAME" > /etc/paywen-agent/agent.env
{
  printf 'header = "Authorization: Bearer %s"\n' "$TOKEN"
  printf 'header = "Content-Type: application/json"\n'
  if [ "$INSECURE" -eq 1 ]; then printf 'insecure\n'; fi
} > /etc/paywen-agent/curlrc
chmod 600 /etc/paywen-agent/agent.env /etc/paywen-agent/curlrc

# Comando de ayuda: sudo paywen-agent run | status | logs | test
cat > /usr/local/bin/paywen-agent <<'EOF'
#!/bin/bash
# Atajos del agente de Paywen Scan.
case "${1:-status}" in
  run)    exec systemctl start paywen-agent.service ;;
  status) systemctl status paywen-agent.timer paywen-agent.service --no-pager; echo; systemctl list-timers paywen-agent.timer --no-pager ;;
  logs)   exec journalctl -u paywen-agent -n "${2:-50}" --no-pager ;;
  test)   APP_URL=$(sed -n 's/^APP_URL=//p' /etc/paywen-agent/agent.env)
          curl -fsS -K /etc/paywen-agent/curlrc --max-time 15 "$APP_URL/healthz" && echo && echo "Conexión OK con $APP_URL" ;;
  *)      echo "Uso: sudo paywen-agent [run|status|logs [N]|test]"; exit 1 ;;
esac
EOF
chmod 755 /usr/local/bin/paywen-agent

# ─── 4. Servicio y timer de systemd (persistente entre reinicios) ─────────────
info "4/5 Creando el servicio y el timer de systemd"
cat > /etc/systemd/system/paywen-agent.service <<'EOF'
[Unit]
Description=Agente de Paywen Scan: inventario y envío a la app
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/paywen-agent/agent.sh
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=1800
EOF

cat > /etc/systemd/system/paywen-agent.timer <<EOF
[Unit]
Description=Agente de Paywen Scan: ejecución periódica

[Timer]
OnBootSec=15min
OnUnitActiveSec=$INTERVAL
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now paywen-agent.timer

# ─── 5. Prueba de conexión y primer envío ─────────────────────────────────────
info "5/5 Probando la conexión con la app y enviando el primer inventario"
if ! curl -fsS -K /etc/paywen-agent/curlrc --max-time 15 -o /dev/null "$URL/healthz"; then
  echo "No se pudo conectar con $URL/healthz." >&2
  echo "El agente quedó instalado y el timer lo reintentará solo. Revisa:" >&2
  echo "  - que la app esté encendida (horario de las instancias)" >&2
  echo "  - si usas la IP en vez del dominio, agrega --insecure" >&2
  echo "  - probar a mano: sudo paywen-agent test" >&2
  exit 2
fi
echo "Conexión OK. Primer envío (1–3 min la primera vez: Trivy descarga sus bases)…"
if systemctl start paywen-agent.service; then
  journalctl -u paywen-agent -n 6 --no-pager -o cat
  echo
  echo "Listo: '$NAME' quedó registrado en la app. Aparece en el dashboard con sus"
  echo "hallazgos después de la próxima pasada del worker (cada 30 min)."
else
  journalctl -u paywen-agent -n 30 --no-pager -o cat >&2
  die "El primer envío falló (ver arriba). Reintentar con: sudo paywen-agent run"
fi
