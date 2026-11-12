#!/bin/bash
# Instalador portable de Paywen Scan (servidor: app + base de datos + HTTPS).
# Probado para Ubuntu 24.04 LTS. No necesita servicios externos (salvo las fuentes públicas de datos).
#
#   sudo ./install-server.sh                       certificado interno, acceso por IP
#   sudo ./install-server.sh --otx-key KEY         con API key de AlienVault OTX
#   sudo ./install-server.sh --domain scan.midominio.cl --email yo@correo.cl
#                                                  Let's Encrypt (dominio público apuntando a esta máquina)
#   sudo ./install-server.sh --uninstall           detiene y quita la app (conserva los datos)
#   sudo ./install-server.sh --uninstall --purge   quita TODO, incluida la base de datos
#
# Opciones:
#   --otx-key KEY        API key de OTX (opcional; sin ella no hay página de Campañas)
#   --domain NOMBRE      dominio público para Let's Encrypt (requiere puertos 80/443 accesibles desde internet)
#   --email CORREO       correo para Let's Encrypt
#   --host NOMBRE        nombre o IP extra para el certificado interno (se puede repetir)
#   --worker-interval S  segundos entre pasadas del worker (por omisión 1800)
#   --dir RUTA           carpeta de instalación (por omisión /opt/paywen-server)
#   --force              instalar aunque no sea Ubuntu 24.04
#
# Volver a ejecutarlo actualiza la app sin perder datos ni contraseñas.

set -euo pipefail

VERSION="1.2.0"
PREFIX="/opt/paywen-server"
OTX=""
OTX_SET=0
DOMAIN=""
EMAIL=""
EXTRA_HOSTS=""
WORKER_INTERVAL=""
FORCE=0
UNINSTALL=0
PURGE=0
HERE=$(cd "$(dirname "$0")" && pwd)

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
info() { printf '\n==> %s\n' "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
secret() { openssl rand -hex "$1"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --otx-key) OTX="${2:-}"; OTX_SET=1; shift 2 ;;
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --email) EMAIL="${2:-}"; shift 2 ;;
    --host) EXTRA_HOSTS="$EXTRA_HOSTS ${2:-}"; shift 2 ;;
    --worker-interval) WORKER_INTERVAL="${2:-}"; shift 2 ;;
    --dir) PREFIX="${2:-}"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "Opción desconocida: $1" >&2; usage 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "Ejecutar con sudo"
PREFIX="${PREFIX%/}"
dc() { docker compose --project-directory "$PREFIX" -f "$PREFIX/compose.yaml" "$@"; }

# ─── Desinstalar ──────────────────────────────────────────────────────────────
if [ "$UNINSTALL" -eq 1 ]; then
  [ -f "$PREFIX/compose.yaml" ] || die "No hay instalación en $PREFIX"
  if [ "$PURGE" -eq 1 ]; then
    read -r -p "Se borrarán la app, la base de datos y los certificados. ¿Continuar? [s/N] " ok
    [ "$ok" = "s" ] || [ "$ok" = "S" ] || exit 1
    dc down -v --rmi local
    rm -rf "$PREFIX" /etc/paywen-server
    rm -f /usr/local/bin/paywen-server
    echo "Paywen Scan eliminado por completo."
  else
    dc down
    rm -f /usr/local/bin/paywen-server
    echo "App detenida y quitada. Los datos (volúmenes de Docker) y $PREFIX/.env se conservan:"
    echo "al volver a instalar, todo vuelve como estaba. Para borrar todo: --uninstall --purge"
  fi
  exit 0
fi

# ─── Validaciones ─────────────────────────────────────────────────────────────
for f in compose.yaml paywen-server db-init/01-app-user.sh app/Dockerfile app/paywen/main.py; do
  [ -e "$HERE/$f" ] || die "Falta $f junto a install-server.sh (¿se descomprimió completo el zip?)"
done
if [ -n "$DOMAIN" ]; then
  [[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "--domain no parece un dominio válido"
fi
if [ -n "$WORKER_INTERVAL" ]; then
  [[ "$WORKER_INTERVAL" =~ ^[0-9]+$ ]] && [ "$WORKER_INTERVAL" -ge 300 ] || die "--worker-interval debe ser un número de segundos ≥ 300"
fi
# shellcheck source=/dev/null
. /etc/os-release
if [ "${ID:-}" != "ubuntu" ] || [ "${VERSION_ID:-}" != "24.04" ]; then
  echo "Este sistema es ${PRETTY_NAME:-desconocido}; el instalador está probado en Ubuntu 24.04 LTS."
  [ "$FORCE" -eq 1 ] || die "Usa --force para instalar de todas formas"
fi
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
[ "$MEM_MB" -ge 1800 ] || echo "AVISO: la máquina tiene ${MEM_MB} MB de RAM; se recomiendan 2 GB o más."

echo "Paywen Scan servidor $VERSION → $PREFIX"

# ─── 1. Docker ────────────────────────────────────────────────────────────────
info "1/6 Docker y herramientas"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q ca-certificates curl openssl iproute2
if ! command -v docker >/dev/null; then
  apt-get install -y -q docker.io docker-compose-v2
fi
if ! docker compose version >/dev/null 2>&1; then
  # Docker CE (repo de Docker) trae el plugin con otro nombre que Docker de Ubuntu.
  if dpkg -s docker-ce >/dev/null 2>&1; then apt-get install -y -q docker-compose-plugin
  else apt-get install -y -q docker-compose-v2; fi
fi
systemctl enable --now docker   # Docker al arranque = la app vuelve sola tras reiniciar
docker compose version

# ─── 2. Archivos ──────────────────────────────────────────────────────────────
info "2/6 Copiando la app a $PREFIX"
install -d -m 755 "$PREFIX" /etc/paywen-server
echo "$PREFIX" > /etc/paywen-server/prefix
rm -rf "$PREFIX/app" "$PREFIX/db-init" "$PREFIX/agent" "$PREFIX/agent-windows"
cp -r "$HERE/app" "$HERE/db-init" "$PREFIX/"
# Agentes para repartir: junto al script (paywen-server.zip) o en carpetas hermanas (repositorio).
for d in "$HERE/agent" "$HERE/../agent-linux"; do
  if [ -d "$d" ]; then cp -r "$d" "$PREFIX/agent"; break; fi
done
for d in "$HERE/agent-windows" "$HERE/../agent-windows"; do
  if [ -d "$d" ]; then cp -r "$d" "$PREFIX/agent-windows"; break; fi
done
install -m 644 "$HERE/compose.yaml" "$PREFIX/compose.yaml"
install -m 755 "$HERE/paywen-server" /usr/local/bin/paywen-server
chmod 755 "$PREFIX/db-init/01-app-user.sh"
echo "$VERSION" > "$PREFIX/VERSION"

# ─── 3. Secretos (.env) ───────────────────────────────────────────────────────
info "3/6 Configuración y contraseñas ($PREFIX/.env)"
ENV_FILE="$PREFIX/.env"
set_env() {   # set_env CLAVE VALOR: reemplaza o agrega
  local key="$1" value="$2"
  if grep -q "^$key=" "$ENV_FILE"; then
    sed -i "s|^$key=.*|$key=$value|" "$ENV_FILE"
  else
    echo "$key=$value" >> "$ENV_FILE"
  fi
}
if [ -f "$ENV_FILE" ]; then
  echo "Se mantiene el .env existente (las contraseñas de la base ya están en uso)."
else
  umask 077
  cat > "$ENV_FILE" <<EOF
# Paywen Scan — generado por install-server.sh el $(date -Iseconds)
# NO compartir este archivo. Las contraseñas de la base solo se aplican
# la primera vez que se crea el volumen de datos (ver INSTALAR-SERVIDOR.md).
POSTGRES_PASSWORD=$(secret 24)
APP_DB_PASSWORD=$(secret 24)
AGENT_TOKEN=$(secret 20)
DASHBOARD_USER=admin
DASHBOARD_PASSWORD=$(secret 12)
OTX_API_KEY=
WORKER_INTERVAL_SECONDS=1800
DISPLAY_TZ=America/Santiago
DOMAIN=
ACME_EMAIL=
EXTRA_HOSTS=
EOF
  umask 022
  echo "Contraseñas generadas."
fi
chmod 600 "$ENV_FILE"
[ "$OTX_SET" -eq 0 ] || set_env OTX_API_KEY "$OTX"
[ -z "$DOMAIN" ] || set_env DOMAIN "$DOMAIN"
[ -z "$EMAIL" ] || set_env ACME_EMAIL "$EMAIL"
[ -z "$EXTRA_HOSTS" ] || set_env EXTRA_HOSTS "$(echo "$EXTRA_HOSTS" | xargs)"
[ -z "$WORKER_INTERVAL" ] || set_env WORKER_INTERVAL_SECONDS "$WORKER_INTERVAL"

# ─── 4. HTTPS (Caddyfile) ─────────────────────────────────────────────────────
info "4/6 Certificado HTTPS"
paywen-server _caddyfile
sed 's/^/  /' "$PREFIX/Caddyfile"
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 80/tcp >/dev/null && ufw allow 443/tcp >/dev/null && echo "Firewall (ufw): abiertos 80 y 443"
fi

# ─── 5. Construir y levantar ──────────────────────────────────────────────────
info "5/6 Construyendo la imagen y levantando los contenedores (2–5 min la primera vez)"
dc build api
dc up -d --remove-orphans

# ─── 6. Esperar a que responda ────────────────────────────────────────────────
info "6/6 Esperando a que la app responda"
for _ in $(seq 1 60); do
  if paywen-server status 2>/dev/null | grep -q "^App: OK"; then OK=1; break; fi
  sleep 3
done
if [ "${OK:-0}" -ne 1 ]; then
  dc ps
  dc logs --tail 40 api db
  die "La app no respondió en 3 minutos (ver los logs de arriba)"
fi

echo
echo "════════════════════════════════════════════════════════════════════"
echo " Paywen Scan instalado"
echo "════════════════════════════════════════════════════════════════════"
paywen-server credentials
echo
paywen-server agent-command
echo
echo "El worker hace su primera pasada en los próximos minutos (sudo paywen-server logs worker)."
echo "Administración: sudo paywen-server help"
