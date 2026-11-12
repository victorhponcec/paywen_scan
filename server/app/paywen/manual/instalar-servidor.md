# Instalar el servidor

Esta guía instala **Paywen Scan completo** (dashboard, API, worker de inteligencia de amenazas y base de datos) en una máquina con **Ubuntu 24.04 LTS** (física, virtual o en la nube). Un script hace todo y al final te entrega la URL, el usuario, la contraseña y el token para conectar agentes. Toma unos 15 minutos.

```
 agentes (otros equipos) ──HTTPS──▶ Caddy :443 ──▶ api ──▶ PostgreSQL (red interna, sin puertos)
                                     ▲            ▲
 tú (navegador) ──HTTPS─────────────┘          worker (cada 30 min) ──▶ OSV · CISA KEV · EPSS · OTX
```

Todo corre en contenedores de Docker:

| Contenedor | Qué hace |
|---|---|
| `db` | PostgreSQL 16 con los datos. Solo está en una red interna: no publica puertos ni tiene salida a internet |
| `api` | API de ingesta y dashboard |
| `worker` | Cruza los inventarios con OSV, CISA KEV, FIRST EPSS y OTX, y calcula prioridades |
| `caddy` | HTTPS en los puertos 80 y 443 |

---

## 1. Requisitos

| | Mínimo |
|---|---|
| Sistema | **Ubuntu 24.04 LTS** (Server o Desktop) |
| CPU / RAM | 2 vCPU / **2 GB** (4 GB si además vas a usar la VM para otras cosas) |
| Disco libre | **10 GB** (imágenes de Docker, base de datos y caché) |
| Red | Salida a internet por HTTPS (para descargar paquetes y consultar OSV, KEV, EPSS y OTX) |
| Usuario | con `sudo` |

Si ya tienes Docker instalado, el script lo usa. Si no, instala el de Ubuntu (`docker.io` + `docker-compose-v2`).

### Red de la VM: decide desde dónde van a llegar los agentes

| Los agentes estarán en… | Configuración de red de la VM servidor |
|---|---|
| La misma VM del servidor | Cualquiera, incluso NAT |
| Otras VMs del mismo computador | **Red interna / Host-only**, o **Adaptador puente** |
| Otros computadores de tu casa | **Adaptador puente (Bridged)**: la VM recibe una IP de tu router |
| Internet (equipos en otras redes) | Instala el servidor en una VM con IP pública (en la nube, por ejemplo) o abre los puertos 80/443 en tu router, y usa un dominio propio con `--domain` (Let's Encrypt) |

Con NAT (la opción por defecto de VirtualBox), otras máquinas no pueden llegar a la VM. Cambia el adaptador **antes** de instalar; si lo cambias después, corre `sudo paywen-server reconfigure`.

---

## 2. Instalar

```bash
# Copiar paywen-server.zip a la VM (navegador, scp o carpeta compartida) y luego:
cd ~
sudo apt-get update && sudo apt-get install -y unzip
unzip paywen-server.zip
cd paywen-server
sudo ./install-server.sh
```

Opciones útiles:

```bash
sudo ./install-server.sh --otx-key TU_API_KEY_DE_OTX    # habilita la página Campañas
sudo ./install-server.sh --host mi-servidor.lan        # nombre extra para el certificado
sudo ./install-server.sh --domain scan.midominio.cl --email yo@correo.cl   # Let's Encrypt (solo con dominio público)
```

La API key de OTX es gratuita: créala en <https://otx.alienvault.com> (Settings → API Integration). Sin ella, todo funciona salvo la página de Campañas. Se puede agregar después (sección 7).

El script hace seis pasos y los va mostrando:

1. **Docker:** lo instala si falta y lo habilita al arranque.
2. **Archivos:** copia la app a `/opt/paywen-server` y crea el comando `paywen-server`.
3. **Contraseñas:** genera contraseñas y tokens aleatorios en `/opt/paywen-server/.env` (permisos 600).
4. **HTTPS:** genera el certificado para las IPs de la VM (o para tu dominio).
5. **Contenedores:** construye la imagen y levanta los contenedores. La base de datos se crea en este paso (sección 5).
6. **Verificación:** espera a que la app responda y muestra un resumen como este:

```
════════════════════════════════════════════════════════════════════
 Paywen Scan instalado
════════════════════════════════════════════════════════════════════
Dashboard:
  https://192.168.1.50
  https://localhost
  Usuario:     admin
  Contraseña:  3f9a…
Token de agentes: 6761…

En la VM del agente (con el contenido de paywen-agent.zip):
  sudo ./install.sh --url https://192.168.1.50 --token 6761… --name NOMBRE-UNICO --interval 1h --insecure
```

**Guarda ese resumen.** Si lo pierdes, lo vuelves a ver con `sudo paywen-server credentials`.

---

## 3. Entrar al dashboard

Abre la URL del resumen (por ejemplo `https://192.168.1.50`). El navegador va a advertir del certificado: es un certificado **interno**, emitido por el propio Caddy de tu servidor, y es normal en una red local. Acepta la advertencia y entra con el usuario `admin` y la contraseña del resumen.

Al principio está vacío: falta conectar al menos un agente.

## 4. Conectar agentes

Hay un agente para cada sistema, con su propia guía:

| Equipo | Paquete | También en el servidor |
|---|---|---|
| Linux (Ubuntu 24.04) | `paywen-agent.zip` | `/opt/paywen-server/agent/` |
| Windows (Server 2016+ o 10/11) | `paywen-agent-windows.zip` | `/opt/paywen-server/agent-windows/` |

El comando exacto para tu servidor (URL y token incluidos) lo da:

```bash
sudo paywen-server agent-command
```

- **En la misma VM del servidor:** `--url https://localhost --insecure`.
- **En otras VMs:** usa la IP del servidor (`--url https://192.168.1.50 --insecure`). `--insecure` es necesario porque el certificado es interno.
- **`--name`:** usa un nombre distinto para cada equipo.
- **Windows:** `.\install.ps1 -Url "https://192.168.1.50" -Name "srv-win-01" -Insecure` (el token se pide de forma oculta).

Después del primer envío, lanza una pasada del worker para ver los hallazgos de inmediato, sin esperar los 30 minutos:

```bash
sudo paywen-server worker
sudo paywen-server logs worker      # Ctrl+C para salir
```

La primera pasada descarga miles de registros de OSV (casi todos del kernel) y tarda de 3 a 5 minutos. Termina con `Pasada terminada sin errores`. Las siguientes usan la caché y son mucho más rápidas.

---

## 5. La base de datos

**No hay que crear nada a mano:** el instalador deja la base, los usuarios y las tablas listos. Esta sección explica qué se creó, para que lo puedas revisar, respaldar o mover a otro PostgreSQL.

### Cómo se crea

1. **Al levantar el contenedor `db` por primera vez** (volumen de datos vacío), la imagen oficial de PostgreSQL crea la base **`paywen`** y el superusuario **`paywen_admin`**, con la contraseña `POSTGRES_PASSWORD` del `.env`.
2. **Luego ejecuta `db-init/01-app-user.sh`,** que crea el usuario de la app con privilegios mínimos:

   ```sql
   CREATE ROLE paywen_app LOGIN PASSWORD '…'          -- APP_DB_PASSWORD del .env
       NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
   ALTER DATABASE paywen OWNER TO paywen_app;          -- dueño de su base…
   ALTER SCHEMA public OWNER TO paywen_app;            -- …y de su esquema, nada más
   REVOKE ALL ON DATABASE paywen FROM PUBLIC;          -- nadie más puede conectarse
   GRANT CONNECT, TEMPORARY ON DATABASE paywen TO paywen_app;
   ```

3. **Al arrancar, la app** (conectada como `paywen_app`) ejecuta `app/paywen/schema.sql`, que crea las tablas con `CREATE TABLE IF NOT EXISTS`. Se aplica en cada arranque sin borrar nada, así que una versión nueva de la app puede agregar tablas sin migraciones manuales.

### Usuarios

| Usuario | Tipo | Para qué |
|---|---|---|
| `paywen_admin` | Superusuario | Solo administración: respaldos, restauraciones, cambios de contraseña. La app **no** lo usa |
| `paywen_app` | Usuario normal, dueño de la base `paywen` | El que usa la app. No puede crear bases ni roles, ni conectarse a otras bases |

Ninguno de los dos es accesible desde fuera: el contenedor `db` no publica puertos y está en una red interna de Docker. Las contraseñas están en `/opt/paywen-server/.env` (`POSTGRES_PASSWORD` y `APP_DB_PASSWORD`) y también aparecen en `sudo paywen-server credentials`.

### Tablas

| Tabla | Contenido |
|---|---|
| `hosts` | Un registro por servidor monitoreado: nombre, sistema operativo, última vez que reportó, puntaje de riesgo |
| `components` | Paquetes y librerías de cada host, ya agrupados como los consulta OSV (paquete fuente + versión) |
| `ports` | Puertos en escucha de cada host y el proceso detrás |
| `findings` | Hallazgos: componente + vulnerabilidad (CVE), con CVSS, versión que corrige, si está expuesto y su prioridad |
| `osv_vulns` | Caché de registros de OSV (recortados), para no volver a descargarlos |
| `kev` | Catálogo CISA KEV (vulnerabilidades explotadas y uso en ransomware), se actualiza cada 12 h |
| `epss` | Puntajes EPSS de cada CVE, se actualizan cada 24 h |
| `otx` | Pulses de OTX por CVE |
| `meta` | Estado interno (última pasada del worker, versión del catálogo KEV) |
| `host_snapshots` | Histórico: una foto por host y por día (hallazgos por prioridad, KEV, ransomware, puntaje, nuevas y resueltas). Es la base de los gráficos |
| `vuln_history` | Cuándo apareció cada vulnerabilidad en cada host y cuándo se resolvió |

Borrar un host borra en cascada sus componentes, puertos, hallazgos e histórico.

### Consola SQL y consultas útiles

```bash
sudo paywen-server psql
```

```sql
\dt                                                     -- listar tablas
SELECT hostname, risk_score, last_seen FROM hosts ORDER BY risk_score DESC;
SELECT count(*) FROM findings WHERE priority_rank = 3;  -- hallazgos críticos
SELECT f.vuln_key, c.name, h.hostname                   -- qué hallazgos están en KEV
  FROM findings f JOIN components c ON c.id = f.component_id JOIN hosts h ON h.id = f.host_id
  JOIN kev k ON k.cve = f.vuln_key;
DELETE FROM hosts WHERE hostname = 'vm-de-prueba';      -- quitar un host del dashboard
\q
```

### Respaldo y restauración

```bash
sudo paywen-server backup                  # deja /var/backups/paywen/paywen-AAAAMMDD-HHMMSS.dump
sudo paywen-server restore /var/backups/paywen/paywen-20261030-2100.dump   # pide confirmación
```

### Cambiar las contraseñas de la base

Las contraseñas del `.env` solo se aplican **la primera vez** que se crea el volumen de datos. Para cambiarlas después, hay que cambiarlas en la base **y** en el `.env`:

```bash
NEW=$(openssl rand -hex 24)
sudo paywen-server psql -c "ALTER ROLE paywen_app PASSWORD '$NEW'"
sudo sed -i "s/^APP_DB_PASSWORD=.*/APP_DB_PASSWORD=$NEW/" /opt/paywen-server/.env
cd /opt/paywen-server && sudo docker compose up -d      # recrea api y worker con la nueva
```

Para `paywen_admin`, es lo mismo con `ALTER ROLE paywen_admin` y `POSTGRES_PASSWORD`.

### Usar un PostgreSQL propio (opcional)

Si prefieres un PostgreSQL ya instalado (versión 14 o mayor) en vez del contenedor:

1. Como superusuario de ese PostgreSQL, crea la base y el usuario de la app:

   ```sql
   CREATE ROLE paywen_app LOGIN PASSWORD 'una-clave-larga' NOSUPERUSER NOCREATEDB NOCREATEROLE;
   CREATE DATABASE paywen OWNER paywen_app;
   \c paywen
   ALTER SCHEMA public OWNER TO paywen_app;
   REVOKE ALL ON DATABASE paywen FROM PUBLIC;
   ```

2. En `/opt/paywen-server/compose.yaml`, cambia la línea `DATABASE_URL` de `x-app-env` por la de tu servidor, por ejemplo `postgresql://paywen_app:una-clave-larga@192.168.1.60:5432/paywen?sslmode=require`. Luego borra o comenta el servicio `db` y las líneas `depends_on: db` de `api` y `worker`.
   > Volver a correr `install-server.sh` restaura el `compose.yaml` original. Si actualizas la app, repite este paso.

3. Ejecuta `sudo docker compose up -d` en `/opt/paywen-server`. La app crea las tablas sola. Si prefieres crearlas a mano antes:

   ```bash
   psql "postgresql://paywen_app:una-clave-larga@192.168.1.60:5432/paywen" -f /opt/paywen-server/app/paywen/schema.sql
   ```

---

## 6. Persistencia: qué pasa al reiniciar la VM

No hay que hacer nada: **todo vuelve a subir solo**. El instalador habilitó Docker al arranque (`systemctl enable docker`) y los cuatro contenedores tienen `restart: unless-stopped`. Los datos están en volúmenes de Docker (`paywen_pgdata` y `paywen_caddy_data`), que no se borran al reiniciar ni al actualizar.

Para comprobarlo:

```bash
systemctl is-enabled docker              # enabled
sudo reboot
# … después de reiniciar:
sudo paywen-server status                # 4 contenedores "Up" y "App: OK"
```

Si la IP de la VM cambió después de reiniciar (DHCP), el certificado ya no la incluye y los agentes van a fallar con un error de TLS. Corre `sudo paywen-server reconfigure` y actualiza la URL de los agentes. Para evitarlo, fija la IP de la VM en tu router (reserva DHCP).

---

## 7. Administración diaria

| Comando | Qué hace |
|---|---|
| `sudo paywen-server status` | Estado de los contenedores y de la app |
| `sudo paywen-server credentials` | URL, usuario, contraseña, token y contraseñas de la base |
| `sudo paywen-server agent-command` | Comando listo para instalar un agente |
| `sudo paywen-server logs [api\|worker\|db\|caddy]` | Logs en vivo |
| `sudo paywen-server worker` | Pasada del worker ahora |
| `sudo paywen-server psql` | Consola SQL (administrador) |
| `sudo paywen-server backup` / `restore ARCHIVO` | Respaldo y restauración |
| `sudo paywen-server reconfigure` | Regenera el certificado (IP nueva, `--host` nuevo) |
| `sudo paywen-server restart` / `stop` / `start` | Reiniciar, detener o arrancar |
| `sudo paywen-server demo 30` / `demo --clear` | Genera 30 días de datos de ejemplo para el histórico / los borra |
| `sudo paywen-server version` | Versión instalada |

### Agregar o cambiar la API key de OTX

```bash
sudo sed -i 's/^OTX_API_KEY=.*/OTX_API_KEY=TU_KEY/' /opt/paywen-server/.env
cd /opt/paywen-server && sudo docker compose up -d
sudo paywen-server worker
```

### Cambiar la contraseña del dashboard

```bash
sudo sed -i "s/^DASHBOARD_PASSWORD=.*/DASHBOARD_PASSWORD=$(openssl rand -hex 12)/" /opt/paywen-server/.env
cd /opt/paywen-server && sudo docker compose up -d
sudo paywen-server credentials
```

### Actualizar a una versión nueva

Descomprime el zip nuevo y vuelve a correr el instalador. Conserva el `.env`, la base de datos y los certificados. Las tablas nuevas se crean solas al arrancar:

```bash
sudo paywen-server backup                      # por si acaso
unzip -o paywen-server.zip && cd paywen-server && sudo ./install-server.sh
sudo paywen-server version                     # debe decir la versión nueva
sudo paywen-server worker                      # primera foto del histórico
```

Las novedades de cada versión están en el dashboard, en **Docs › Novedades**.

### Estado de los agentes (verde, naranjo, rojo)

En **Servidores** cada host muestra su estado según cuánto hace que llegó su último inventario:

- **En línea:** menos de 2 h.
- **Atrasado:** entre 2 y 6 h.
- **Sin reportar:** 6 h o más.

Si tus agentes usan `--interval 6h`, sube los umbrales, o baja el intervalo de los agentes a 1 h:

```bash
echo "STATUS_WARN_HOURS=8"     | sudo tee -a /opt/paywen-server/.env
echo "STATUS_OFFLINE_HOURS=14" | sudo tee -a /opt/paywen-server/.env
cd /opt/paywen-server && sudo docker compose up -d
```

### Datos de ejemplo para el histórico (demo)

El histórico se llena con una foto por día y parte de cero al instalar. Para mostrar cómo se ven los gráficos con varias semanas de datos, después de la primera pasada del worker:

```bash
sudo paywen-server demo 30       # 30 días simulados hacia atrás (no pisa fotos reales)
sudo paywen-server demo --clear  # los borra
```

El dashboard avisa con una franja amarilla cuando muestra datos de ejemplo.

### Desinstalar

```bash
sudo ./install-server.sh --uninstall           # quita la app; conserva datos y .env
sudo ./install-server.sh --uninstall --purge   # borra TODO, incluida la base de datos
```

---

## Problemas comunes

| Síntoma | Causa | Qué hacer |
|---|---|---|
| `La app no respondió en 3 minutos` | Falla de la base o de la API | El script muestra los logs. Revisa espacio (`df -h /`) y memoria (`free -m`) |
| El build falla con `no space left on device` | Falta disco | Libera espacio (`sudo docker system prune`) y vuelve a correr el instalador |
| Desde otra VM, `curl: (7) Failed to connect` | Red de la VM en NAT, o firewall | Usa Adaptador puente o Host-only (sección 1). `sudo ufw status`: deben estar abiertos 80 y 443 |
| Agente con `curl: (60) SSL certificate problem` | Falta `--insecure` | Reinstala el agente con `--insecure` |
| Agente con error TLS después de reiniciar la VM | Cambió la IP del servidor | `sudo paywen-server reconfigure` y actualiza la URL del agente |
| Agente con `401` | Token equivocado | `sudo paywen-server credentials` y reinstala el agente con el token correcto |
| `api` reiniciándose, `password authentication failed` | Cambiaste `APP_DB_PASSWORD` en el `.env` sin cambiarla en la base | Sigue "Cambiar las contraseñas de la base" (sección 5) |
| El worker terminó con `exit 137` | Se quedó sin memoria | Dale 2 GB o más a la VM, o agrega swap: `sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile` |
| Campañas vacía | Sin API key de OTX | Sección 7 |
| Host sin hallazgos | El worker todavía no lo cruzó | `sudo paywen-server worker` |

## Seguridad

- **Credenciales:** el `.env` tiene todas las contraseñas (permisos 600). No lo subas a ningún repositorio ni lo compartas.
- **Exposición a internet:** el dashboard tiene login, pero el servidor está pensado para una red local o de laboratorio. Antes de exponerlo a internet, usa `--domain` (Let's Encrypt) y una contraseña fuerte.
- **Base de datos:** nunca queda expuesta. Para entrar, usa `sudo paywen-server psql` desde el propio servidor.

## Archivos

| Ruta | Qué es |
|---|---|
| `/opt/paywen-server/compose.yaml` | Definición de los contenedores |
| `/opt/paywen-server/.env` | Contraseñas y configuración (600) |
| `/opt/paywen-server/Caddyfile` | Configuración HTTPS (la genera `paywen-server reconfigure`) |
| `/opt/paywen-server/app/` | Código de la app (de aquí se construye la imagen) |
| `/opt/paywen-server/db-init/01-app-user.sh` | Creación del usuario `paywen_app` |
| `/opt/paywen-server/agent/` | Agente de Linux, para copiar a otros equipos |
| `/opt/paywen-server/agent-windows/` | Agente de Windows (`install.ps1`) |
| `/usr/local/bin/paywen-server` | Comando de administración |
| Volúmenes `paywen_pgdata`, `paywen_caddy_data` | Datos de la base y certificados |
