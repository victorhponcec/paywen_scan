# Instalar el agente de Linux

> **Desde el repositorio:** esta carpeta equivale al contenido de `paywen-agent.zip`. Cópiala al equipo (o clona el repositorio en él) y ejecuta `sudo ./install.sh` desde aquí.

Esta guía instala el agente en un servidor Linux (probado en **Ubuntu 24.04 LTS**) para que su inventario aparezca en el dashboard de Paywen Scan. Se hace una vez, en unos 10 minutos. Después el agente funciona solo, también después de reiniciar el equipo.

Para equipos Windows, ver **Instalar el agente de Windows**.

## Qué hace el agente y qué envía

Cada cierto tiempo (1 h recomendado; 6 h por omisión), el agente hace lo siguiente:

1. **Trivy** lista los paquetes del sistema y las librerías de lenguajes instalados.
2. El agente agrega el sistema operativo, el kernel y los puertos en escucha (`ss`).
3. Envía todo por HTTPS al servidor de Paywen Scan, con un token.

**Envía:** el nombre del equipo, la versión del sistema operativo y del kernel, la lista de paquetes y librerías con su versión, y los puertos abiertos con el proceso que escucha en cada uno.

**No envía:** el contenido de los archivos, usuarios, contraseñas, historial ni variables de entorno. Para ver exactamente qué se envió:

```bash
sudo jq '{hostname, os, ports, componentes: (.sbom.components | length)}' /var/lib/paywen-agent/last-payload.json
```

## Antes de empezar

| Necesitas | Detalle |
|---|---|
| Un equipo con **Ubuntu 24.04 LTS** | Desktop o Server, con systemd. Debian y otras versiones de Ubuntu suelen funcionar con `--force` |
| Un usuario con **sudo** | |
| **Salida HTTPS (443)** | Para descargar Trivy y llegar al servidor. No hace falta abrir puertos de entrada: el agente funciona detrás de un NAT |
| ~1,5 GB libres en disco y 1 GB de RAM | Trivy guarda sus bases en `/var/cache/trivy` |
| La **URL** del servidor y el **token** de agentes | Te los entrega el administrador de Paywen Scan por un canal privado. En el servidor se obtienen con `sudo paywen-server agent-command` |

| Dato | Ejemplo |
|---|---|
| URL del servidor | `https://paywen.ejemplo.cl` (con dominio) o `https://192.168.1.50` (por IP, con certificado interno) |
| Token | 40 caracteres. **No lo publiques** en chats ni repositorios |
| Nombre del equipo | uno **único**, por ejemplo `srv-web-01`. Si dos equipos usan el mismo nombre, en el dashboard uno pisa al otro |

---

## Paso 1 — Copiar el zip al equipo

Usa cualquiera de estas opciones:

- **Descargarlo directamente** en el equipo.
- **Por SSH desde tu computador:**
  ```bash
  scp paywen-agent.zip usuario@IP-DEL-EQUIPO:~/
  ```
- **Carpeta compartida** de VirtualBox o VMware.

## Paso 2 — Descomprimir

```bash
cd ~
sudo apt-get update && sudo apt-get install -y unzip
unzip paywen-agent.zip
cd paywen-agent
ls
```

Deberías ver `install.sh`, `paywen-agent.sh`, `INSTALAR.md` y `VERSION`.

## Paso 3 — Instalar

Reemplaza la URL, `TOKEN` y el nombre por los tuyos:

```bash
sudo ./install.sh \
  --url https://paywen.ejemplo.cl \
  --token TOKEN \
  --name srv-web-01 \
  --interval 1h
```

Si el servidor usa **certificado interno** (instalación por IP, sin dominio), agrega `--insecure`:

```bash
sudo ./install.sh --url https://192.168.1.50 --token TOKEN --name srv-web-01 --interval 1h --insecure
```

`--interval 1h` envía el inventario cada hora. Así el estado del equipo en el dashboard se mantiene en verde; con 6 h se vería atrasado la mayor parte del tiempo.

El instalador hace cinco pasos y los va mostrando:

1. Instala `curl`, `jq`, `iproute2` y `gnupg`.
2. Instala **Trivy 0.69.3** desde el repositorio oficial de Aqua y la deja fija con `apt-mark hold`. La versión 0.69.4 está bloqueada porque fue comprometida en marzo de 2026 (CVE-2026-33634).
3. Copia el agente a `/opt/paywen-agent` y guarda la configuración en `/etc/paywen-agent`, con permisos solo para root.
4. Crea el servicio y el timer de systemd.
5. Prueba la conexión y envía el primer inventario. Puede tardar 1 a 3 minutos, porque Trivy descarga sus bases.

Si todo salió bien, termina con algo así:

```
Inventario de srv-web-01: 1100 componentes. Enviando a https://paywen.ejemplo.cl…
{"status":"ok","host_id":3,"components":640,"changed":true,"warnings":[]}
Inventario enviado a https://paywen.ejemplo.cl

Listo: 'srv-web-01' quedó registrado en la app.
```

## Paso 4 — Verificar

En el equipo:

```bash
sudo paywen-agent test        # prueba la conexión: {"ok":true,...} y "Conexión OK"
sudo paywen-agent status      # estado del timer y cuándo es el próximo envío
sudo paywen-agent logs        # últimas 50 líneas del agente
sudo paywen-agent run         # enviar el inventario ahora (no espera al timer)
```

En el dashboard, el equipo aparece en **Servidores** y en **Resumen › Riesgo por host**:

- **De inmediato** aparece como *pendiente de cruce*.
- **Sus hallazgos aparecen después de la próxima pasada del worker,** que corre cada 30 minutos. El administrador puede lanzarla a mano con `sudo paywen-server worker`.

## Paso 5 — Persistencia (que siga funcionando después de reiniciar)

El instalador ya dejó el timer **habilitado**, así que no hay que hacer nada más. Después de cada arranque, el agente corre a los 15 minutos y luego cada `--interval`. Para comprobarlo:

```bash
systemctl is-enabled paywen-agent.timer       # debe decir: enabled
systemctl list-timers paywen-agent.timer      # muestra NEXT (próximo envío) y LAST (último)
```

Para probarlo de verdad, reinicia el equipo, espera unos 20 minutos y revisa:

```bash
sudo reboot
# … después de reiniciar y esperar unos 20 minutos:
sudo paywen-agent logs 10      # debe aparecer un "Inventario enviado" con hora posterior al reinicio
```

---

## Cómo se ve en el dashboard

En **Servidores**, cada equipo tiene un estado según cuánto hace que llegó su último inventario:

| Estado | Último inventario |
|---|---|
| **En línea** (verde) | hace menos de 2 h |
| **Atrasado** (naranjo) | entre 2 y 6 h |
| **Sin reportar** (rojo) | hace 6 h o más |

El histórico guarda una foto diaria del equipo. Si actualizas paquetes (`sudo apt upgrade` y luego `sudo paywen-agent run`), al día siguiente las vulnerabilidades corregidas aparecen como *resueltas* en **Histórico**.

## Opcional: que el equipo tenga algo que mostrar

Un equipo recién instalado tiene pocos hallazgos importantes. Para ver cómo la app marca un servicio como *expuesto*, instala un servidor web y vuelve a enviar el inventario:

```bash
sudo apt-get install -y nginx
sudo paywen-agent run
```

Los hallazgos de nginx suben un nivel de prioridad por estar escuchando en el puerto 80.

## Cambiar la configuración

Para cambiar el nombre, la URL, el token o el intervalo, vuelve a correr el instalador con los valores nuevos. Reemplaza la configuración y no duplica nada:

```bash
cd ~/paywen-agent
sudo ./install.sh --url https://paywen.ejemplo.cl --token TOKEN --name otro-nombre --interval 2h
```

Si cambias el nombre, el anterior queda en el dashboard como un equipo que dejó de reportar.

## Desinstalar

```bash
cd ~/paywen-agent
sudo ./install.sh --uninstall
```

Borra el agente, su configuración y el timer. Trivy queda instalado; el comando para quitarlo también aparece en pantalla.

---

## Problemas comunes

| Síntoma | Causa | Qué hacer |
|---|---|---|
| `No se pudo conectar con …/healthz` | El servidor no responde o el equipo no tiene salida a internet | Prueba `curl -kI https://URL-DEL-SERVIDOR/healthz`. El agente reintenta solo en el siguiente intervalo |
| `curl: (22) … error: 401` | Token incorrecto o incompleto | Copia el token completo, sin espacios, y vuelve a correr el paso 3 |
| `curl: (22) … error: 403` | Un proxy o CDN delante del servidor bloqueó la petición | Revisa con el administrador las reglas del proxy |
| `curl: (60) SSL certificate problem` | El servidor usa certificado interno | Agrega `--insecure`, o usa el dominio con certificado válido |
| `Este sistema es … ; el agente está probado en Ubuntu 24.04` | Otra distro o versión | Debian o Ubuntu 22.04 suelen funcionar con `--force` |
| `trivy: command not found` o falla el paso 2 | No se pudo descargar Trivy (red o proxy) | Revisa la salida del paso 2 y reintenta; necesitas acceso a `aquasecurity.github.io` |
| `No space left on device` | Falta disco para la caché de Trivy | Libera ~1,5 GB (`sudo apt-get clean`, `docker system prune`…) y reintenta |
| El equipo no aparece en el dashboard | El envío falló o el nombre es otro | `sudo paywen-agent logs` y busca `Inventario enviado` |
| Aparece, pero sin hallazgos | El worker todavía no lo cruzó | Espera hasta 30 minutos o pide una pasada manual |

### Archivos que instala

| Ruta | Qué es |
|---|---|
| `/opt/paywen-agent/agent.sh` | el agente |
| `/etc/paywen-agent/agent.env` | URL del servidor y nombre del equipo |
| `/etc/paywen-agent/curlrc` | token (permisos 600, solo root) |
| `/etc/systemd/system/paywen-agent.{service,timer}` | servicio y timer |
| `/usr/local/bin/paywen-agent` | atajos: `run`, `status`, `logs`, `test` |
| `/var/lib/paywen-agent/last-payload.json` | el último inventario enviado |
| `/var/cache/trivy` | caché de Trivy |
