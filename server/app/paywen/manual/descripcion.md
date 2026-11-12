# Paywen Scan — descripción general

**Plataforma de inteligencia de amenazas sobre el inventario de los servidores** · versión 1.2

Diplomado de Gestión Técnica de Ciberseguridad · Pontificia Universidad Católica de Chile
Curso 5 — Proyecto de innovación · Los seguritos (Grupo 4)

---

## 1. Qué es y qué problema resuelve

Un servidor Linux típico tiene cientos de paquetes instalados, y cada uno puede arrastrar decenas de vulnerabilidades conocidas (CVE). Si se revisa solo por gravedad teórica (CVSS), todas parecen urgentes y el equipo termina parchando en el orden equivocado. Mientras tanto, una vulnerabilidad que los atacantes **ya están explotando** puede quedar abierta.

La información para distinguir lo urgente de lo que puede esperar existe y es gratuita (qué se explota hoy, qué probabilidad tiene de explotarse, qué campañas la usan), pero está repartida en distintas fuentes y nadie la cruza con lo que la organización tiene instalado.

**Paywen Scan** hace ese cruce de forma automática:

1. Un **agente** instalado en cada servidor envía su inventario: paquetes, librerías y puertos abiertos.
2. La plataforma compara cada versión instalada con bases públicas de vulnerabilidades.
3. Enriquece cada hallazgo con explotación real, probabilidad de explotación y campañas activas.
4. Un **dashboard** muestra qué parchar primero en cada servidor.

En la prueba del proyecto, un servidor de laboratorio arrojó **más de 5.000 vulnerabilidades únicas**, que la plataforma redujo a **8 que se están explotando hoy** (2 de ellas en campañas de ransomware) y unas 30 de prioridad crítica.

---

## 2. Cómo funciona

![Arquitectura de Paywen Scan](/static/img/arquitectura.svg)

1. **Recolección (agente):** cada cierto tiempo arma el inventario del servidor y lo envía a la API.
2. **Ingesta (API):** valida el token y el formato, agrupa los paquetes como los indexan las bases de vulnerabilidades y guarda el inventario. Si no cambió desde el envío anterior, conserva los resultados ya calculados.
3. **Enriquecimiento (worker):** cruza cada componente con OSV.dev; suma CISA KEV, FIRST EPSS y AlienVault OTX; y calcula la prioridad de cada hallazgo y el puntaje de cada servidor.
4. **Visualización (dashboard):** muestra los resultados ya calculados. No consulta APIs externas al cargar, así que responde rápido.
5. **Histórico:** en cada pasada, el worker guarda una foto diaria de cada servidor. También registra qué vulnerabilidades aparecieron o se resolvieron. Con eso se arman los gráficos de evolución.

---

## 3. Componentes

### 3.1 Los agentes

Hay un agente para **Linux** (script de Bash, probado en Ubuntu 24.04 LTS) y otro para **Windows** (PowerShell 5.1). Los dos envían el mismo formato de inventario a la misma API.

#### Agente de Linux

**Qué recolecta:**

| Dato | Cómo lo obtiene |
|---|---|
| Paquetes del sistema (deb/rpm) y librerías de lenguajes (Python, Node.js, Java, Go…) | **Trivy** (`trivy rootfs`), que genera un SBOM en formato **CycloneDX** |
| Sistema operativo y versión | `/etc/os-release` |
| Kernel | `uname -r` |
| Puertos en escucha y el proceso detrás de cada uno | `ss -tulnp` |
| Nombre del host | `--name` en la instalación, o el hostname |

**Qué NO envía:** el contenido de archivos, usuarios, contraseñas, historial ni variables de entorno. Solo nombres y versiones de software, y puertos.

**De qué depende:**

| Dependencia | Para qué |
|---|---|
| **Trivy 0.69.3** (Aqua Security) | Inventario de software (SBOM). La versión está **fijada** a propósito: la v0.69.4 y las imágenes 0.69.5/0.69.6 fueron comprometidas en un ataque a la cadena de suministro en marzo de 2026 (CVE-2026-33634). El instalador rechaza la 0.69.4 |
| `jq` | Armar el JSON del inventario |
| `curl` | Enviar el inventario por HTTPS |
| `iproute2` (`ss`) | Listar puertos en escucha |
| `systemd` | Timer que ejecuta el agente periódicamente y lo mantiene después de reiniciar |
| `flock` (util-linux) | Evitar dos ejecuciones simultáneas |

**Funcionamiento:**

- **Instalación:** un instalador (`install.sh`) agrega las dependencias, copia el agente a `/opt/paywen-agent` y guarda la configuración en `/etc/paywen-agent`. El token queda en un archivo legible solo por root, y no aparece en la lista de procesos.
- **Ejecución periódica:** un timer de systemd lo ejecuta 15 minutos después de cada arranque y luego cada intervalo configurado (por omisión, 6 horas).
- **Conexión:** el agente es quien inicia la conexión (push), así que funciona detrás de un NAT sin abrir puertos de entrada.
- **Autenticación:** con un token (`Authorization: Bearer`) sobre HTTPS.
- **Registro local:** el último inventario enviado queda en `/var/lib/paywen-agent/last-payload.json`, para auditar exactamente qué se envió.

#### Agente de Windows

Es un script de PowerShell (`install.ps1`) que se instala como tarea programada de SYSTEM (cada 1 h por omisión y 15 minutos después de cada arranque).

| Dato | Cómo lo obtiene | Qué hace el servidor |
|---|---|---|
| Sistema operativo, compilación y revisión | `Win32_OperatingSystem` y el registro | Lo muestra |
| Programas instalados (64 y 32 bits) | Claves *Uninstall* del registro (no usa `Win32_Product`, que repara MSI) | **Solo inventario** |
| Parches de Windows (KB) | `Win32_QuickFixEngineering` | **Solo inventario** |
| Puertos TCP y UDP, con su proceso | `Get-NetTCPConnection`, `Get-NetUDPEndpoint` | Exposición |
| Opcional: librerías de aplicaciones (NuGet, npm, PyPI, Java…) | **Trivy 0.69.3** sobre las carpetas indicadas, con SHA-256 verificado | **Se cruzan** con OSV, KEV, EPSS y OTX |

El token se guarda cifrado con DPAPI del equipo, la carpeta del agente solo es accesible por SYSTEM y Administradores, y el envío no sigue redirecciones. Como OSV no tiene datos de Windows, los programas y KB se muestran como inventario y los hallazgos salen de las librerías.

### 3.2 La API y el dashboard

Aplicación en **Python 3.12** con **FastAPI**, empaquetada en un contenedor Docker que corre sin root.

- **Ingesta (`POST /api/v1/ingest`):** recibe el inventario, lo valida (hasta 50 MB) y traduce el SBOM a componentes consultables:
    - Los paquetes del sistema se agrupan por **paquete fuente**, que es como los indexan las bases de vulnerabilidades. Por ejemplo, `libcurl4t64` y `curl` cuentan como `curl`.
    - El ecosistema se deduce del sistema operativo (por ejemplo, `Ubuntu:24.04:LTS`).
    - Las librerías de lenguajes se identifican por su *Package URL* (purl).
- **Dashboard:** usuario y contraseña sobre HTTPS, con cuatro vistas (ver sección 6).

### 3.3 El worker

Usa la misma imagen que la API y corre cada 30 minutos. En cada pasada:

1. Actualiza el catálogo **CISA KEV** (cada 12 horas).
2. Cruza con **OSV.dev** los servidores cuyo inventario cambió, o que no se revisan hace más de 24 horas. Descarga el detalle de cada vulnerabilidad por lotes, lo recorta a lo que usa y lo guarda en caché.
3. Actualiza los puntajes **EPSS** de los CVEs encontrados (cada 24 horas).
4. Consulta **OTX** solo para los CVEs relevantes: en KEV, con EPSS ≥ 10 % o con CVSS ≥ 9. Tiene un tope de 60 por pasada, para cuidar la cuota de la API.
5. Recalcula la prioridad, la exposición (y por qué puerto) y el puntaje de riesgo.
6. Guarda la foto del día de cada servidor y registra las vulnerabilidades nuevas y resueltas.

Si una fuente no responde, registra el error y sigue con las demás. La próxima pasada lo reintenta.

### 3.4 Base de datos y HTTPS

- **PostgreSQL 16:** guarda hosts, componentes, puertos, hallazgos, el histórico diario y la caché de cada fuente. La app se conecta con un usuario de **privilegios mínimos** (`paywen_app`), y las tablas se crean solas al arrancar.
- **Caddy:** proxy inverso con HTTPS automático. Usa Let's Encrypt cuando hay dominio, o un certificado interno en redes locales.

---

## 4. De dónde sale la información

Todas las fuentes son **públicas y gratuitas**.

| Fuente | Quién la mantiene | Qué aporta | Cómo la usa Paywen Scan |
|---|---|---|---|
| **OSV.dev** | Google (proyecto abierto) | Qué vulnerabilidades afectan **exactamente** a cada paquete y versión. Agrega avisos de GitHub, PyPI, npm, Go, RustSec, Debian, Ubuntu (USN y Ubuntu CVE Tracker), Alpine, AlmaLinux, Rocky y otros | `POST /v1/querybatch` con todo el inventario (hasta 1.000 consultas por llamada) y `GET /v1/vulns/{id}` para el detalle, con caché |
| **CISA KEV** | Agencia de Ciberseguridad de EE. UU. (CISA) | Catálogo de vulnerabilidades **explotadas en el mundo real**, con fecha límite de remediación y la marca de uso en **campañas de ransomware** | Descarga el catálogo completo (JSON) cada 12 horas |
| **FIRST EPSS** | FIRST (Forum of Incident Response and Security Teams) | **Probabilidad** de que un CVE se explote en los próximos 30 días (0–100 %), con su percentil; se recalcula a diario | Consulta en lotes que respetan el límite de 2.000 caracteres de la API, cada 24 horas |
| **AlienVault OTX** | LevelBlue (comunidad Open Threat Exchange) | **Pulses**: reportes de la comunidad sobre campañas, actores y malware que mencionan cada CVE | Consulta solo los CVEs relevantes, con una API key gratuita |
| **NVD** | NIST | Ficha pública de cada CVE | Solo como enlace desde el dashboard |

**Por qué cuatro fuentes:**

- **OSV** dice qué te afecta.
- **KEV** dice qué ya se está explotando.
- **EPSS** dice qué es probable que se explote pronto.
- **OTX** da contexto: quién lo usa y en qué campañas.

Ninguna sirve por sí sola para priorizar.

---

## 5. Cómo prioriza

| Condición | Prioridad |
|---|---|
| El CVE está en **CISA KEV** (se explota hoy) | **Crítica** |
| **EPSS ≥ 10 %** (probable en 30 días) | **Alta** |
| Resto: CVSS ≥ 9 | Alta |
| Resto: CVSS ≥ 7 | Media |
| Resto: CVSS < 7 (sin CVSS, se usa la prioridad de la distribución) | Baja |
| **El paquete está detrás de un puerto en escucha** | **+1 nivel** |

- **Exposición:** se deduce del proceso que escucha en cada puerto. Por ejemplo, `nginx` en el 80 marca expuesto al paquete `nginx`, y un proceso `java` escuchando marca las librerías Java.
- **Puertos locales:** los que solo escuchan en `127.0.0.1` no cuentan como expuestos.
- **Puntaje de riesgo del host (0–100):** suma 25 puntos por cada hallazgo Crítico, 8 por Alto, 2 por Medio y 0,2 por Bajo, con un tope de 100.

---

## 6. Funciones del dashboard

| Vista | Qué muestra |
|---|---|
| **Resumen** | Indicadores: hosts y estado de sus agentes, vulnerabilidades únicas y con parche, cuántas están en KEV y con ransomware, campañas. Además: evolución de 30 días por prioridad (con variación de 7 días), distribución por prioridad, paquetes más vulnerables, riesgo por host, campañas recientes y los hallazgos más urgentes |
| **Servidores** | Todos los hosts con su estado: verde *En línea* (< 2 h desde el último inventario), naranjo *Atrasado* (2–6 h) y rojo *Sin reportar* (≥ 6 h). Muestra sistema, kernel, IP, puertos, componentes y hallazgos, con filtros por sistema operativo, estado o nombre/IP |
| **Host** | Detalle de un servidor: estado, puntaje, evolución y distribución propias, paquetes más vulnerables, puertos en escucha (marca los que son solo locales), inventario por ecosistema, **software instalado y parches KB** (equipos Windows) y sus hallazgos con filtros |
| **Hallazgos** | Lista priorizada con CVSS, EPSS (y percentil), KEV, ransomware, puertos de exposición y **versión que corrige**. Filtros: prioridad, solo KEV, con ransomware, con puerto expuesto, con parche, búsqueda, y en *Más filtros*: servidor, sistema operativo, puerto, ecosistema, EPSS mínimo, CVSS mínimo y nuevas (24 h / 7 / 30 días) |
| **Histórico** | Consolidado o por servidor, en 7, 30 o 90 días: un gráfico por prioridad, vulnerabilidades explotadas (KEV y ransomware), puntaje de riesgo, nuevas y resueltas por día, tendencia de cada servidor y la tabla de datos |
| **Campañas** | Pulses de OTX que mencionan CVEs del inventario, con adversario, malware, etiquetas y hosts afectados |
| **Docs** | Esta documentación, las guías de instalación y las novedades de cada versión (changelog) |
| **Exportar CSV** | Los hallazgos con los filtros aplicados, para llevarlos a una planilla o a un ticket |

**Diseño:**

- Los gráficos se generan en el servidor como SVG, sin JavaScript, así que la página funciona con una política CSP estricta.
- El detalle de cada punto aparece al pasar el mouse, y cada gráfico tiene su leyenda.
- Los íconos son de [Lucide](https://lucide.dev) (licencia ISC).

---|---|
| **Resumen** | Indicadores: hosts monitoreados, vulnerabilidades únicas y con parche, cuántas están en KEV y con ransomware, y campañas relacionadas. También el riesgo por host, los hallazgos más urgentes y las campañas recientes |
| **Hallazgos** | Lista priorizada, con CVSS, EPSS (y percentil), KEV, ransomware, exposición y **versión que corrige**. Filtros por prioridad, solo KEV, EPSS ≥ 10 %, con puerto expuesto, con parche, y búsqueda por CVE o paquete |
| **Host** | Detalle de un servidor: puertos en escucha y proceso, inventario por ecosistema y sus hallazgos |
| **Campañas** | Pulses de OTX que mencionan CVEs del inventario, con adversario, malware, etiquetas y hosts afectados |
| **Exportar CSV** | Los hallazgos con los filtros aplicados, para llevarlos a una planilla o a un ticket |

---

## 7. Seguridad del diseño

- **Agentes y base separados:** los agentes **nunca** se conectan a la base de datos. Toda escritura pasa por una API que valida y autentica.
- **Comunicaciones:** van por HTTPS. Los agentes usan un token; el dashboard, usuario y contraseña comparados en tiempo constante.
- **Base de datos aislada:** está en una red interna de Docker, sin puertos publicados, y la app usa un usuario de privilegios mínimos.
- **Secretos fuera del código:** están en un `.env` generado al azar por el instalador, con permisos 600. Nunca dentro de la imagen ni en el código.
- **Contenedor sin root.** El dashboard funciona sin JavaScript ni recursos externos, con una política CSP estricta y encabezados de seguridad.
- **Exportación CSV:** neutraliza la inyección de fórmulas (celdas que empiezan con `=`, `+`, `-` o `@`).
- **Cadena de suministro:** Trivy queda fijado en la 0.69.3 (en Linux desde el repositorio oficial con `apt-mark hold`; en Windows con el SHA-256 escrito en el script). La 0.69.4, comprometida, se rechaza.
- **Privacidad:** el agente envía solo nombres y versiones de software y puertos; nunca contenido de archivos.

---

## 8. Instalación

Todo el servidor se instala con un solo script en cualquier máquina con **Ubuntu 24.04 LTS** (física, virtual o en la nube), con Docker:

| Pieza | Cómo queda |
|---|---|
| App (API + dashboard) y worker | Contenedores construidos localmente; el worker corre en bucle cada 30 min |
| Base de datos | PostgreSQL 16 en contenedor, en red interna, con usuario de privilegios mínimos |
| Secretos | `.env` generado al azar por el instalador (permisos 600) |
| HTTPS | Caddy: certificado interno para uso por IP en red local, o Let's Encrypt con dominio propio |
| Persistencia | Todo vuelve solo después de reiniciar; los datos quedan en volúmenes de Docker |
| Administración | Comando `paywen-server`: estado, credenciales, comando para agentes, logs, worker, respaldo y restauración, actualización |

| Paquete | Qué contiene |
|---|---|
| `paywen-server.zip` | El servidor completo: `install-server.sh`, la app y los agentes para repartir |
| `paywen-agent.zip` | Agente de Linux |
| `paywen-agent-windows.zip` | Agente de Windows |

Las guías **Instalar el servidor**, **Instalar el agente de Linux** e **Instalar el agente de Windows** tienen el paso a paso.

---

## 9. Limitaciones y trabajo futuro

- **Windows parcial:** los programas y parches KB de Windows se muestran como inventario, pero no se cruzan: OSV no tiene datos de Windows. Cruzarlos requiere los boletines de Microsoft (MSRC) y NVD por CPE. Las librerías que encuentra Trivy en Windows sí se cruzan.
- **Exposición heurística:** se deduce del nombre del proceso, no de un escaneo de red.
- **Ruido en OTX:** algunos pulses son listas automáticas que republican CVEs, no campañas dirigidas. La relación es "un pulse menciona un CVE de tu inventario", no "te están atacando".
- **Volumen del kernel:** el kernel de Linux acumula miles de CVEs, la mayoría de prioridad baja. Los filtros y la priorización los dejan al final, pero inflan el total.
- **Puntaje que se satura:** un servidor muy vulnerable llega rápido al tope de 100. Con muchos hosts convendría una escala logarítmica; para comparar servidores, conviene mirar las críticas y los KEV.
- **El histórico parte el día de la instalación:** no hay datos de días anteriores. Para una demo se pueden generar datos de ejemplo, que quedan marcados como tales (`python -m paywen.demo`).
- **Estado del agente por tiempo:** el agente no mantiene una conexión abierta; el estado depende de cuánto hace que llegó el último inventario. Si un agente usa un intervalo de 6 h, conviene subir los umbrales (`STATUS_WARN_HOURS`, `STATUS_OFFLINE_HOURS`) o bajar su intervalo a 1 h.
- **Un solo usuario de dashboard:** sin roles ni SSO.
- **Mejoras posibles:** alertas por correo o Slack cuando aparece un CVE en KEV o un agente deja de reportar, tickets automáticos, roles y SSO, y cruce de vulnerabilidades de Windows (MSRC).

---

## 10. Glosario

| Término | Significado |
|---|---|
| **CVE** | Identificador público de una vulnerabilidad (por ejemplo, CVE-2021-44228) |
| **CVSS** | Puntaje de gravedad teórica, de 0 a 10 |
| **EPSS** | Probabilidad de explotación en los próximos 30 días, de 0 a 100 % |
| **KEV** | *Known Exploited Vulnerabilities*: catálogo de CISA con vulnerabilidades explotadas en el mundo real |
| **SBOM** | *Software Bill of Materials*: inventario del software instalado |
| **CycloneDX** | Formato estándar de SBOM (el que genera Trivy) |
| **purl** | *Package URL*: identificador estándar de un paquete (`pkg:pypi/django@3.2.0`) |
| **OSV** | *Open Source Vulnerabilities*: formato y base de datos abierta de vulnerabilidades |
| **USN** | *Ubuntu Security Notice*: aviso de seguridad de Ubuntu |
| **Pulse** | En OTX, un reporte de la comunidad con indicadores de una amenaza |
| **Paquete fuente** | Paquete del que se compilan uno o más paquetes binarios (`curl` → `curl`, `libcurl4t64`) |
