# Novedades

Todas las versiones de Paywen Scan. El número de versión aparece en el pie de cada página y en `/healthz`.

## v1.2.0 — noviembre 2026

### Nuevo

- **Agente de Windows 1.0.0** (`paywen-agent-windows.zip`), basado en el prototipo del equipo. Envía:
    - sistema operativo, compilación y revisión;
    - programas instalados (registro, 64 y 32 bits, sin componentes internos ni actualizaciones de otros programas);
    - parches KB;
    - puertos TCP y UDP con su proceso;
    - opcional, librerías de aplicaciones con Trivy 0.69.3, descargado y verificado por SHA-256.
- **El servidor acepta el inventario de Windows:** los programas y KB (`pkg:generic`) se guardan como *solo inventario* y se muestran en la nueva sección **Software instalado** del detalle del host. Las librerías de Trivy se cruzan con OSV, KEV, EPSS y OTX como en Linux.
- La respuesta de la ingesta avisa cuántos componentes quedaron como solo inventario, y el agente de Windows lo muestra al enviar.
- `paywen-server agent-command` también muestra el comando para Windows.
- Agente de Windows 1.0.1: los avisos del servidor se muestran con acentos correctos en Windows PowerShell 5.1.
- La exposición reconoce procesos de Windows (`w3wp`, `dotnet`, `javaw`, `pythonw`).

### Correcciones

- **El agente de Windows enviaba un solo puerto:** el prototipo deduplicaba con `Sort-Object -Unique` sobre diccionarios, que los colapsa en uno. Ahora envía todos.
- **El agente de Windows enviaba 0 componentes útiles:** el servidor descartaba los programas porque no traen un purl cruzable. Ahora se guardan como inventario.
- **Inventario por ecosistema:** el conteo de componentes ya no se infla con la cantidad de hallazgos.
- **Resumen:** *Campañas recientes* tiene altura máxima con desplazamiento, así *Paquetes más vulnerables* ya no queda con un espacio en blanco.

### Documentación

- Guías genéricas, sin datos de ninguna instalación en particular, y centradas en la instalación con Docker.
- Nueva guía **Instalar el agente de Windows**.

## v1.1.0 — noviembre 2026

Mejoras a partir de la retroalimentación del curso: histórico, gráficos, estado de los agentes, más filtros, íconos y documentación dentro de la app.

### Nuevo

- **Histórico** (menú *Histórico*): una foto diaria por servidor con la cantidad de hallazgos por prioridad, KEV, ransomware, puntaje y vulnerabilidades nuevas/resueltas. Se ve consolidado o por servidor, en períodos de 7, 30 o 90 días, con gráficos y la tabla de datos.
- **Gráficos** en el resumen y en cada servidor:
    - evolución de los últimos 30 días por prioridad, con la variación de 7 días;
    - distribución por prioridad (dona);
    - paquetes más vulnerables (CVEs críticos y altos).
    - Todos se generan en el servidor como SVG, sin JavaScript, y muestran el detalle al pasar el mouse.
- **Vulnerabilidades nuevas y resueltas:** se registra cuándo aparece cada vulnerabilidad en un servidor y cuándo deja de aparecer. Lo que un servidor ya tenía en su primer cruce es la línea base y no cuenta como "nueva".
- **Estado de los agentes:** verde *En línea* (< 2 h desde el último inventario), naranjo *Atrasado* (2–6 h) y rojo *Sin reportar* (6 h o más).
    - Los umbrales se configuran con `STATUS_WARN_HOURS` y `STATUS_OFFLINE_HOURS`.
    - Si el servidor de Paywen estuvo apagado, el atraso se cuenta desde que volvió a estar disponible.
- **Página Servidores:** lista con estado, sistema, kernel, IP, puertos, componentes y hallazgos. Se filtra por sistema operativo, estado o nombre/IP.
- **Más filtros en Hallazgos:**
    - servidor, sistema operativo, puerto expuesto y ecosistema (Ubuntu, Maven, PyPI, npm…);
    - con ransomware, EPSS mínimo (1 %, 10 %, 50 %) y CVSS mínimo (7, 9);
    - nuevas en las últimas 24 h, 7 o 30 días.
- **Puertos por hallazgo:** la columna *Expuesto* muestra por qué puerto queda expuesto cada paquete. El CSV incluye la columna `puertos`.
- **Documentación dentro de la app** (menú *Docs*): descripción general con diagrama de arquitectura, guías de instalación del servidor y del agente, y esta página de novedades.
- **Íconos** de [Lucide](https://lucide.dev) (licencia ISC) en el menú, los indicadores, los filtros y las tablas.
- **Cerrar sesión** (ícono a la derecha del menú).
- **Datos de ejemplo para el histórico** (opcional, para demos): `python -m paywen.demo --days 30` genera fotos simuladas hacia atrás, sin pisar las reales; `python -m paywen.demo --clear` las borra. El dashboard avisa cuando las muestra.

### Cambios

- Los puertos que solo escuchan en `127.0.0.1` / `::1` ya **no** cuentan como expuestos. Así lo decía la documentación, pero el worker los consideraba.
- Rediseño visual del dashboard: tarjetas con íconos, paneles más limpios y una paleta de prioridades revisada para daltonismo. La prioridad Baja pasa de gris a verde azulado.

### Base de datos

- Tablas nuevas `host_snapshots` y `vuln_history`, y columna `findings.exposed_ports`. Se crean solas al arrancar la versión nueva, sin pasos manuales ni pérdida de datos.

## v1.0.0 — octubre 2026

Primera versión.

- **Agente** para Linux: Trivy (SBOM CycloneDX) + `ss`, con un timer de systemd.
- **API de ingesta** con token, y **worker** que cruza con OSV.dev, CISA KEV, FIRST EPSS y AlienVault OTX.
- **Priorización:**
    - KEV → Crítica; EPSS ≥ 10 % → Alta; el resto por CVSS;
    - +1 nivel si el paquete está expuesto.
    - Puntaje de riesgo por host.
- **Dashboard** con resumen, hallazgos con filtros, detalle de host, campañas y exportación a CSV.
- **Instalación** del servidor con Docker y un solo script.
