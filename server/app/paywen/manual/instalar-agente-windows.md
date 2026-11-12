# Instalar el agente de Windows

Esta guía instala el agente de Paywen Scan en un equipo **Windows Server 2016 o superior, o Windows 10/11**, para que su inventario aparezca en el dashboard. Se hace una vez. Después el agente corre solo como una tarea programada de SYSTEM, sin que nadie inicie sesión, y vuelve a correr después de reiniciar.

Versión del agente: **1.0.1**. Archivo: `paywen-agent-windows.zip`.

## Qué hace el agente y qué envía

Cada cierto tiempo (1 h por omisión), el agente envía por HTTPS, con un token:

| Qué | De dónde lo saca | Qué hace el servidor con eso |
|---|---|---|
| Sistema operativo, versión, compilación y revisión | `Win32_OperatingSystem` y el registro | Lo muestra en el detalle del equipo |
| **Programas instalados** para todo el equipo | Claves *Uninstall* del registro, de 64 y 32 bits | Los muestra como **inventario** |
| **Parches de Windows (KB)** | `Win32_QuickFixEngineering` | Los muestra como **inventario** |
| Puertos TCP en escucha y endpoints UDP, con su proceso | `Get-NetTCPConnection`, `Get-NetUDPEndpoint` | Detecta servicios expuestos |
| *Opcional:* **librerías de aplicaciones** (NuGet, npm, PyPI, Java, Go…) | **Trivy 0.69.3** sobre las carpetas que indiques | Las **cruza con OSV, CISA KEV, EPSS y OTX**, igual que en Linux |

**No envía:** el contenido de los archivos, cuentas, contraseñas, historial ni variables de entorno.

> **Alcance:** OSV no tiene datos de vulnerabilidades de Windows ni de sus programas, así que los programas y los KB se muestran como inventario ("solo inventario"), sin hallazgos. Los hallazgos de un equipo Windows salen de las librerías que encuentra Trivy. **Cero hallazgos no significa que el equipo no tenga vulnerabilidades.** Cruzar los parches de Windows requiere los boletines de Microsoft (MSRC), que es trabajo futuro.

## Antes de empezar

| Necesitas | Detalle |
|---|---|
| Windows de 64 bits | Windows Server 2016/2019/2022/2025 o Windows 10/11 |
| Una cuenta de **administrador** | Para registrar la tarea programada |
| **Windows PowerShell 5.1 de 64 bits** | Viene con Windows. **No** uses "Windows PowerShell (x86)" |
| **Salida HTTPS (443)** hacia el servidor | No hace falta abrir puertos de entrada |
| La **URL** del servidor y el **token** de agentes | Te los entrega el administrador por un canal privado (`sudo paywen-server agent-command` en el servidor) |
| Para Trivy (opcional) | Salida a `github.com` para descargarlo, ~1 GB libre y las carpetas donde están tus aplicaciones (por ejemplo `C:\inetpub`, `C:\apps`) |

| Dato | Ejemplo |
|---|---|
| URL del servidor | `https://paywen.ejemplo.cl`, o `https://192.168.1.50` con certificado interno |
| Nombre del equipo | uno **único**, por ejemplo `srv-win-01` (letras, números, punto, guion y guion bajo) |

---

## Paso 1 — Copiar y descomprimir

Copia `paywen-agent-windows.zip` al equipo, por ejemplo por Escritorio remoto (copiar y pegar, o *Recursos locales › Unidades* y `\\tsclient\`). Descomprímelo en `C:\PaywenSetup`, de modo que quede así:

```text
C:\PaywenSetup\install.ps1
C:\PaywenSetup\LEEME.txt
```

## Paso 2 — Abrir PowerShell de 64 bits como administrador

Inicio → escribe **Windows PowerShell** → clic derecho → **Ejecutar como administrador**. Comprueba que es la versión de 64 bits:

```powershell
[Environment]::Is64BitProcess        # debe decir True
```

## Paso 3 — Instalar y hacer el primer envío

```powershell
cd C:\PaywenSetup
Unblock-File .\install.ps1

.\install.ps1 -Url "https://paywen.ejemplo.cl" -Name "srv-win-01"
```

Cuando aparezca `Token de Paywen Scan:`, pega el token (clic derecho pega en la consola) y presiona Enter. La entrada queda oculta.

**Variantes:**

```powershell
# Servidor con certificado interno (instalación por IP, sin dominio):
.\install.ps1 -Url "https://192.168.1.50" -Name "srv-win-01" -Insecure

# Con Trivy, para inventariar las librerías de tus aplicaciones (y obtener hallazgos):
.\install.ps1 -Url "https://paywen.ejemplo.cl" -Name "srv-win-01" -InstallTrivy -ScanPaths "C:\inetpub","C:\apps"

# Con otro intervalo (1 a 24 horas):
.\install.ps1 -Url "https://paywen.ejemplo.cl" -Name "srv-win-01" -IntervalHours 2
```

Si la política de ejecución bloquea el script, ejecútalo solo para ese proceso, sin cambiar la política del equipo:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\PaywenSetup\install.ps1 -Url "https://paywen.ejemplo.cl" -Name "srv-win-01"
```

El instalador hace lo siguiente:

1. Crea `C:\ProgramData\PaywenAgent`, con acceso solo para SYSTEM y Administradores.
2. Guarda el token cifrado con **DPAPI** del equipo (`token.bin`). El token no queda en el zip, en los argumentos de la tarea ni en los logs.
3. Con `-InstallTrivy`, descarga **Trivy 0.69.3** desde GitHub y **verifica su SHA-256** contra el valor fijo del script; si no coincide, no lo instala. Rechaza la 0.69.4 (comprometida).
4. Registra la tarea programada **PaywenAgent**: cada `-IntervalHours` y 15 minutos después de cada arranque, como SYSTEM.
5. Hace el primer envío y muestra cuántos componentes registró el servidor.

Resultado esperado:

```text
Instalado. Se ejecuta cada 1 h y 15 minutos después de cada arranque, como SYSTEM.
Inventario: 42 programas, 9 parches KB, 0 librerías (Trivy), 31 puertos.
Inventario aceptado (HTTP 200): el servidor registró 51 componentes.
  Aviso del servidor: 51 programas o parches se guardaron solo como inventario: …
```

## Paso 4 — Verificar

```powershell
$agent = "$env:ProgramData\PaywenAgent\agent.ps1"
& $agent -Mode Status                 # tarea, próxima ejecución, configuración y último envío
& $agent -Mode Run                    # enviar el inventario ahora
& $agent -Mode Run -CollectOnly       # solo generar el inventario, sin enviarlo
```

Para revisar exactamente qué se envió:

```powershell
$inv = Get-Content "$env:ProgramData\PaywenAgent\last-payload.json" -Raw | ConvertFrom-Json
$inv.summary                          # programas, parches y librerías
$inv.ports | Format-Table
```

En el dashboard, el equipo aparece en **Servidores**. En su detalle se ven:

- la sección **Software instalado**, con los programas y los parches KB;
- el **Inventario por ecosistema** (`Windows` y `Windows KB` marcados como *solo inventario*; `NuGet`, `npm`, etc. si usaste Trivy);
- los **Puertos en escucha**;
- los **Hallazgos** de las librerías, después de la próxima pasada del worker (máximo 30 minutos).

## Paso 5 — Comprobar la ejecución automática

```powershell
Start-ScheduledTask -TaskName "PaywenAgent"
Start-Sleep 60
& "$env:ProgramData\PaywenAgent\agent.ps1" -Mode Status     # LastTaskResult debe ser 0
```

Como prueba completa, reinicia el equipo, espera unos 20 minutos y revisa que la fecha de `last-success.json` sea posterior al arranque.

---

## Cambiar la configuración

Vuelve a ejecutar el instalador con `-Force` y los valores nuevos (pide el token otra vez). Mantén el mismo `-Name` para no crear otro equipo en el dashboard:

```powershell
C:\PaywenSetup\install.ps1 -Url "https://paywen.ejemplo.cl" -Name "srv-win-01" -IntervalHours 2 -InstallTrivy -ScanPaths "C:\apps" -Force
```

## Desinstalar

```powershell
& "$env:ProgramData\PaywenAgent\agent.ps1" -Mode Uninstall
```

Elimina la tarea, el token, la configuración y la caché de Trivy. Conserva el script y el último inventario por si hay que auditarlo; para borrar todo, elimina `C:\ProgramData\PaywenAgent`.

## Problemas comunes

| Síntoma | Qué hacer |
|---|---|
| `Ejecuta PowerShell como administrador` | Abre PowerShell con *Ejecutar como administrador* |
| `Usa Windows PowerShell de 64 bits` | Cierra la consola x86 y abre la de 64 bits |
| `El token es demasiado corto` | Pega el token completo, sin comillas ni espacios (clic derecho para pegar) |
| `Ya está instalado` | Agrega `-Force` para reemplazar la configuración |
| `HTTP 0: sin conexión` | Revisa URL, DNS, salida al 443 y certificado. Con certificado interno usa `-Insecure` |
| `HTTP 401: token incorrecto` | Pide el token de nuevo al administrador |
| `HTTP 413` | Inventario demasiado grande: reduce las carpetas de `-ScanPaths` |
| `El SHA-256 de Trivy no coincide` | La descarga se corrompió o fue alterada. No se instala; reintenta más tarde |
| `Trivy falló en …` | Revisa que la carpeta exista y que haya espacio; el resto del inventario se envía igual |
| El equipo aparece sin hallazgos | Es lo esperado si solo tiene programas y KB (*solo inventario*). Con `-InstallTrivy -ScanPaths` se cruzan las librerías |

## Archivos instalados

| Ruta (`C:\ProgramData\PaywenAgent\`) | Contenido |
|---|---|
| `agent.ps1` | el agente (también sirve para `-Mode Run`, `Status`, `Uninstall`) |
| `config.json` | URL, nombre, intervalo, carpetas de Trivy |
| `token.bin` | token cifrado con DPAPI del equipo. **No copiar a otro equipo** |
| `last-payload.json` | último inventario generado |
| `last-success.json` | fecha, código HTTP, componentes aceptados y avisos del último envío |
| `trivy\`, `trivy-cache\` | Trivy y su caché (solo con `-InstallTrivy`) |

> DPAPI con alcance de equipo protege el token frente a otros usuarios, pero no frente a un administrador local del mismo equipo.

*Basado en el prototipo 0.1.0 del agente de Windows desarrollado por el equipo.*
