#requires -Version 5.1
<#
.SYNOPSIS
    Agente de Paywen Scan para Windows (instalador y agente en un solo archivo).

.DESCRIPTION
    Recolecta el inventario del equipo y lo envía por HTTPS a Paywen Scan:
      - sistema operativo, compilación y revisión (UBR);
      - programas instalados para todo el equipo (registro, 64 y 32 bits);
      - parches de Windows instalados (KB);
      - puertos TCP en escucha y endpoints UDP, con su proceso;
      - opcional: librerías de aplicaciones (NuGet, npm, PyPI, Java, Go…) con
        Trivy 0.69.3, en las carpetas indicadas con -ScanPaths.

    No envía contenido de archivos, cuentas, contraseñas, historial ni variables
    de entorno. Los programas y parches se muestran como inventario: OSV no
    tiene datos de vulnerabilidades de Windows. Las librerías de Trivy sí se
    cruzan con OSV, CISA KEV, EPSS y OTX como en Linux.

    Basado en el prototipo 0.1.0 del equipo (registro, DPAPI, tarea SYSTEM).

.EXAMPLE
    .\install.ps1 -Url https://paywen.ejemplo.cl -Name srv-win-01
    (pide el token de forma oculta, instala la tarea y hace el primer envío)

.EXAMPLE
    .\install.ps1 -Url https://192.168.56.10 -Name srv-win-01 -Insecure -InstallTrivy -ScanPaths 'C:\inetpub','C:\apps'

.EXAMPLE
    & "$env:ProgramData\PaywenAgent\agent.ps1" -Mode Run | Status | Uninstall
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Run', 'Status', 'Uninstall')][string]$Mode = 'Install',
    [string]$Url,
    [Security.SecureString]$Token,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$')][string]$Name = $env:COMPUTERNAME,
    [ValidateRange(1, 24)][int]$IntervalHours = 1,
    [string[]]$ScanPaths = @(),
    [switch]$InstallTrivy,
    [string]$TrivyPath,
    [switch]$Insecure,
    [switch]$Force,
    [switch]$CollectOnly
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # Invoke-WebRequest es muy lento con la barra de progreso en 5.1

$AgentVersion = '1.0.1'
$TrivyVersion = '0.69.3'                   # la 0.69.4 fue comprometida (CVE-2026-33634): no usar
$TrivyZip = "trivy_${TrivyVersion}_windows-64bit.zip"
$TrivySha256 = '74362dc711383255308230ecbeb587eb1e4e83a8d332be5b0259afac6e0c2224'
$Root = Join-Path $env:ProgramData 'PaywenAgent'
$TaskName = 'PaywenAgent'
$ConfigPath = Join-Path $Root 'config.json'
$AgentPath = Join-Path $Root 'agent.ps1'
$Utf8 = New-Object Text.UTF8Encoding($false)

function Write-Json([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 40), $Utf8)
}

function Set-PrivateDirectory {
    # Solo SYSTEM y Administradores pueden leer la carpeta (está el token).
    if (Test-Path $Root) {
        if ((Get-Item $Root).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'La carpeta de instalación no puede ser un enlace.' }
    } else { New-Item -ItemType Directory -Path $Root | Out-Null }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Root -AclObject $acl
}

# ─── Recolección ──────────────────────────────────────────────────────────────

function Get-OsInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $ubr = if ($cv -and $null -ne $cv.UBR) { ".$($cv.UBR)" } else { '' }
    $display = if ($cv -and $cv.DisplayVersion) { " ($($cv.DisplayVersion))" } else { '' }
    [ordered]@{
        id         = 'windows'
        version_id = [string]$os.Version
        name       = ([string]$os.Caption).Trim() + $display
        kernel     = "$($os.Version)$ubr"
    }
}

function Get-UninstallEntries {
    # Programas instalados para todo el equipo. No se usa Win32_Product porque
    # dispara reparaciones de MSI.
    foreach ($base in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (Test-Path $base) { Get-ItemProperty "$base\*" -ErrorAction SilentlyContinue }
    }
}

function Get-InstalledApplications {
    $apps = @(Get-UninstallEntries | Where-Object {
        $_.DisplayName -and $_.DisplayVersion -and
        $_.SystemComponent -ne 1 -and                       # componentes internos de Windows
        -not $_.ParentKeyName -and                          # actualizaciones de otro programa
        $_.ReleaseType -notin @('Update', 'Hotfix', 'Security Update', 'Update Rollup')
    })
    $seen = @{}
    foreach ($app in ($apps | Sort-Object DisplayName, DisplayVersion)) {
        $name = ([string]$app.DisplayName).Trim()
        $version = ([string]$app.DisplayVersion).Trim()
        $key = "$name|$version"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        $purl = 'pkg:generic/{0}@{1}' -f [uri]::EscapeDataString($name), [uri]::EscapeDataString($version)
        if ($app.Publisher) { $purl += '?publisher=' + [uri]::EscapeDataString(([string]$app.Publisher).Trim()) }
        [ordered]@{ type = 'application'; name = $name; version = $version; 'bom-ref' = $purl; purl = $purl }
    }
}

function Get-InstalledHotfixes {
    $seen = @{}
    foreach ($fix in @(Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue)) {
        $id = ([string]$fix.HotFixID).Trim()
        if (-not $id -or $id -eq 'File 1' -or $seen.ContainsKey($id)) { continue }
        $seen[$id] = $true
        $installed = 'instalado'
        if ($fix.InstalledOn) { try { $installed = ([datetime]$fix.InstalledOn).ToString('yyyy-MM-dd') } catch { } }
        $purl = 'pkg:generic/microsoft-hotfix/{0}@{1}' -f [uri]::EscapeDataString($id), [uri]::EscapeDataString($installed)
        if ($fix.Description) { $purl += '?publisher=' + [uri]::EscapeDataString(([string]$fix.Description).Trim()) }
        [ordered]@{ type = 'application'; name = $id; version = $installed; 'bom-ref' = $purl; purl = $purl }
    }
}

function Get-ListeningPorts {
    $processes = @{}
    Get-Process | ForEach-Object { $processes[[int]$_.Id] = ([string]$_.ProcessName).ToLowerInvariant() }
    $rows = foreach ($proto in @('tcp', 'udp')) {
        $endpoints = if ($proto -eq 'tcp') { @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue) }
                     else { @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue) }
        foreach ($ep in $endpoints) {
            $ip = [string]$ep.LocalAddress
            $address = if ($ip.Contains(':')) { "[${ip}]:$($ep.LocalPort)" } else { "${ip}:$($ep.LocalPort)" }
            $processName = $processes[[int]$ep.OwningProcess]
            # Mismo formato que `ss` en Linux, para que el servidor lo lea igual (fd=0 es solo formato).
            $processText = if ($processName) { 'users:(("{0}",pid={1},fd=0))' -f $processName, $ep.OwningProcess } else { '' }
            # [pscustomobject] y no [ordered]@{}: Sort-Object -Unique no ve las claves de un
            # diccionario y los colapsa en uno solo (por eso el prototipo enviaba un único puerto).
            [pscustomobject]@{ proto = $proto; address = $address; port = [int]$ep.LocalPort; process = $processText }
        }
    }
    @($rows | Sort-Object proto, port, address, process -Unique)
}

function Get-TrivyComponents([string]$Trivy, [string[]]$Paths) {
    # Librerías de aplicaciones con su purl (las que OSV sí conoce).
    $all = @{}
    if (-not $Trivy -or -not $Paths) { return @() }
    $cache = Join-Path $Root 'trivy-cache'
    foreach ($path in $Paths) {
        if (-not (Test-Path -LiteralPath $path)) { Write-Warning "Trivy: no existe $path (se omite)"; continue }
        $out = Join-Path $Root ('trivy-' + [guid]::NewGuid().ToString() + '.json')
        try {
            & $Trivy fs --quiet --cache-dir $cache --format cyclonedx --output $out $path 2>&1 | ForEach-Object { Write-Verbose "trivy: $_" }
            if ($LASTEXITCODE -ne 0 -or -not (Test-Path $out)) { Write-Warning "Trivy falló en $path (código $LASTEXITCODE)"; continue }
            $bom = Get-Content -LiteralPath $out -Raw -Encoding UTF8 | ConvertFrom-Json
            $stack = New-Object System.Collections.Stack
            foreach ($c in @($bom.components)) { if ($c) { $stack.Push($c) } }
            while ($stack.Count -gt 0) {
                $c = $stack.Pop()
                foreach ($child in @($c.components)) { if ($child) { $stack.Push($child) } }
                if ($c.type -eq 'library' -and $c.purl -and -not $all.ContainsKey($c.purl)) { $all[$c.purl] = $c }
            }
        } finally { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
    }
    @($all.Values)
}

function New-InventoryPayload($Config) {
    $apps = @(Get-InstalledApplications)
    $hotfixes = @(Get-InstalledHotfixes)
    $libs = @(Get-TrivyComponents -Trivy $Config.trivy_path -Paths @($Config.scan_paths))
    $now = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    [ordered]@{
        hostname     = $Config.name
        collected_at = $now
        agent        = [ordered]@{ name = 'paywen-agent-windows'; version = $AgentVersion }
        os           = Get-OsInfo
        ports        = @(Get-ListeningPorts)
        sbom         = [ordered]@{
            bomFormat    = 'CycloneDX'
            specVersion  = '1.5'
            version      = 1
            serialNumber = 'urn:uuid:' + [guid]::NewGuid().ToString()
            metadata     = [ordered]@{ timestamp = $now; tools = @([ordered]@{ name = 'paywen-agent-windows'; version = $AgentVersion }) }
            components   = @($apps + $hotfixes + $libs)
        }
        summary      = [ordered]@{ applications = $apps.Count; hotfixes = $hotfixes.Count; libraries = $libs.Count }
    }
}

# ─── Envío ────────────────────────────────────────────────────────────────────

function Send-Payload([string]$BaseUrl, [string]$PlainToken, [string]$PayloadPath, [bool]$SkipTls) {
    $params = @{
        UseBasicParsing   = $true
        Method            = 'Post'
        Uri               = $BaseUrl.TrimEnd('/') + '/api/v1/ingest'
        Headers           = @{ Authorization = "Bearer $PlainToken" }
        ContentType       = 'application/json; charset=utf-8'
        InFile            = $PayloadPath
        TimeoutSec        = 120
        MaximumRedirection = 0      # no seguir redirecciones con el token
    }
    if ($SkipTls) {
        if ($PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }
        else { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
    }
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $response = Invoke-WebRequest @params
            $body = $null
            # Se decodifica como UTF-8: Windows PowerShell 5.1 usa Latin-1 si la respuesta
            # no trae charset, y los acentos de los avisos del servidor salían mal.
            try {
                $text = if ($response.RawContentStream) { [Text.Encoding]::UTF8.GetString($response.RawContentStream.ToArray()) } else { [string]$response.Content }
                $body = $text | ConvertFrom-Json
            } catch { }
            return @{ status = [int]$response.StatusCode; body = $body }
        } catch {
            $status = 0
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if (($status -ge 300 -and $status -lt 500) -or $attempt -eq 3) {
                $hint = switch ($status) {
                    0 { 'sin conexión: revisa la URL, el DNS, el puerto 443 y el certificado (con certificado interno usa -Insecure)' }
                    401 { 'token incorrecto' }
                    413 { 'inventario demasiado grande' }
                    422 { 'el servidor rechazó el formato del inventario' }
                    default { 'revisa la URL y el estado del servidor' }
                }
                throw "No se pudo enviar el inventario (HTTP ${status}: $hint). Queda guardado en last-payload.json."
            }
            Start-Sleep -Seconds 10
        }
    }
}

function Invoke-Inventory {
    if (-not (Test-Path $ConfigPath)) { throw 'El agente no está instalado. Ejecuta install.ps1 primero.' }
    $lock = $null
    try {
        try { $lock = [IO.File]::Open((Join-Path $Root 'agent.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
        catch [IO.IOException] { Write-Host 'El agente ya se está ejecutando.'; return }
        $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        $payload = New-InventoryPayload $cfg
        $payloadPath = Join-Path $Root 'last-payload.json'
        Write-Json $payloadPath $payload
        $s = $payload.summary
        Write-Host ("Inventario: {0} programas, {1} parches KB, {2} librerías (Trivy), {3} puertos." -f $s.applications, $s.hotfixes, $s.libraries, $payload.ports.Count)
        if ($CollectOnly) { Write-Host "Solo recolección (no se envió): $payloadPath"; return }

        Add-Type -AssemblyName System.Security
        $secretBytes = [Security.Cryptography.ProtectedData]::Unprotect(
            [IO.File]::ReadAllBytes((Join-Path $Root 'token.bin')), $null,
            [Security.Cryptography.DataProtectionScope]::LocalMachine)
        try {
            $plainToken = [Text.Encoding]::UTF8.GetString($secretBytes)
            $result = Send-Payload -BaseUrl $cfg.url -PlainToken $plainToken -PayloadPath $payloadPath -SkipTls ([bool]$cfg.insecure)
        } finally {
            if ($secretBytes) { [Array]::Clear($secretBytes, 0, $secretBytes.Length) }
            $plainToken = $null
        }
        $accepted = if ($result.body) { $result.body.components } else { $null }
        Write-Json (Join-Path $Root 'last-success.json') ([ordered]@{
            sent_at = $payload.collected_at; http_status = $result.status
            components_sent = $payload.sbom.components.Count; components_accepted = $accepted
            warnings = @($result.body.warnings)
        })
        Write-Host "Inventario aceptado (HTTP $($result.status)): el servidor registró $accepted componentes."
        foreach ($w in @($result.body.warnings)) { if ($w) { Write-Host "  Aviso del servidor: $w" } }
    } finally { if ($lock) { $lock.Dispose() } }
}

# ─── Trivy (opcional) ─────────────────────────────────────────────────────────

function Install-PinnedTrivy {
    $dir = Join-Path $Root 'trivy'
    $exe = Join-Path $dir 'trivy.exe'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $zip = Join-Path $dir $TrivyZip
    $src = "https://github.com/aquasecurity/trivy/releases/download/v$TrivyVersion/$TrivyZip"
    Write-Host "Descargando Trivy $TrivyVersion…"
    Invoke-WebRequest -UseBasicParsing -Uri $src -OutFile $zip -TimeoutSec 300
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $TrivySha256) {
        Remove-Item -LiteralPath $zip -Force
        throw "El SHA-256 de Trivy no coincide (esperado $TrivySha256, recibido $hash). No se instaló."
    }
    Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force
    Remove-Item -LiteralPath $zip -Force
    if (-not (Test-Path $exe)) { throw 'No se encontró trivy.exe en el paquete descargado.' }
    Write-Host "Trivy $TrivyVersion instalado y verificado (SHA-256)."
    $exe
}

function Assert-SafeTrivy([string]$Exe) {
    if (-not (Test-Path -LiteralPath $Exe)) { throw "No existe $Exe" }
    $ver = (& $Exe --version 2>$null | Select-Object -First 1)
    if ($ver -match '0\.69\.4') { throw 'Trivy 0.69.4 fue comprometida (CVE-2026-33634). Usa -InstallTrivy para la 0.69.3.' }
    Write-Host "Trivy: $ver"
}

# Al cargarlo con ". .\install.ps1" (pruebas) solo se definen las funciones.
if ($MyInvocation.InvocationName -eq '.') { return }

# ─── Principal ────────────────────────────────────────────────────────────────

try {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw 'Ejecuta PowerShell como administrador.' }
    if (-not [Environment]::Is64BitProcess) { throw 'Usa Windows PowerShell de 64 bits (no la versión x86).' }

    switch ($Mode) {
        'Status' {
            Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State | Format-Table -AutoSize
            Get-ScheduledTaskInfo -TaskName $TaskName | Select-Object LastRunTime, LastTaskResult, NextRunTime | Format-List
            if (Test-Path $ConfigPath) { Write-Host 'Configuración:'; Get-Content $ConfigPath }
            $ok = Join-Path $Root 'last-success.json'
            if (Test-Path $ok) { Write-Host 'Último envío aceptado:'; Get-Content $ok }
            exit 0
        }
        'Uninstall' {
            $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            if ($task) { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
            foreach ($file in @('token.bin', 'config.json')) { Remove-Item (Join-Path $Root $file) -Force -ErrorAction SilentlyContinue }
            Remove-Item (Join-Path $Root 'trivy-cache') -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Tarea, token y configuración eliminados. El script y el último inventario quedan en $Root (bórralo si ya no lo necesitas)."
            exit 0
        }
        'Run' { Invoke-Inventory; exit 0 }
    }

    # Install
    if (-not $Url) { throw 'Falta -Url (por ejemplo: -Url https://paywen.ejemplo.cl o -Url https://192.168.1.50).' }
    $uri = $null
    if (-not [uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment) {
        throw 'La URL debe ser HTTPS, sin usuario, parámetros ni fragmento.'
    }
    $Url = $Url.TrimEnd('/') -replace '/api/v1/ingest$', ''
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (((Test-Path $ConfigPath) -or $existing) -and -not $Force) { throw 'Ya está instalado. Usa -Force para reemplazar la configuración.' }
    if ($existing -and $existing.State -eq 'Running') { throw 'Espera a que termine la ejecución actual del agente.' }
    if (-not $Token) { $Token = Read-Host 'Token de Paywen Scan' -AsSecureString }
    if ($Token.Length -lt 16) { throw 'El token es demasiado corto (¿se pegó completo?).' }
    foreach ($p in $ScanPaths) { if (-not (Test-Path -LiteralPath $p)) { Write-Warning "La carpeta $p no existe todavía; Trivy la omitirá hasta que exista." } }

    Set-PrivateDirectory
    Add-Type -AssemblyName System.Security
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Token)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr))
        $encrypted = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
        [IO.File]::WriteAllBytes((Join-Path $Root 'token.bin'), $encrypted)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    }

    $trivy = $null
    if ($InstallTrivy) { $trivy = Install-PinnedTrivy }
    elseif ($TrivyPath) { $trivy = (Resolve-Path -LiteralPath $TrivyPath).Path }
    if ($trivy) { Assert-SafeTrivy $trivy }
    if ($ScanPaths -and -not $trivy) { Write-Warning '-ScanPaths sin Trivy: agrega -InstallTrivy (o -TrivyPath) para inventariar librerías.' }
    if ($Insecure) { Write-Warning '-Insecure: no se valida el certificado del servidor. Úsalo solo con el certificado interno del servidor portable en una red de confianza.' }

    if ([IO.Path]::GetFullPath($PSCommandPath) -ne [IO.Path]::GetFullPath($AgentPath)) { Copy-Item -LiteralPath $PSCommandPath -Destination $AgentPath -Force }
    Write-Json $ConfigPath ([ordered]@{
        url = $Url; name = $Name; interval_hours = $IntervalHours; insecure = [bool]$Insecure
        trivy_path = $trivy; scan_paths = @($ScanPaths); agent_version = $AgentVersion
    })

    $exe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action = New-ScheduledTaskAction -Execute $exe -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Mode Run' -f $AgentPath)
    $periodic = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours($IntervalHours) -RepetitionInterval (New-TimeSpan -Hours $IntervalHours)
    $startup = New-ScheduledTaskTrigger -AtStartup
    $startup.Delay = 'PT15M'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $limit = if ($trivy) { New-TimeSpan -Hours 1 } else { New-TimeSpan -Minutes 30 }
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit $limit
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($periodic, $startup) -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host "Instalado. Se ejecuta cada $IntervalHours h y 15 minutos después de cada arranque, como SYSTEM."

    Invoke-Inventory
} catch {
    # No se registran cuerpos HTTP ni encabezados (podrían tener el token).
    Write-Error $_.Exception.Message -ErrorAction Continue
    exit 1
}
