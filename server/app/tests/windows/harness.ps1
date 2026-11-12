# Prueba del agente de Windows fuera de Windows (PowerShell 7 en Linux).
# Reemplaza los comandos que solo existen en Windows por datos de ejemplo,
# arma el inventario con las funciones reales del agente y lo guarda en -Out.
#   pwsh -File harness.ps1 -Script ../../../paywen-agent-windows/install.ps1 -Out payload.json [-Trivy trivy -ScanPath dir]
param([Parameter(Mandatory)][string]$Script, [Parameter(Mandatory)][string]$Out, [string]$Trivy, [string]$ScanPath)
$ErrorActionPreference = 'Stop'
$env:ProgramData = Join-Path ([IO.Path]::GetTempPath()) ('paywen-win-' + [guid]::NewGuid())
New-Item -ItemType Directory -Force -Path (Join-Path $env:ProgramData 'PaywenAgent') | Out-Null
. $Script

function Get-CimInstance { param([Parameter(Position = 0)][string]$ClassName)
    switch ($ClassName) {
        'Win32_OperatingSystem' { [pscustomobject]@{ Caption = 'Microsoft Windows Server 2022 Datacenter '; Version = '10.0.20348'; BuildNumber = '20348' } }
        'Win32_QuickFixEngineering' { @(
            [pscustomobject]@{ HotFixID = 'KB5034439'; InstalledOn = [datetime]'2026-10-15'; Description = 'Security Update' },
            [pscustomobject]@{ HotFixID = 'KB5041160'; InstalledOn = $null; Description = 'Update' },
            [pscustomobject]@{ HotFixID = 'KB5034439'; InstalledOn = [datetime]'2026-10-15'; Description = 'Security Update' }) }
    }
}
function Get-ItemProperty { param([Parameter(Position = 0)]$Path) [pscustomobject]@{ UBR = 2582; DisplayVersion = '21H2' } }
function Get-UninstallEntries { @(
    [pscustomobject]@{ DisplayName = 'Google Chrome'; DisplayVersion = '130.0.6723.70'; Publisher = 'Google LLC' },
    [pscustomobject]@{ DisplayName = '7-Zip 23.01 (x64)'; DisplayVersion = '23.01'; Publisher = 'Igor Pavlov' },
    [pscustomobject]@{ DisplayName = 'Notepad++ (64-bit x64)'; DisplayVersion = '8.6.2'; Publisher = 'Notepad++ Team' },
    [pscustomobject]@{ DisplayName = 'Microsoft Visual C++ 2022 X64 Runtime'; DisplayVersion = '14.38.33135'; Publisher = 'Microsoft Corporation'; SystemComponent = 1 },
    [pscustomobject]@{ DisplayName = 'Security Update for Office'; DisplayVersion = '1.0'; ParentKeyName = 'Office16' },
    [pscustomobject]@{ DisplayName = 'Amazon SSM Agent'; DisplayVersion = '3.3.40.0'; Publisher = 'Amazon Web Services' },
    [pscustomobject]@{ DisplayName = 'Google Chrome'; DisplayVersion = '130.0.6723.70'; Publisher = 'Google LLC' },
    [pscustomobject]@{ DisplayName = 'Sin versión' }) }
function Get-Process { @(
    [pscustomobject]@{ Id = 4; ProcessName = 'System' }, [pscustomobject]@{ Id = 900; ProcessName = 'svchost' },
    [pscustomobject]@{ Id = 1500; ProcessName = 'w3wp' }, [pscustomobject]@{ Id = 2100; ProcessName = 'node' }) }
function Get-NetTCPConnection { param($State, $ErrorAction) @(
    [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 80; OwningProcess = 4 },
    [pscustomobject]@{ LocalAddress = '::'; LocalPort = 80; OwningProcess = 4 },
    [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 3389; OwningProcess = 900 },
    [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 8080; OwningProcess = 2100 },
    [pscustomobject]@{ LocalAddress = '127.0.0.1'; LocalPort = 5000; OwningProcess = 1500 }) }
function Get-NetUDPEndpoint { param($ErrorAction) @(
    [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 5353; OwningProcess = 900 },
    [pscustomobject]@{ LocalAddress = '0.0.0.0'; LocalPort = 5353; OwningProcess = 900 }) }

$cfg = [pscustomobject]@{ name = 'srv-win-01'; trivy_path = $Trivy; scan_paths = @($ScanPath | Where-Object { $_ }) }
$payload = New-InventoryPayload $cfg
Write-Json $Out $payload
"programas={0} parches={1} librerias={2} puertos={3}" -f $payload.summary.applications, $payload.summary.hotfixes, $payload.summary.libraries, $payload.ports.Count
Remove-Item -Recurse -Force $env:ProgramData
