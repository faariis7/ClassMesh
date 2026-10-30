$ErrorActionPreference = 'Stop'
if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'Registry value-kind regression requires Windows'
}
. (Join-Path (Join-Path $PSScriptRoot '..') 'phase13-vc-runtime.ps1')
$keyName = "Software\ClassMeshPhase13RuntimeProbe-$PID"
$key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($keyName)
try {
    $key.SetValue('Installed', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
    $key.SetValue('Version', 'v14.44.35207.00', [Microsoft.Win32.RegistryValueKind]::String)
    if ((Read-VcRuntimeRecord $key).ToString() -ne '14.44.35207.0') { throw 'valid Registry record rejected' }
    $key.SetValue('Installed', '1', [Microsoft.Win32.RegistryValueKind]::String)
    $rejected = $false
    try { $null = Read-VcRuntimeRecord $key } catch { $rejected = $true }
    if (-not $rejected) { throw 'string Installed value was accepted' }
    $key.SetValue('Installed', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
    $key.SetValue('Version', 1444, [Microsoft.Win32.RegistryValueKind]::DWord)
    $rejected = $false
    try { $null = Read-VcRuntimeRecord $key } catch { $rejected = $true }
    if (-not $rejected) { throw 'DWORD Version value was accepted' }
    $key.SetValue('Installed', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
    if ($null -ne (Read-VcRuntimeRecord $key)) { throw 'uninstalled runtime was accepted' }
} finally {
    $key.Dispose()
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($keyName, $false)
}
Write-Host 'phase13_vc_runtime_registry_tests=pass'
