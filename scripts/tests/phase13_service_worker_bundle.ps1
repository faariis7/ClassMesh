$ErrorActionPreference = 'Stop'
. (Join-Path (Join-Path $PSScriptRoot '..') 'phase13-service-worker-bundle.ps1') -Mode Help | Out-Null

$index = [pscustomobject]@{ runtime_prerequisites = @(
    [pscustomobject]@{ path = 'classmesh-service.exe'; minimum_vc_runtime_version = '14.44.35207.0' },
    [pscustomobject]@{ path = 'classmesh-worker.exe'; minimum_vc_runtime_version = '14.44.35207.0' }
) }
if ((Read-RuntimePrerequisites -Index $index).Count -ne 2) { throw 'per-executable prerequisites were lost' }
$index.runtime_prerequisites = @($index.runtime_prerequisites[0])
$rejected = $false
try { $null = Read-RuntimePrerequisites -Index $index } catch { $rejected = $true }
if (-not $rejected) { throw 'missing Worker prerequisite was accepted' }

$fixture = Join-Path ([System.IO.Path]::GetTempPath()) "classmesh-phase13-pe-$PID.bin"
try {
    $bytes = [byte[]]::new(128)
    $bytes[0] = 0x4d; $bytes[1] = 0x5a
    $bytes[0x3c] = 64
    $bytes[64] = 0x50; $bytes[65] = 0x45
    $bytes[68] = 0x64; $bytes[69] = 0x86
    [System.IO.File]::WriteAllBytes($fixture, $bytes)
    Assert-X64Pe -Path $fixture
    $bytes[69] = 0x01
    [System.IO.File]::WriteAllBytes($fixture, $bytes)
    try { Assert-X64Pe -Path $fixture; throw 'x86 PE was accepted' }
    catch { if ($_.Exception.Message -eq 'x86 PE was accepted') { throw } }
    $bytes[64] = 0
    [System.IO.File]::WriteAllBytes($fixture, $bytes)
    try { Assert-X64Pe -Path $fixture; throw 'bad PE signature was accepted' }
    catch { if ($_.Exception.Message -eq 'bad PE signature was accepted') { throw } }
} finally { Remove-Item -LiteralPath $fixture -ErrorAction SilentlyContinue }
Write-Host 'phase13_service_worker_bundle_tests=pass'
