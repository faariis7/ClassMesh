$ErrorActionPreference = 'Stop'
. (Join-Path (Join-Path $PSScriptRoot '..') 'phase11f4-teacher-ui-smoke.ps1') -Mode Help | Out-Null

function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $threw = $false
    try { & $Action } catch { $threw = $true }
    if (-not $threw) { throw $Message }
}

$toolset = Parse-VcVersion '14.44.35207'
$runtime = Parse-VcVersion 'v14.51.36247.00'
if ($toolset.ToString() -ne '14.44.35207.0') { throw 'toolset version was not normalized' }
Assert-RuntimeSatisfiesToolset $toolset $runtime
Assert-RuntimeSatisfiesToolset $toolset (Parse-VcVersion '14.44.35207.0')
Assert-Throws { Assert-RuntimeSatisfiesToolset $toolset (Parse-VcVersion '14.44.35206.9') } 'older runtime passed'
Assert-Throws { Assert-RuntimeSatisfiesToolset $toolset $null } 'missing runtime passed'
Assert-X64CompatibleArchitecture ([System.Runtime.InteropServices.Architecture]::X64)
Assert-X64CompatibleArchitecture ([System.Runtime.InteropServices.Architecture]::Arm64)
Assert-Throws { Assert-X64CompatibleArchitecture ([System.Runtime.InteropServices.Architecture]::X86) } 'x86 Windows architecture passed'
foreach ($invalid in @('', '14.44', '14.44.x', '15.0.0.0', '14.44.35207.0.1', '14.44.35207-beta')) {
    Assert-Throws { Parse-VcVersion $invalid | Out-Null } "invalid version passed: $invalid"
}
Write-Host 'phase13_vc_runtime_preflight_tests=pass'
