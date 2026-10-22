# Regression test for the portable Windows VM qualification bundle.
# The fixture is deliberately NONEXECUTABLE; only manifest modes are tested.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$helper = Join-Path $PSScriptRoot 'phase10-native-telemetry-smoke.ps1'
$root = Join-Path ([System.IO.Path]::GetTempPath()) ('ClassMesh-native-smoke-' + [guid]::NewGuid().ToString('N'))
$sha = '741af56a7c1a33f3167093ed447b13ef19c5c272'
function Assert-Fails {
    param([scriptblock]$Action, [string]$Case)
    $rejected = $false
    try { & $Action | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw "Phase10 native bundle failed to reject: $Case" }
}
try {
    New-Item -ItemType Directory -Path $root | Out-Null
    $exe = Join-Path $root 'classmesh-win32-native-tests.exe'
    [System.IO.File]::WriteAllBytes($exe, [byte[]]@(77,90,1,2,3,4))
    Assert-Fails { & $helper -Mode IndexBundle -BundleDir $root -SourceRevision 'unknown' } 'invalid source revision'
    & $helper -Mode IndexBundle -BundleDir $root -SourceRevision $sha | Out-Null
    & $helper -Mode ValidateBundle -BundleDir $root | Out-Null
    $bytes = [System.IO.File]::ReadAllBytes($exe)
    $bytes[2] = 255
    [System.IO.File]::WriteAllBytes($exe, $bytes)
    Assert-Fails { & $helper -Mode ValidateBundle -BundleDir $root } 'tampered binary'
    $bytes[2] = 1
    [System.IO.File]::WriteAllBytes($exe, $bytes)
    & $helper -Mode ValidateBundle -BundleDir $root | Out-Null
    $manifest = Join-Path $root 'native-smoke-index.json'
    $index = Get-Content -LiteralPath $manifest -Raw | ConvertFrom-Json
    $index.source_revision = '../forged'
    $index | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $manifest -Encoding utf8
    Assert-Fails { & $helper -Mode ValidateBundle -BundleDir $root } 'forged source revision'
    Assert-Fails { & $helper -Mode Run -BundleDir $root } 'forged bundle execution'
    Remove-Item -LiteralPath $exe -Force
    Assert-Fails { & $helper -Mode ValidateBundle -BundleDir $root } 'missing native binary'
    Write-Output 'PHASE10_NATIVE_VM_MANIFEST_NEGATIVE_TESTS_PASSED'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
