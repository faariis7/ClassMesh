param([Parameter(Mandatory = $true)][string]$BundleDir, [string]$SignerPath, [string]$VerifierPath)

$ErrorActionPreference = 'Stop'
if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { throw 'Windows required' }
$signer = if ($SignerPath) { $SignerPath } else { Join-Path (Join-Path $PSScriptRoot '..') 'phase13-sign-release.ps1' }
$verifier = if ($VerifierPath) { $VerifierPath } else { Join-Path (Join-Path $PSScriptRoot '..') 'phase13-release-manifest.ps1' }
$temp = Join-Path ([System.IO.Path]::GetTempPath()) "ClassMesh-release-signing-$PID"
$cert = $null
try {
    New-Item -ItemType Directory -Path $temp -ErrorAction Stop | Out-Null
    foreach ($name in @('classmesh-service.exe', 'classmesh-worker.exe', 'service-worker-bundle-index.json',
        'phase13-service-worker-bundle.ps1', 'phase13-vc-runtime.ps1', 'PHASE13_SERVICE_WORKER_PREREQUISITES.md')) {
        Copy-Item -LiteralPath (Join-Path $BundleDir $name) -Destination $temp
    }
    $cert = New-SelfSignedCertificate -Subject "CN=ClassMesh release signer test $PID" -Type CodeSigningCert -CertStoreLocation 'Cert:\CurrentUser\My'
    $rejected = $false
    try { & $signer -BundleDir $temp -ReleaseSequence 0 -SignerThumbprint $cert.Thumbprint | Out-Null } catch { $rejected = $true }
    if (-not $rejected -or (Test-Path (Join-Path $temp 'release-manifest.p7s'))) { throw 'zero release sequence accepted' }
    Add-Content -LiteralPath (Join-Path $temp 'classmesh-worker.exe') -Value 'tamper'
    $rejected = $false
    try { & $signer -BundleDir $temp -ReleaseSequence 2 -SignerThumbprint $cert.Thumbprint | Out-Null } catch { $rejected = $true }
    if (-not $rejected -or (Test-Path (Join-Path $temp 'release-manifest.p7s'))) { throw 'corrupt bundle was signed' }
    Copy-Item -LiteralPath (Join-Path $BundleDir 'classmesh-worker.exe') -Destination $temp -Force
    $orphan = Join-Path $temp 'release-manifest.p7s'
    [System.IO.File]::WriteAllBytes($orphan, [byte[]](1, 2, 3))
    $rejected = $false
    try { & $signer -BundleDir $temp -ReleaseSequence 2 -SignerThumbprint $cert.Thumbprint | Out-Null } catch { $rejected = $true }
    if (-not $rejected -or (Test-Path (Join-Path $temp 'release-manifest.json'))) { throw 'orphan signature was adopted' }
    Remove-Item -LiteralPath $orphan -ErrorAction Stop
    & $signer -BundleDir $temp -ReleaseSequence 2 -SignerThumbprint $cert.Thumbprint | Out-Null
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $pin = ([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    & $verifier -Mode Verify -BundleDir $temp -TrustedSignerSha256 $pin | Out-Null
    $rejected = $false
    try { & $signer -BundleDir $temp -ReleaseSequence 3 -SignerThumbprint $cert.Thumbprint | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'existing signed release was overwritten' }
    Write-Host 'phase13_release_signing_tests=pass'
} finally {
    if ($null -ne $cert) { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction Stop }
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction Stop
}
