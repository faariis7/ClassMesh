param([Parameter(Mandatory = $true)][string]$BundleDir, [string]$VerifierPath)

$ErrorActionPreference = 'Stop'
if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { throw 'Windows required' }
try { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
catch { Add-Type -AssemblyName System.Security -ErrorAction Stop }
$verifier = if ($VerifierPath) { $VerifierPath } else { Join-Path (Join-Path $PSScriptRoot '..') 'phase13-release-manifest.ps1' }
$testDir = Join-Path ([System.IO.Path]::GetTempPath()) "ClassMesh-release-manifest-$PID"
$cert = $null
try {
    New-Item -ItemType Directory -Path $testDir -ErrorAction Stop | Out-Null
    $names = @('classmesh-service.exe', 'classmesh-worker.exe', 'service-worker-bundle-index.json',
        'phase13-service-worker-bundle.ps1', 'phase13-vc-runtime.ps1', 'PHASE13_SERVICE_WORKER_PREREQUISITES.md')
    foreach ($name in $names) { Copy-Item -LiteralPath (Join-Path $BundleDir $name) -Destination $testDir }
    $files = @($names | ForEach-Object {
        $file = Get-Item -LiteralPath (Join-Path $testDir $_)
        [ordered]@{ path = $_; bytes = [int64]$file.Length; sha256 = (Get-FileHash $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
    [ordered]@{ schema_version = 1; target = 'windows-x64'; release_sequence = 1; files = $files } |
        ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $testDir 'release-manifest.json') -Encoding utf8
    $cert = New-SelfSignedCertificate -Subject "CN=ClassMesh release manifest test $PID" -Type CodeSigningCert -CertStoreLocation 'Cert:\CurrentUser\My'
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $pin = ([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    $content = [System.IO.File]::ReadAllBytes((Join-Path $testDir 'release-manifest.json'))
    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new([System.Security.Cryptography.Pkcs.ContentInfo]::new($content), $true)
    $signer = [System.Security.Cryptography.Pkcs.CmsSigner]::new($cert)
    $signer.DigestAlgorithm = [System.Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
    $cms.ComputeSignature($signer)
    [System.IO.File]::WriteAllBytes((Join-Path $testDir 'release-manifest.p7s'), $cms.Encode())

    & $verifier -Mode Verify -BundleDir $testDir -TrustedSignerSha256 $pin | Out-Null
    $weak = [System.Security.Cryptography.Pkcs.SignedCms]::new([System.Security.Cryptography.Pkcs.ContentInfo]::new($content), $true)
    $weakSigner = [System.Security.Cryptography.Pkcs.CmsSigner]::new($cert)
    $weakSigner.DigestAlgorithm = [System.Security.Cryptography.Oid]::new('1.3.14.3.2.26')
    $weak.ComputeSignature($weakSigner)
    [System.IO.File]::WriteAllBytes((Join-Path $testDir 'release-manifest.p7s'), $weak.Encode())
    $rejected = $false
    try { & $verifier -Mode Verify -BundleDir $testDir -TrustedSignerSha256 $pin | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'SHA-1 manifest signature accepted' }
    [System.IO.File]::WriteAllBytes((Join-Path $testDir 'release-manifest.p7s'), $cms.Encode())
    $rejected = $false
    try { & $verifier -Mode Verify -BundleDir $testDir -TrustedSignerSha256 ('0' * 64) | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'wrong signer pin accepted' }
    Add-Content -LiteralPath (Join-Path $testDir 'classmesh-worker.exe') -Value 'tamper'
    $rejected = $false
    try { & $verifier -Mode Verify -BundleDir $testDir -TrustedSignerSha256 $pin | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'modified Worker accepted' }
    Copy-Item -LiteralPath (Join-Path $BundleDir 'classmesh-worker.exe') -Destination $testDir -Force
    Add-Content -LiteralPath (Join-Path $testDir 'release-manifest.json') -Value 'tamper'
    $rejected = $false
    try { & $verifier -Mode Verify -BundleDir $testDir -TrustedSignerSha256 $pin | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'modified signed manifest accepted' }
    Write-Host 'phase13_signed_release_manifest_tests=pass'
} finally {
    if ($null -ne $cert) { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction Stop }
    Remove-Item -LiteralPath $testDir -Recurse -Force -ErrorAction Stop
}
