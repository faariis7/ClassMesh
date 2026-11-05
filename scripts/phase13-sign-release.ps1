[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BundleDir,
    [Parameter(Mandatory = $true)][long]$ReleaseSequence,
    [Parameter(Mandatory = $true)][string]$SignerThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'phase13-release-manifest.ps1') -Mode Help -BundleDir $BundleDir 6>$null | Out-Null

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { throw 'Windows required' }
if ($ReleaseSequence -le 0 -or $SignerThumbprint -cnotmatch '^[0-9a-fA-F]{40}$') {
    throw 'A positive release sequence and certificate thumbprint are required'
}
$cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$SignerThumbprint" -ErrorAction Stop
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($cert)
try {
    if (-not $cert.HasPrivateKey -or $null -eq $rsa -or $rsa.KeySize -lt 2048 -or
        $cert.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow -or
        $cert.NotAfter.ToUniversalTime() -lt [DateTime]::UtcNow) {
        throw 'Release signer requires a current RSA-2048+ certificate with an accessible private key'
    }
} finally { if ($null -ne $rsa) { $rsa.Dispose() } }
$codeSigning = $false
foreach ($extension in $cert.Extensions) {
    if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
        foreach ($usage in $extension.EnhancedKeyUsages) {
            if ($usage.Value -ceq '1.3.6.1.5.5.7.3.3') { $codeSigning = $true }
        }
    }
}
if (-not $codeSigning) { throw 'Release signer requires code-signing certificate purpose' }

$manifestPath = Join-Path $BundleDir 'release-manifest.json'
$signaturePath = Join-Path $BundleDir 'release-manifest.p7s'
if ((Test-Path -LiteralPath $manifestPath) -or (Test-Path -LiteralPath $signaturePath)) {
    throw 'Release manifest or signature already exists; refusing replacement'
}
& (Join-Path $PSScriptRoot 'phase13-service-worker-bundle.ps1') -Mode ValidateBundle -BundleDir $BundleDir 6>$null | Out-Null
$files = @()
foreach ($name in $RequiredFiles) {
    $bytes = Read-BoundedExclusiveFile -Path (Join-Path $BundleDir $name) -Maximum $MaxPayloadBytes
    $files += [ordered]@{ path = $name; bytes = [int64]$bytes.Length; sha256 = Get-Sha256Hex -Bytes $bytes }
}
$json = [ordered]@{
    schema_version = 1
    target = 'windows-x64'
    release_sequence = $ReleaseSequence
    files = $files
} | ConvertTo-Json -Depth 5
$manifest = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
if ($manifest.Length -gt $MaxManifestBytes) { throw 'Release manifest exceeds size limit' }
try { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
catch { Add-Type -AssemblyName System.Security -ErrorAction Stop }
$cms = [System.Security.Cryptography.Pkcs.SignedCms]::new(
    [System.Security.Cryptography.Pkcs.ContentInfo]::new($manifest), $true)
$signer = [System.Security.Cryptography.Pkcs.CmsSigner]::new($cert)
$signer.DigestAlgorithm = [System.Security.Cryptography.Oid]::new('2.16.840.1.101.3.4.2.1')
$cms.ComputeSignature($signer)
$signature = $cms.Encode()
if ($signature.Length -gt $MaxSignatureBytes) { throw 'Release signature exceeds size limit' }

function Write-CreateOnly {
    param([string]$Path, [byte[]]$Bytes)
    $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
}

# A crash between these creates leaves an orphan that verification rejects.
# The manifest appears last, after its detached signature was flushed.
Write-CreateOnly -Path $signaturePath -Bytes $signature
Write-CreateOnly -Path $manifestPath -Bytes $manifest
Write-Host "release_manifest_signed=true"
Write-Host "release_sequence=$ReleaseSequence"
Write-Host "signer_certificate_sha256=$(Get-Sha256Hex -Bytes $cert.RawData)"
