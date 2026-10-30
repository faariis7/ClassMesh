[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Help', 'Verify')]
    [string]$Mode,
    [string]$BundleDir = '.',
    [string]$TrustedSignerSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Fixed names are part of the verifier, never selected by untrusted JSON.
$RequiredFiles = @('classmesh-service.exe', 'classmesh-worker.exe',
    'service-worker-bundle-index.json', 'phase13-service-worker-bundle.ps1',
    'phase13-vc-runtime.ps1', 'PHASE13_SERVICE_WORKER_PREREQUISITES.md')
$MaxManifestBytes = 65536
$MaxSignatureBytes = 65536
$MaxPayloadBytes = 134217728

function Read-BoundedExclusiveFile {
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][int]$Maximum)
    $stream = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
    try {
        if ($stream.Length -le 0 -or $stream.Length -gt $Maximum) { throw "Invalid release file size: $Path" }
        $bytes = [byte[]]::new([int]$stream.Length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($read -le 0) { throw "Short release file read: $Path" }
            $offset += $read
        }
        return ,$bytes
    } finally { $stream.Dispose() }
}

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try { ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Assert-SignedManifest {
    param([byte[]]$Manifest, [byte[]]$Signature, [string]$Pin)
    if ($Pin -cnotmatch '^[0-9a-fA-F]{64}$') { throw 'Trusted signer SHA-256 pin is required' }
    try { Add-Type -AssemblyName System.Security.Cryptography.Pkcs -ErrorAction Stop }
    catch { Add-Type -AssemblyName System.Security -ErrorAction Stop }
    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new(
        [System.Security.Cryptography.Pkcs.ContentInfo]::new($Manifest), $true)
    $cms.Decode($Signature)
    if (-not $cms.Detached -or $cms.SignerInfos.Count -ne 1) {
        throw 'Release manifest must have exactly one detached signer'
    }
    if ($cms.SignerInfos[0].DigestAlgorithm.Value -notin @(
        '2.16.840.1.101.3.4.2.1', '2.16.840.1.101.3.4.2.2', '2.16.840.1.101.3.4.2.3')) {
        throw 'Release manifest requires a SHA-2 signature digest'
    }
    $cms.CheckSignature($true)
    $certificate = $cms.SignerInfos[0].Certificate
    if ($null -eq $certificate -or
        (Get-Sha256Hex -Bytes $certificate.RawData) -cne $Pin.ToLowerInvariant()) {
        throw 'Release manifest signer does not match the independently trusted pin'
    }
}

function Verify-ReleaseManifest {
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        throw 'Release verification requires Windows'
    }
    $manifestBytes = Read-BoundedExclusiveFile -Path (Join-Path $BundleDir 'release-manifest.json') -Maximum $MaxManifestBytes
    $signatureBytes = Read-BoundedExclusiveFile -Path (Join-Path $BundleDir 'release-manifest.p7s') -Maximum $MaxSignatureBytes
    Assert-SignedManifest -Manifest $manifestBytes -Signature $signatureBytes -Pin $TrustedSignerSha256
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $json = $utf8.GetString($manifestBytes).TrimStart([char]0xfeff) | ConvertFrom-Json
    if (($json.schema_version -isnot [int] -and $json.schema_version -isnot [long]) -or
        $json.schema_version -ne 1 -or
        [string]$json.target -cne 'windows-x64' -or
        ($json.release_sequence -isnot [int] -and $json.release_sequence -isnot [long]) -or
        $json.release_sequence -le 0) {
        throw 'Unsupported release manifest schema, target or sequence'
    }
    $files = @($json.files)
    if ($files.Count -ne $RequiredFiles.Count) { throw 'Release manifest file count mismatch' }
    foreach ($name in $RequiredFiles) {
        $matches = @($files | Where-Object { [string]$_.path -ceq $name })
        if ($matches.Count -ne 1) { throw "Missing or duplicate release file: $name" }
        $record = $matches[0]
        if (($record.bytes -isnot [int] -and $record.bytes -isnot [long]) -or
            $record.bytes -le 0 -or $record.bytes -gt $MaxPayloadBytes -or
            [string]$record.sha256 -cnotmatch '^[0-9a-f]{64}$') {
            throw "Invalid release file evidence: $name"
        }
        $bytes = Read-BoundedExclusiveFile -Path (Join-Path $BundleDir $name) -Maximum $MaxPayloadBytes
        if ($bytes.Length -ne [long]$record.bytes -or
            (Get-Sha256Hex -Bytes $bytes) -cne [string]$record.sha256) {
            throw "Release file changed: $name"
        }
    }
    Write-Host 'release_manifest_valid=true'
    Write-Host "release_sequence=$($json.release_sequence)"
    Write-Host "trusted_signer_sha256=$($TrustedSignerSha256.ToLowerInvariant())"
}

switch ($Mode) {
    'Help' { Write-Host 'Verify a detached CMS release manifest against an independent SHA-256 certificate pin. No installation or update is performed.' }
    'Verify' { Verify-ReleaseManifest }
}
