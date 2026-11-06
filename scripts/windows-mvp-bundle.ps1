[CmdletBinding()]
param(
    [ValidateSet('Help','RecordBuild','Stage','Validate')][string]$Mode,
    [string]$ExecutableName, [string]$BuildDir = 'target/release', [string]$ReceiptsDir,
    [string]$OutputDir = 'windows-mvp-output', [string]$BundleDir = '.',
    [string]$ExpectedSourceRevision, [string]$ExpectedCiRunId, [string]$ExpectedCiRunAttempt = '1',
    [string]$ExpectedIndexSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-mvp-common.ps1')

if ($Mode -eq 'Help') {
    Write-Host 'Windows MVP: CI-only RecordBuild/Stage. Validate requires the expected source SHA, run ID, attempt, and trusted index SHA256.'
    return
}
if ($Mode -eq 'Validate') {
    $expected = [pscustomobject]@{source_revision=$ExpectedSourceRevision;ci_run_id=$ExpectedCiRunId;ci_run_attempt=$ExpectedCiRunAttempt;ci_repository='faariis7/ClassMesh';ci_job='windows'}
    $handles = @(Open-MvpBundleLease $BundleDir)
    try { $null = Test-MvpBundle $BundleDir $expected $ExpectedIndexSha256 } finally { foreach ($h in $handles) { $h.Dispose() } }
    Write-Host 'mvp_bundle_valid=true'
    return
}
$repo = (Get-Item -LiteralPath (Join-Path $PSScriptRoot '..')).FullName
$context = Get-MvpCiContext $repo
if ([string]::IsNullOrWhiteSpace($ReceiptsDir)) { throw 'ReceiptsDir is required' }
if ($Mode -eq 'RecordBuild') {
    if ($ExecutableName -cnotin @(Get-MvpExecutables)) { throw 'Only the three fixed MVP executables may be recorded' }
    $evidence = Get-MvpFileEvidence (Join-Path $BuildDir $ExecutableName) $ExecutableName
    $receipt = [ordered]@{}
    foreach ($p in $context.PSObject.Properties) { $receipt[$p.Name] = $p.Value }
    foreach ($p in $evidence.PSObject.Properties) { $receipt[$p.Name] = $p.Value }
    if (-not (Test-Path -LiteralPath $ReceiptsDir)) { $null = New-Item -ItemType Directory -Path $ReceiptsDir }
    Write-MvpNewJson $receipt (Join-Path $ReceiptsDir ($ExecutableName + '.json'))
    return
}
if ($Mode -ne 'Stage') { throw 'Mode is required' }
if (Test-Path -LiteralPath $OutputDir) { throw 'MVP output directory already exists; refusing to mix builds' }
$components = @()
foreach ($name in @(Get-MvpExecutables)) {
    $receipt = Read-MvpJson (Join-Path $ReceiptsDir ($name + '.json'))
    Assert-MvpBuildContext $receipt $context
    $actual = Get-MvpFileEvidence (Join-Path $BuildDir $name) $name
    if ($receipt.path -cne $name -or $receipt.sha256 -cne $actual.sha256 -or $receipt.bytes -ne $actual.bytes) {
        throw "MVP component changed since its same-run build receipt: $name"
    }
    $components += $receipt
}
$out = (New-Item -ItemType Directory -Path $OutputDir).FullName
$bundle = (New-Item -ItemType Directory -Path (Join-Path $out 'classmesh-windows-mvp-x64')).FullName
foreach ($name in @(Get-MvpRequiredFiles)) {
    $source = if ($name -in @(Get-MvpExecutables)) { Join-Path $BuildDir $name }
        elseif ($name -like '*.md') { Join-Path (Join-Path $repo 'docs') $name }
        else { Join-Path $PSScriptRoot $name }
    Copy-Item -LiteralPath $source -Destination (Join-Path $bundle $name) -ErrorAction Stop
}
& (Join-Path $bundle 'phase11f4-teacher-ui-smoke.ps1') -Mode IndexBundle -BundleDir $bundle
& (Join-Path $bundle 'phase13-service-worker-bundle.ps1') -Mode IndexBundle -BundleDir $bundle
$files = @(@(Get-MvpRequiredFiles) + @('teacher-ui-bundle-index.json','service-worker-bundle-index.json') | ForEach-Object {
    Get-MvpFileEvidence (Join-Path $bundle $_) $_
})
$index = [ordered]@{schema_version=1;target='windows-x64';production_qualified=$false;components=$components;files=$files}
foreach ($p in $context.PSObject.Properties) { $index[$p.Name] = $p.Value }
$indexPath = Join-Path $bundle 'mvp-bundle-index.json'
Write-MvpNewJson $index $indexPath
$indexSha256 = (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash.ToLowerInvariant()
$null = Test-MvpBundle $bundle $context $indexSha256
# The existing runtime validators remain authoritative for all three binaries.
& (Join-Path $bundle 'phase11f4-teacher-ui-smoke.ps1') -Mode PreflightRuntime -BundleDir $bundle
& (Join-Path $bundle 'phase13-service-worker-bundle.ps1') -Mode PreflightRuntime -BundleDir $bundle
$zip = Join-Path $out 'classmesh-windows-mvp-x64.zip'
Compress-Archive -Path (Join-Path $bundle '*') -DestinationPath $zip -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($zip + '.sha256'), "$hash  classmesh-windows-mvp-x64.zip`n", [Text.UTF8Encoding]::new($false))
Write-Host "mvp_zip=$zip"
Write-Host "mvp_zip_sha256=$hash"
Write-Host "mvp_index_sha256=$indexSha256"
Write-Host "mvp_source_revision=$($context.source_revision)"
Write-Host "mvp_ci_run_id=$($context.ci_run_id) attempt=$($context.ci_run_attempt) job=$($context.ci_job)"
