#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../mvp-service-scm-guarded.ps1') -Raw
$required = @(
    '[string]$ExpectedWorkerSha256',
    'classmesh-worker.exe',
    'Assert-ProtectedFile $workerPath $ExpectedWorkerSha256'
)
foreach ($needle in $required) {
    if (-not $source.Contains($needle)) {
        throw "FAIL: installed Service can spawn unpinned Worker executable: missing $needle"
    }
}
$createAt = $source.IndexOf('& sc.exe create $serviceName')
$startAt = $source.IndexOf('Start-Service -Name $serviceName')
$workerChecks = @([regex]::Matches($source,'Assert-ProtectedFile \$workerPath \$ExpectedWorkerSha256') | ForEach-Object { $_.Index })
if ($createAt -lt 0 -or $startAt -le $createAt -or $workerChecks.Count -lt 3 -or
    $workerChecks[0] -ge $createAt -or
    -not @($workerChecks | Where-Object { $_ -gt $createAt -and $_ -lt $startAt }).Count) {
    throw 'FAIL: Worker executable must be pinned before Service creation and before SCM start'
}
$hashGuard = $source.IndexOf('ExpectedWorkerSha256 -cnotmatch')
if ($hashGuard -lt 0) { throw 'FAIL: Worker SHA-256 pin is not mandatory before any Service installation' }
'PASS: protected SCM release requires same-directory Worker SHA256, signer and ACL pre-start'
