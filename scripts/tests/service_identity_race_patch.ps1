param([Parameter(Mandatory)][string]$SourceDir, [Parameter(Mandatory)][string]$PatchDir)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Push-Location $SourceDir
try {
    $null = git symbolic-ref -q HEAD 2>$null
    if ($LASTEXITCODE -ne 1) { throw 'Detached checkout required; refusing to patch a source branch' }
    $head = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -ne 'd546360dd60c4108f91b48d51c9f3b9fbc4357a7') { throw 'Race proof requires exact isolated #716 source head' }
    if (@(git status --porcelain).Count -ne 0) { throw 'Race checkout must start clean' }
    $red = Join-Path $PatchDir '716-race-red.patch'
    $green = Join-Path $PatchDir '716-race-green.patch'
    git apply --check --unidiff-zero $red
    if ($LASTEXITCODE -ne 0) { throw 'RED patch does not apply exactly' }
    git apply --unidiff-zero $red
    if ($LASTEXITCODE -ne 0) { throw 'RED patch failed' }
    $output = @(cargo test -p classmesh-win32 --features experimental-service-peer-probe identity_evidence_race_ --lib -- --nocapture 2>&1)
    $redExit = $LASTEXITCODE
    $text = $output -join "`n"
    $output | Write-Host
    if ($redExit -eq 0 -or $text -notmatch 'IDENTITY_EVIDENCE_RACE: exited process accepted after final sample' -or $text -notmatch 'test result: FAILED\. 1 passed; 1 failed') {
        throw 'RED must be the actual owned-child observation race, not compilation/environment failure'
    }
    git apply --check --unidiff-zero $green
    if ($LASTEXITCODE -ne 0) { throw 'GREEN patch does not apply exactly' }
    git apply --unidiff-zero $green
    if ($LASTEXITCODE -ne 0) { throw 'GREEN patch failed' }
    cargo test -p classmesh-win32 --features experimental-service-peer-probe identity_evidence_race_ --lib -- --nocapture
    if ($LASTEXITCODE -ne 0) { throw 'Repaired native race tests failed' }
    cargo clippy -p classmesh-win32 --all-targets --features experimental-service-peer-probe -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Patched native prototype Clippy failed' }
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'Patched source formatting failed' }
    Write-Host 'PASS actual native RED/GREEN race proof; isolated checkout only; no PR merged or source branch modified'
} finally { Pop-Location }
