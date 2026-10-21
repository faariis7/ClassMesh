# Native Windows test-first regression for Phase 10G physical evidence paths.
# All test directories are disposable; this does NOT provide physical evidence.
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$helper = Join-Path $PSScriptRoot "phase10g-adaptive.ps1"
$root = Join-Path ([System.IO.Path]::GetTempPath()) ("ClassMesh-Phase10G-ID-" + [guid]::NewGuid().ToString("N"))
$good = @("student-01", "student-02", "student-03", "student-04", "student-05")

function Assert-InitRejects {
    param([string[]]$Ids, [string]$CaseName)
    $caseDir = Join-Path $root $CaseName
    $rejected = $false
    try {
        & $helper -Mode Init -ReceiverCount 5 -ReceiverId $Ids -ResultsDir $caseDir | Out-Null
    } catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "Unsafe Phase 10G receiver identifier accepted by Init: $CaseName"
    }
}

try {
    [void](New-Item -Path $root -ItemType Directory -Force)
    $badIds = @(
        @("..", "student-02", "student-03", "student-04", "student-05"),
        @(".", "student-02", "student-03", "student-04", "student-05"),
        @("CON", "student-02", "student-03", "student-04", "student-05"),
        @("AUX.txt", "student-02", "student-03", "student-04", "student-05"),
        @("LPT1.report", "student-02", "student-03", "student-04", "student-05"),
        @("student-01.", "student-02", "student-03", "student-04", "student-05"),
        @(" student-01", "student-02", "student-03", "student-04", "student-05"),
        @("student-01 ", "student-02", "student-03", "student-04", "student-05"),
        @("student/01", "student-02", "student-03", "student-04", "student-05"),
        @("student-01", "STUDENT-01", "student-03", "student-04", "student-05"),
        @(("x" * 65), "student-02", "student-03", "student-04", "student-05")
    )
    for ($i = 0; $i -lt $badIds.Count; $i++) {
        Assert-InitRejects -Ids $badIds[$i] -CaseName ("bad-" + $i)
    }

    # Accepted letters/digits include non-ASCII names, plus safe punctuation.
    $positiveDir = Join-Path $root "valid"
    $arabicId = ((@([char]0x0637, [char]0x0627, [char]0x0644, [char]0x0628) -join "") + "-05")
    $valid = @("student-01", "student-02", "student-03", "student-04", $arabicId)
    & $helper -Mode Init -ReceiverCount 5 -ReceiverId $valid -ResultsDir $positiveDir | Out-Null
    if (-not (Test-Path -LiteralPath (Join-Path $positiveDir "adaptive-controller-manifest.json"))) {
        throw "valid manifest missing"
    }
    Set-Content -LiteralPath (Join-Path $positiveDir "teacher.log") -Encoding UTF8 -Value "test fixture only, not physical qualification"
    foreach ($id in $valid) {
        Set-Content -LiteralPath (Join-Path (Join-Path $positiveDir "receivers") ($id + ".log")) -Encoding UTF8 -Value ("test fixture for " + $id)
    }
    & $helper -Mode ValidateEvidence -ResultsDir $positiveDir | Out-Null
    $index = Get-Content -LiteralPath (Join-Path $positiveDir "evidence-index.json") -Raw | ConvertFrom-Json
    if ($index.qualification_passed -ne $null -or $index.production_default_selected -ne $false -or
        $index.receiver_count -ne 5 -or $index.receivers.Count -ne 5) {
        throw "Evidence validator must preserve pending physical conclusions and all receiver identities"
    }
    if ((@($index.receivers | Where-Object { $_.sha256.Length -ne 64 })).Count -ne 0) {
        throw "Evidence hashes must be 64 hex digits"
    }

    # Adversarial manifests must be rejected as invalid IDs *before* any
    # filesystem reads, rather than following parent-directory identifiers.
    $manifestPath = Join-Path $positiveDir "adaptive-controller-manifest.json"
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    $manifest.receiver_ids[0] = ".."
    $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    $message = ""
    try {
        & $helper -Mode ValidateEvidence -ResultsDir $positiveDir | Out-Null
    } catch {
        $message = $_.Exception.Message
    }
    if ($message -notmatch "invalid receiver identifier") {
        throw "ValidateEvidence did not reject manifest traversal on identifier validation: $message"
    }

    Write-Host "PHASE10G_RECEIVER_ID_VALIDATION_TESTS_PASS"
} finally {
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
