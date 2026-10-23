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

    # TDD: a new Init must NEVER relabel old Teacher/receiver files as
    # evidence for a fresh test. Even a previously valid output directory
    # must not be reused without the operator choosing a new empty folder.
    $reusedDir = Join-Path $root "reused-physical-result"
    & $helper -Mode Init -ReceiverCount 5 -ReceiverId $good -ResultsDir $reusedDir | Out-Null
    $staleTeacher = Join-Path $reusedDir "teacher.log"
    Set-Content -LiteralPath $staleTeacher -Encoding UTF8 -Value "STALE TEST EVIDENCE"
    $reinitRejected = $false
    try {
        & $helper -Mode Init -ReceiverCount 5 -ReceiverId $good -ResultsDir $reusedDir | Out-Null
    } catch {
        $reinitRejected = $true
    }
    if (-not $reinitRejected) {
        throw "Phase 10G Init reused a nonempty evidence folder and mislabeled stale logs"
    }
    if ((Get-Content -LiteralPath $staleTeacher -Raw) -notmatch "STALE TEST EVIDENCE") {
        throw "Rejected Phase 10G Init must leave the existing evidence unchanged"
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

    # Regression fixtures cover bookkeeping at each required physical scale.
    # These are synthetic files and NEVER evidence of real receivers or a soak.
    foreach ($count in @(5, 10, 20, 30)) {
        $scaleDir = Join-Path $root ("scale-fixture-" + $count)
        $ids = @(1..$count | ForEach-Object { "device-{0:D2}" -f $_ })
        $duration = if ($count -eq 30) { 1800 } else { 300 }
        & $helper -Mode Init -ReceiverCount $count -ReceiverId $ids -DurationSeconds $duration -ResultsDir $scaleDir | Out-Null
        $teacher = Join-Path $scaleDir "teacher.log"
        Set-Content -LiteralPath $teacher -Value "SYNTHETIC TEST FIXTURE" -Encoding UTF8
        foreach ($id in $ids) {
            Set-Content -LiteralPath (Join-Path (Join-Path $scaleDir "receivers") ($id + ".log")) -Value ("SYNTHETIC ONLY " + $id) -Encoding UTF8
        }
        & $helper -Mode ValidateEvidence -ResultsDir $scaleDir | Out-Null
        $idx = Get-Content -LiteralPath (Join-Path $scaleDir "evidence-index.json") -Raw | ConvertFrom-Json
        $hash = (Get-FileHash -LiteralPath $teacher -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($idx.receiver_count -ne $count -or $idx.receivers.Count -ne $count -or
            $idx.duration_seconds -ne $duration -or $idx.teacher.sha256 -cne $hash -or
            $idx.qualification_passed -ne $null -or $idx.production_default_selected -ne $false) {
            throw "Synthetic scale evidence index mismatch at count $count"
        }
        foreach ($item in $idx.receivers) {
            if ($ids -cnotcontains $item.receiver_id) { throw "Unexpected receiver in evidence index" }
            $path = Join-Path (Join-Path $scaleDir "receivers") ($item.receiver_id + ".log")
            $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($item.sha256 -cne $actual -or $item.bytes -le 0) {
                throw "Incorrect synthetic receiver evidence SHA-256 or size at count $count"
            }
        }
        $last = Join-Path (Join-Path $scaleDir "receivers") ($ids[-1] + ".log")
        Remove-Item -LiteralPath $last
        $message = ""
        try { & $helper -Mode ValidateEvidence -ResultsDir $scaleDir | Out-Null } catch { $message = $_.Exception.Message }
        if ($message -notmatch "Missing receiver evidence") { throw "Missing log was not rejected at scale $count" }
        [System.IO.File]::WriteAllBytes($last, [byte[]]@())
        $message = ""
        try { & $helper -Mode ValidateEvidence -ResultsDir $scaleDir | Out-Null } catch { $message = $_.Exception.Message }
        if ($message -notmatch "Empty receiver evidence") { throw "Empty log was not rejected at scale $count" }
        Set-Content -LiteralPath $last -Value "SYNTHETIC RESTORED" -Encoding UTF8

        $manifestPath = Join-Path $scaleDir "adaptive-controller-manifest.json"
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $manifest.qualification_passed = $true
        $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
        $message = ""
        try { & $helper -Mode ValidateEvidence -ResultsDir $scaleDir | Out-Null } catch { $message = $_.Exception.Message }
        if ($message -notmatch "must remain null") { throw "Fabricated qualification was not rejected at scale $count" }
        $manifest.qualification_passed = $null
        $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
        & $helper -Mode ValidateEvidence -ResultsDir $scaleDir | Out-Null
        Write-Host ("PHASE10G_SYNTHETIC_EVIDENCE_SCALE_" + $count + "_PASS")
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
