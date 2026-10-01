[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Help", "Init", "ValidateEvidence")]
    [string]$Mode,

    [ValidateSet("healthy", "weak-receiver", "reconnect", "soak")]
    [string]$Scenario = "healthy",

    [int]$ReceiverCount = 0,
    [string[]]$ReceiverId = @(),
    [string]$WeakReceiverId = "",
    [string]$Strategy = "direct-unicast",
    [string]$RunId = "",
    [switch]$ApEvidenceExpected,
    [string]$ResultsDir = "phase8-wifi-results"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SupportedReceiverCounts = @(5, 10, 20, 30)

function Assert-SafeLabel {
    param(
        [string]$Name,
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$Name must not be empty"
    }

    $trimmed = $Value.Trim()
    if ($trimmed.Length -gt 64) {
        throw "$Name must be at most 64 characters"
    }
    if ($trimmed -notmatch '^[A-Za-z0-9._-]+$') {
        throw "$Name may contain only letters, numbers, dot, underscore and dash"
    }

    return $trimmed
}

function Assert-ReceiverSet {
    if ($SupportedReceiverCounts -notcontains $ReceiverCount) {
        throw "-ReceiverCount must be one of 5, 10, 20, 30"
    }

    $normalized = @($ReceiverId | ForEach-Object {
        $_ -split ','
    } | ForEach-Object {
        Assert-SafeLabel -Name "Receiver identifier" -Value $_
    })
    if ($normalized.Count -ne $ReceiverCount) {
        throw "-ReceiverId must contain exactly $ReceiverCount receiver identifiers"
    }

    $unique = @($normalized | Sort-Object -Unique)
    if ($unique.Count -ne $ReceiverCount) {
        throw "Receiver identifiers must be unique"
    }

    return $normalized
}

function Manifest-Path {
    return Join-Path $ResultsDir "wifi-qualification-manifest.json"
}

function Show-Help {
    @"
ClassMesh Phase 8 physical Wi-Fi evidence harness

This helper prepares and validates evidence collection. It never selects a transport or SFU strategy
and never marks a physical run PASS automatically.

Examples:
  .\scripts\phase8-wifi-scale.ps1 -Mode Init -Scenario healthy -ReceiverCount 5 `
    -ReceiverId student-01,student-02,student-03,student-04,student-05 `
    -Strategy direct-unicast -RunId wifi-direct-5-001

  .\scripts\phase8-wifi-scale.ps1 -Mode Init -Scenario weak-receiver -ReceiverCount 5 `
    -ReceiverId student-01,student-02,student-03,student-04,student-05 `
    -WeakReceiverId student-01 -Strategy direct-unicast -RunId wifi-direct-5-weak-001

  .\scripts\phase8-wifi-scale.ps1 -Mode ValidateEvidence -ResultsDir .\phase8-wifi-results

Expected evidence:
  <ResultsDir>\teacher.log
  <ResultsDir>\physical-observations.md
  <ResultsDir>\receivers\<receiver-id>.log
  <ResultsDir>\ap.log   (only when -ApEvidenceExpected was used)

See docs\PHASE8_WIFI_PHYSICAL_QUALIFICATION.md for physical acceptance criteria.
"@ | Write-Host
}

switch ($Mode) {
    "Help" {
        Show-Help
    }

    "Init" {
        $receivers = Assert-ReceiverSet
        $strategyLabel = Assert-SafeLabel -Name "-Strategy" -Value $Strategy
        $effectiveRunId = if ([string]::IsNullOrWhiteSpace($RunId)) {
            "wifi-$strategyLabel-$ReceiverCount-$Scenario"
        } else {
            Assert-SafeLabel -Name "-RunId" -Value $RunId
        }

        $weakReceiver = $null
        if ($Scenario -eq "weak-receiver") {
            $weakReceiver = Assert-SafeLabel -Name "-WeakReceiverId" -Value $WeakReceiverId
            if ($receivers -notcontains $weakReceiver) {
                throw "-WeakReceiverId must match one of the exact receiver identifiers"
            }
        } elseif (-not [string]::IsNullOrWhiteSpace($WeakReceiverId)) {
            throw "-WeakReceiverId is valid only for -Scenario weak-receiver"
        }

        New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $ResultsDir "receivers") -Force | Out-Null

        $manifest = [ordered]@{
            schema_version = 1
            evidence_kind = "physical-wifi"
            created_utc = (Get-Date).ToUniversalTime().ToString("o")
            run_id = $effectiveRunId
            strategy_label = $strategyLabel
            scenario = $Scenario
            receiver_count = $ReceiverCount
            receiver_ids = $receivers
            weak_receiver_id = $weakReceiver
            ap_evidence_expected = [bool]$ApEvidenceExpected
            physical_wifi = $true
            qualification_passed = $null
            strategy_selected = $null
            note = "Evidence manifest only. Physical PASS and strategy selection require reviewed evidence."
        }

        $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Manifest-Path) -Encoding utf8
        Write-Host "Initialized Phase 8 physical Wi-Fi evidence manifest: $(Manifest-Path)"
        Write-Host "physical_wifi=true"
        Write-Host "qualification_passed=undetermined"
        Write-Host "strategy_selection=undetermined"
    }

    "ValidateEvidence" {
        $manifestPath = Manifest-Path
        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw "Manifest not found: $manifestPath"
        }

        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ($manifest.schema_version -ne 1) {
            throw "Unsupported manifest schema version: $($manifest.schema_version)"
        }
        if ($manifest.evidence_kind -ne "physical-wifi" -or $manifest.physical_wifi -ne $true) {
            throw "Manifest is not physical Wi-Fi evidence"
        }
        if ($SupportedReceiverCounts -notcontains [int]$manifest.receiver_count) {
            throw "Manifest receiver_count must be one of 5, 10, 20, 30"
        }
        if ($null -eq $manifest.receiver_ids -or $manifest.receiver_ids.Count -ne $manifest.receiver_count) {
            throw "Manifest receiver_ids do not match receiver_count"
        }

        Assert-SafeLabel -Name "Manifest run_id" -Value ([string]$manifest.run_id) | Out-Null
        Assert-SafeLabel -Name "Manifest strategy_label" -Value ([string]$manifest.strategy_label) | Out-Null

        $receiverIds = @($manifest.receiver_ids | ForEach-Object {
            Assert-SafeLabel -Name "Manifest receiver identifier" -Value ([string]$_)
        })
        if (@($receiverIds | Sort-Object -Unique).Count -ne $manifest.receiver_count) {
            throw "Manifest receiver identifiers must be unique"
        }

        if ($manifest.scenario -notin @("healthy", "weak-receiver", "reconnect", "soak")) {
            throw "Manifest scenario is unsupported: $($manifest.scenario)"
        }
        if ($manifest.scenario -eq "weak-receiver") {
            $weak = Assert-SafeLabel -Name "Manifest weak_receiver_id" -Value ([string]$manifest.weak_receiver_id)
            if ($receiverIds -notcontains $weak) {
                throw "Manifest weak_receiver_id is not in the exact receiver set"
            }
        } elseif ($null -ne $manifest.weak_receiver_id -and -not [string]::IsNullOrWhiteSpace([string]$manifest.weak_receiver_id)) {
            throw "Manifest weak_receiver_id is valid only for weak-receiver scenario"
        }

        $required = @(
            (Join-Path $ResultsDir "teacher.log"),
            (Join-Path $ResultsDir "physical-observations.md")
        )
        foreach ($receiverId in $receiverIds) {
            $required += Join-Path (Join-Path $ResultsDir "receivers") "$receiverId.log"
        }
        if ([bool]$manifest.ap_evidence_expected) {
            $required += Join-Path $ResultsDir "ap.log"
        }

        $missing = @($required | Where-Object {
            -not (Test-Path -LiteralPath $_ -PathType Leaf)
        })
        if ($missing.Count -gt 0) {
            throw "Missing required evidence files: $($missing -join ', ')"
        }

        Write-Host "physical_wifi_evidence_complete=true"
        Write-Host "run_id=$($manifest.run_id)"
        Write-Host "strategy_label=$($manifest.strategy_label)"
        Write-Host "scenario=$($manifest.scenario)"
        Write-Host "receiver_count=$($manifest.receiver_count)"
        Write-Host "qualification_passed=undetermined"
        Write-Host "strategy_selection=undetermined"
        Write-Host "Evidence presence/correlation is complete. Review telemetry and physical observations before recording PASS/FAIL or selecting a strategy."
    }
}
