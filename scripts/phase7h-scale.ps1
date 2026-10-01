[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Help", "Init", "ValidateEvidence")]
    [string]$Mode,

    [int]$ReceiverCount = 0,
    [string[]]$ReceiverId = @(),
    [string]$ResultsDir = "phase7h-results",
    [string]$Scenario = "wired-multicast"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-ReceiverSet {
    if ($ReceiverCount -lt 2) {
        throw "-ReceiverCount must be at least 2"
    }
    if ($ReceiverId.Count -ne $ReceiverCount) {
        throw "-ReceiverId must contain exactly $ReceiverCount unique receiver identifiers"
    }

    $normalized = @($ReceiverId | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_)) {
            throw "Receiver identifiers must not be empty"
        }
        $trimmed = $_.Trim()
        if ($trimmed.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
            throw "Receiver identifiers must be valid file-name components"
        }
        $trimmed
    })

    $unique = @($normalized | Sort-Object -Unique)
    if ($unique.Count -ne $ReceiverCount) {
        throw "Receiver identifiers must be unique"
    }

    return $normalized
}

function Manifest-Path {
    return Join-Path $ResultsDir "qualification-manifest.json"
}

function Show-Help {
    @"
ClassMesh Phase 7H classroom-scale qualification harness

This helper prepares and validates evidence collection only. It never marks Phase 7H PASS.

Examples:
  .\scripts\phase7h-scale.ps1 -Mode Init -ReceiverCount 5 -ReceiverId student-01,student-02,student-03,student-04,student-05

  .\scripts\phase7h-scale.ps1 -Mode ValidateEvidence -ResultsDir .\phase7h-results

Expected receiver evidence files:
  <ResultsDir>\receivers\<receiver-id>.log

The runbook and human/telemetry acceptance criteria are in:
  docs\PHASE7_SCALE_QUALIFICATION.md
"@ | Write-Host
}

switch ($Mode) {
    "Help" {
        Show-Help
    }

    "Init" {
        $receivers = Assert-ReceiverSet
        if ([string]::IsNullOrWhiteSpace($Scenario)) {
            throw "-Scenario must not be empty"
        }

        New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $ResultsDir "receivers") -Force | Out-Null

        $manifest = [ordered]@{
            schema_version = 1
            created_utc = (Get-Date).ToUniversalTime().ToString("o")
            scenario = $Scenario.Trim()
            receiver_count = $ReceiverCount
            receiver_ids = $receivers
            qualification_passed = $null
            note = "Evidence manifest only. Physical PASS requires the Phase 7H runbook and reviewed results."
        }

        $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Manifest-Path) -Encoding utf8
        Write-Host "Initialized Phase 7H evidence manifest: $(Manifest-Path)"
        Write-Host "qualification_passed=undetermined"
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
        if ($manifest.receiver_count -lt 2) {
            throw "Manifest receiver_count must be at least 2"
        }
        if ($null -eq $manifest.receiver_ids -or $manifest.receiver_ids.Count -ne $manifest.receiver_count) {
            throw "Manifest receiver_ids do not match receiver_count"
        }

        $missing = @()
        foreach ($id in $manifest.receiver_ids) {
            $safeId = [string]$id
            if ([string]::IsNullOrWhiteSpace($safeId) -or $safeId.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                throw "Manifest contains an invalid receiver identifier"
            }

            $logPath = Join-Path (Join-Path $ResultsDir "receivers") "$safeId.log"
            if (-not (Test-Path -LiteralPath $logPath -PathType Leaf)) {
                $missing += $safeId
            }
        }

        if ($missing.Count -gt 0) {
            throw "Missing receiver evidence for: $($missing -join ', ')"
        }

        Write-Host "evidence_complete=true"
        Write-Host "receiver_count=$($manifest.receiver_count)"
        Write-Host "qualification_passed=undetermined"
        Write-Host "All expected evidence files are present. Review telemetry and physical observations against the runbook before recording PASS/FAIL."
    }
}
