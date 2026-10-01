[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Help", "Init", "ValidateEvidence")]
    [string]$Mode,

    [ValidateSet("direct-unicast", "relay")]
    [string]$Strategy = "direct-unicast",

    [int]$ReceiverCount = 0,
    [string[]]$ReceiverId = @(),
    [string]$ResultsDir = "phase8d-results",
    [string]$Scenario = "physical-wifi"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SupportedReceiverCounts = @(5, 10, 20, 30)

function Assert-ReceiverSet {
    if ($SupportedReceiverCounts -notcontains $ReceiverCount) {
        throw "-ReceiverCount must be one of: $($SupportedReceiverCounts -join ', ')"
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
    return Join-Path $ResultsDir "wifi-benchmark-manifest.json"
}

function Show-Help {
    @"
ClassMesh Phase 8D physical Wi-Fi evidence harness

This helper prepares and validates evidence only.
It never selects the Wi-Fi strategy.

Examples:
  .\scripts\phase8d-wifi.ps1 -Mode Init -Strategy direct-unicast -ReceiverCount 5 -ReceiverId student-01,student-02,student-03,student-04,student-05

  .\scripts\phase8d-wifi.ps1 -Mode ValidateEvidence -ResultsDir .\phase8d-results

Required evidence:
  <ResultsDir>\teacher.log
  <ResultsDir>\receivers\<receiver-id>.log

Optional AP evidence:
  <ResultsDir>\ap.log

ValidateEvidence writes:
  <ResultsDir>\evidence-index.json

The physical runbook and decision rules are in:
  docs\PHASE8_WIFI_PHYSICAL_QUALIFICATION.md
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
            strategy = $Strategy
            receiver_count = $ReceiverCount
            receiver_ids = $receivers
            physical_wifi = $true
            strategy_selected = $null
            note = "Evidence manifest only. Strategy selection requires reviewed physical Phase 8D evidence."
        }

        $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Manifest-Path) -Encoding utf8
        Write-Host "Initialized Phase 8D Wi-Fi evidence manifest: $(Manifest-Path)"
        Write-Host "strategy_selected=undetermined"
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
        if (@("direct-unicast", "relay") -notcontains [string]$manifest.strategy) {
            throw "Manifest strategy must be direct-unicast or relay"
        }
        if ($SupportedReceiverCounts -notcontains [int]$manifest.receiver_count) {
            throw "Manifest receiver_count must be one of: $($SupportedReceiverCounts -join ', ')"
        }
        if ($null -eq $manifest.receiver_ids -or $manifest.receiver_ids.Count -ne $manifest.receiver_count) {
            throw "Manifest receiver_ids do not match receiver_count"
        }
        $manifestReceiverIds = @($manifest.receiver_ids | ForEach-Object { [string]$_ })
        if (@($manifestReceiverIds | Sort-Object -Unique).Count -ne $manifest.receiver_count) {
            throw "Manifest receiver_ids must be unique"
        }
        if ($manifest.physical_wifi -ne $true) {
            throw "Manifest physical_wifi must be true for Phase 8D evidence"
        }
        if ($null -ne $manifest.strategy_selected) {
            throw "Manifest strategy_selected must remain null until reviewed physical evidence produces a human decision"
        }

        $teacherPath = Join-Path $ResultsDir "teacher.log"
        if (-not (Test-Path -LiteralPath $teacherPath -PathType Leaf)) {
            throw "Teacher evidence not found: $teacherPath"
        }
        if ((Get-Item -LiteralPath $teacherPath).Length -le 0) {
            throw "Teacher evidence is empty: $teacherPath"
        }

        $missing = @()
        $empty = @()
        $receiverEvidence = @()
        foreach ($id in $manifest.receiver_ids) {
            $safeId = [string]$id
            if ([string]::IsNullOrWhiteSpace($safeId) -or $safeId.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                throw "Manifest contains an invalid receiver identifier"
            }

            $logPath = Join-Path (Join-Path $ResultsDir "receivers") "$safeId.log"
            if (-not (Test-Path -LiteralPath $logPath -PathType Leaf)) {
                $missing += $safeId
                continue
            }

            $item = Get-Item -LiteralPath $logPath
            if ($item.Length -le 0) {
                $empty += $safeId
                continue
            }

            $receiverEvidence += [ordered]@{
                receiver_id = $safeId
                path = "receivers/$safeId.log"
                bytes = $item.Length
                sha256 = (Get-FileHash -LiteralPath $logPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }

        if ($missing.Count -gt 0) {
            throw "Missing receiver evidence for: $($missing -join ', ')"
        }
        if ($empty.Count -gt 0) {
            throw "Empty receiver evidence for: $($empty -join ', ')"
        }

        $teacherItem = Get-Item -LiteralPath $teacherPath
        $index = [ordered]@{
            schema_version = 1
            generated_utc = (Get-Date).ToUniversalTime().ToString("o")
            strategy = [string]$manifest.strategy
            receiver_count = [int]$manifest.receiver_count
            strategy_selected = $null
            manifest_sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
            teacher = [ordered]@{
                path = "teacher.log"
                bytes = $teacherItem.Length
                sha256 = (Get-FileHash -LiteralPath $teacherPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            receivers = @($receiverEvidence | Sort-Object receiver_id)
        }

        $apPath = Join-Path $ResultsDir "ap.log"
        if (Test-Path -LiteralPath $apPath -PathType Leaf) {
            $apItem = Get-Item -LiteralPath $apPath
            if ($apItem.Length -le 0) {
                throw "AP evidence exists but is empty: $apPath"
            }
            $index["ap"] = [ordered]@{
                path = "ap.log"
                bytes = $apItem.Length
                sha256 = (Get-FileHash -LiteralPath $apPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }

        $indexPath = Join-Path $ResultsDir "evidence-index.json"
        $index | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $indexPath -Encoding utf8

        Write-Host "evidence_complete=true"
        Write-Host "strategy=$($manifest.strategy)"
        Write-Host "receiver_count=$($manifest.receiver_count)"
        Write-Host "evidence_index=$indexPath"
        Write-Host "strategy_selected=undetermined"
        Write-Host "Evidence presence and hashes are complete. Review physical metrics and observations before selecting any strategy."
    }
}
