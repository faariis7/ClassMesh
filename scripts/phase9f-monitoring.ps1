[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Help", "Init", "ValidateEvidence")]
    [string]$Mode,

    [int]$ReceiverCount = 0,
    [string[]]$ReceiverId = @(),
    [int]$TileWidth = 320,
    [int]$TileHeight = 180,
    [int]$Fps = 3,
    [int]$DurationSeconds = 300,
    [string]$ResultsDir = "phase9f-results"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SupportedReceiverCounts = @(5, 10, 20, 30)

function Manifest-Path {
    Join-Path $ResultsDir "monitoring-grid-manifest.json"
}

function Assert-ReceiverSet {
    if ($SupportedReceiverCounts -notcontains $ReceiverCount) {
        throw "-ReceiverCount must be one of: $($SupportedReceiverCounts -join ', ')"
    }
    if ($ReceiverId.Count -ne $ReceiverCount) {
        throw "-ReceiverId must contain exactly $ReceiverCount unique identifiers"
    }
    $normalized = @($ReceiverId | ForEach-Object {
        if ([string]::IsNullOrWhiteSpace($_)) {
            throw "Receiver identifiers must not be empty"
        }
        $value = $_.Trim()
        if ($value.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
            throw "Receiver identifiers must be valid file-name components"
        }
        $value
    })
    if (@($normalized | Sort-Object -Unique).Count -ne $ReceiverCount) {
        throw "Receiver identifiers must be unique"
    }
    $normalized
}

function Show-Help {
@"
ClassMesh Phase 9F monitoring-grid physical qualification helper

Modes:
  Help
  Init
  ValidateEvidence

Example:
  .\scripts\phase9f-monitoring.ps1 -Mode Init -ReceiverCount 5 -ReceiverId student-01,student-02,student-03,student-04,student-05 -ResultsDir .\phase9f-5

Required evidence:
  <ResultsDir>\teacher.log
  <ResultsDir>\receivers\<receiver-id>.log

Optional evidence:
  <ResultsDir>\network.log
  <ResultsDir>\teacher-ui.log

ValidateEvidence writes:
  <ResultsDir>\evidence-index.json

CI validates tooling only. It never sets qualification_passed=true.
"@ | Write-Host
}

switch ($Mode) {
    "Help" {
        Show-Help
    }

    "Init" {
        $receivers = Assert-ReceiverSet
        if ($TileWidth -le 0 -or $TileWidth -gt 640) {
            throw "-TileWidth must be in 1..640"
        }
        if ($TileHeight -le 0 -or $TileHeight -gt 360) {
            throw "-TileHeight must be in 1..360"
        }
        if ($Fps -lt 2 -or $Fps -gt 5) {
            throw "-Fps must be in 2..5"
        }
        if ($DurationSeconds -le 0) {
            throw "-DurationSeconds must be positive"
        }

        New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $ResultsDir "receivers") -Force | Out-Null

        [ordered]@{
            schema_version = 1
            created_utc = (Get-Date).ToUniversalTime().ToString("o")
            physical_monitoring_grid = $true
            receiver_count = $ReceiverCount
            receiver_ids = $receivers
            tile_width = $TileWidth
            tile_height = $TileHeight
            fps = $Fps
            duration_seconds = $DurationSeconds
            qualification_passed = $null
            note = "Physical evidence manifest only. Qualification requires human review of retained classroom evidence."
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Manifest-Path) -Encoding utf8

        Write-Host "Initialized Phase 9F manifest: $(Manifest-Path)"
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
        if ($manifest.physical_monitoring_grid -ne $true) {
            throw "Manifest physical_monitoring_grid must be true"
        }
        if ($SupportedReceiverCounts -notcontains [int]$manifest.receiver_count) {
            throw "Manifest receiver_count must be one of: $($SupportedReceiverCounts -join ', ')"
        }
        if ($null -eq $manifest.receiver_ids -or $manifest.receiver_ids.Count -ne $manifest.receiver_count) {
            throw "Manifest receiver_ids do not match receiver_count"
        }
        $ids = @($manifest.receiver_ids | ForEach-Object { [string]$_ })
        if (@($ids | Sort-Object -Unique).Count -ne $manifest.receiver_count) {
            throw "Manifest receiver_ids must be unique"
        }
        if ([int]$manifest.tile_width -le 0 -or [int]$manifest.tile_width -gt 640) {
            throw "Manifest tile_width is outside the Phase 9 monitoring bound"
        }
        if ([int]$manifest.tile_height -le 0 -or [int]$manifest.tile_height -gt 360) {
            throw "Manifest tile_height is outside the Phase 9 monitoring bound"
        }
        if ([int]$manifest.fps -lt 2 -or [int]$manifest.fps -gt 5) {
            throw "Manifest fps is outside the Phase 9 monitoring bound"
        }
        if ([int]$manifest.duration_seconds -le 0) {
            throw "Manifest duration_seconds must be positive"
        }
        if ($null -ne $manifest.qualification_passed) {
            throw "Manifest qualification_passed must remain null until reviewed physical evidence produces a human conclusion"
        }

        $teacherPath = Join-Path $ResultsDir "teacher.log"
        if (-not (Test-Path -LiteralPath $teacherPath -PathType Leaf)) {
            throw "Teacher evidence not found: $teacherPath"
        }
        if ((Get-Item -LiteralPath $teacherPath).Length -le 0) {
            throw "Teacher evidence is empty: $teacherPath"
        }

        $receiverEvidence = @()
        foreach ($id in $ids) {
            if ([string]::IsNullOrWhiteSpace($id) -or $id.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0) {
                throw "Manifest contains an invalid receiver identifier"
            }
            $path = Join-Path (Join-Path $ResultsDir "receivers") "$id.log"
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "Missing receiver evidence: $id"
            }
            $item = Get-Item -LiteralPath $path
            if ($item.Length -le 0) {
                throw "Empty receiver evidence: $id"
            }
            $receiverEvidence += [ordered]@{
                receiver_id = $id
                path = "receivers/$id.log"
                bytes = $item.Length
                sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            }
        }

        $teacherItem = Get-Item -LiteralPath $teacherPath
        $index = [ordered]@{
            schema_version = 1
            generated_utc = (Get-Date).ToUniversalTime().ToString("o")
            receiver_count = [int]$manifest.receiver_count
            tile_width = [int]$manifest.tile_width
            tile_height = [int]$manifest.tile_height
            fps = [int]$manifest.fps
            qualification_passed = $null
            manifest_sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
            teacher = [ordered]@{
                path = "teacher.log"
                bytes = $teacherItem.Length
                sha256 = (Get-FileHash -LiteralPath $teacherPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            receivers = @($receiverEvidence | Sort-Object receiver_id)
        }

        foreach ($optional in @("network.log", "teacher-ui.log")) {
            $path = Join-Path $ResultsDir $optional
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $item = Get-Item -LiteralPath $path
                if ($item.Length -le 0) {
                    throw "Optional evidence exists but is empty: $path"
                }
                $key = [System.IO.Path]::GetFileNameWithoutExtension($optional).Replace("-", "_")
                $index[$key] = [ordered]@{
                    path = $optional
                    bytes = $item.Length
                    sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
        }

        $indexPath = Join-Path $ResultsDir "evidence-index.json"
        $index | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $indexPath -Encoding utf8

        Write-Host "evidence_complete=true"
        Write-Host "receiver_count=$($manifest.receiver_count)"
        Write-Host "profile=$($manifest.tile_width)x$($manifest.tile_height)@$($manifest.fps)"
        Write-Host "evidence_index=$indexPath"
        Write-Host "qualification_passed=undetermined"
    }
}
