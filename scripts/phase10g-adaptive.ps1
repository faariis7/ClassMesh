[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Help", "Init", "ValidateEvidence")]
    [string]$Mode,

    [int]$ReceiverCount = 0,
    [string[]]$ReceiverId = @(),
    [int]$DurationSeconds = 300,
    [string]$ResultsDir = "phase10g-results"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SupportedReceiverCounts = @(5, 10, 20, 30)

# Evidence IDs are single, safe Windows filename components, never paths.
# Use the same strict validation on both manifest creation and later
# untrusted manifest reads. Preserve Unicode letters without accepting path
# aliases, Windows DOS device names or case-folded duplicate evidence files.
function Assert-ReceiverIdentifier {
    param([AllowNull()][string]$Id)

    if ([string]::IsNullOrWhiteSpace($Id) -or $Id.Length -gt 64 -or
        $Id -cne $Id.Trim() -or
        $Id -cnotmatch '^[\p{L}\p{Nd}][\p{L}\p{Nd}._-]{0,63}$' -or
        $Id.EndsWith(".")) {
        throw "Invalid receiver identifier: must be one safe filename component (1..64 letters/digits/._-)"
    }

    $deviceStem = ($Id -split '\.', 2)[0]
    if ($deviceStem -imatch '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
        throw "Invalid receiver identifier: reserved Windows device basename"
    }
    return $Id
}

function Assert-UniqueReceiverIdentifiers {
    param([string[]]$Ids)
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $Ids) {
        if (-not $seen.Add($id)) {
            throw "Receiver identifiers must be unique on case-insensitive Windows filesystems"
        }
    }
}

function Manifest-Path {
    Join-Path $ResultsDir "adaptive-controller-manifest.json"
}

function Assert-ReceiverSet {
    if ($SupportedReceiverCounts -notcontains $ReceiverCount) {
        throw "-ReceiverCount must be one of: $($SupportedReceiverCounts -join ', ')"
    }
    if ($ReceiverId.Count -ne $ReceiverCount) {
        throw "-ReceiverId must contain exactly $ReceiverCount unique identifiers"
    }

    $normalized = @($ReceiverId | ForEach-Object {
        Assert-ReceiverIdentifier -Id $_
    })
    Assert-UniqueReceiverIdentifiers -Ids $normalized
    $normalized
}

function Show-Help {
@"
ClassMesh Phase 10G adaptive-controller physical qualification helper

Modes:
  Help
  Init
  ValidateEvidence

Example:
  .\scripts\phase10g-adaptive.ps1 -Mode Init -ReceiverCount 5 -ReceiverId student-01,student-02,student-03,student-04,student-05 -ResultsDir .\phase10g-5

Required evidence:
  <ResultsDir>\teacher.log
  <ResultsDir>\receivers\<receiver-id>.log

Optional evidence:
  <ResultsDir>\network.log
  <ResultsDir>\topology.log
  <ResultsDir>\recovery.log
  <ResultsDir>\encoder.log

ValidateEvidence writes:
  <ResultsDir>\evidence-index.json

CI validates tooling only. It never marks physical qualification complete and
never selects transport/topology/relay/rendition production defaults.
"@ | Write-Host
}

switch ($Mode) {
    "Help" {
        Show-Help
    }

    "Init" {
        $receivers = Assert-ReceiverSet
        if ($DurationSeconds -le 0) {
            throw "-DurationSeconds must be positive"
        }

        New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $ResultsDir "receivers") -Force | Out-Null

        [ordered]@{
            schema_version = 1
            created_utc = (Get-Date).ToUniversalTime().ToString("o")
            physical_adaptive_controller = $true
            receiver_count = $ReceiverCount
            receiver_ids = $receivers
            duration_seconds = $DurationSeconds
            qualification_passed = $null
            transport_selected = $null
            topology_selected = $null
            relay_selected = $null
            rendition_count_selected = $null
            note = "Physical evidence manifest only. Final decisions require reviewed real-hardware evidence and independent open physical gates."
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Manifest-Path) -Encoding utf8

        Write-Host "Initialized Phase 10G manifest: $(Manifest-Path)"
        Write-Host "qualification_passed=undetermined"
        Write-Host "production_default_selected=false"
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
        if ($manifest.physical_adaptive_controller -ne $true) {
            throw "Manifest physical_adaptive_controller must be true"
        }
        if ($SupportedReceiverCounts -notcontains [int]$manifest.receiver_count) {
            throw "Manifest receiver_count must be one of: $($SupportedReceiverCounts -join ', ')"
        }
        if ($null -eq $manifest.receiver_ids -or $manifest.receiver_ids.Count -ne $manifest.receiver_count) {
            throw "Manifest receiver_ids do not match receiver_count"
        }

        # Validate BEFORE combining a manifest field with a filesystem path.
        # A forged manifest must never redirect hashing to parent directories,
        # DOS devices or an equivalent path alias.
        $ids = @($manifest.receiver_ids | ForEach-Object {
            Assert-ReceiverIdentifier -Id ([string]$_)
        })
        Assert-UniqueReceiverIdentifiers -Ids $ids
        if ([int]$manifest.duration_seconds -le 0) {
            throw "Manifest duration_seconds must be positive"
        }

        foreach ($field in @(
            "qualification_passed",
            "transport_selected",
            "topology_selected",
            "relay_selected",
            "rendition_count_selected"
        )) {
            if ($null -ne $manifest.$field) {
                throw "Manifest $field must remain null until reviewed physical evidence produces a human conclusion"
            }
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
            duration_seconds = [int]$manifest.duration_seconds
            qualification_passed = $null
            production_default_selected = $false
            manifest_sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
            teacher = [ordered]@{
                path = "teacher.log"
                bytes = $teacherItem.Length
                sha256 = (Get-FileHash -LiteralPath $teacherPath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            receivers = @($receiverEvidence | Sort-Object receiver_id)
        }

        foreach ($optional in @("network.log", "topology.log", "recovery.log", "encoder.log")) {
            $path = Join-Path $ResultsDir $optional
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $item = Get-Item -LiteralPath $path
                if ($item.Length -le 0) {
                    throw "Optional evidence exists but is empty: $path"
                }
                $key = [System.IO.Path]::GetFileNameWithoutExtension($optional)
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
        Write-Host "evidence_index=$indexPath"
        Write-Host "qualification_passed=undetermined"
        Write-Host "production_default_selected=false"
    }
}
