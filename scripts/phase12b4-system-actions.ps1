[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Help", "IndexBundle", "ValidateBundle", "CollectPreflight")]
    [string]$Mode,

    [string]$BundleDir = "phase12b4-system-action-bundle",
    [string]$EvidenceDir = "phase12b4-system-action-evidence",
    [string]$SourceRevision = "",
    [switch]$HostedCi
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SchemaVersion = 1
$Target = "windows-x64"
$IndexName = "system-action-bundle-index.json"
$ServiceExecutable = "classmesh-service.exe"
$RequiredFiles = @(
    $ServiceExecutable,
    "phase12b4-system-actions.ps1",
    "PHASE12_SYSTEM_ACTION_QUALIFICATION.md",
    "PHASE12_SYSTEM_ACTION_RESULTS.md"
)

function Bundle-Path {
    param([Parameter(Mandatory = $true)][string]$Name)
    Join-Path $BundleDir $Name
}

function Assert-NonEmptyFile {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required file not found: $Path"
    }

    $item = Get-Item -LiteralPath $Path
    if ($item.Length -le 0) {
        throw "Required file is empty: $Path"
    }

    $item
}

function File-Evidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    $item = Assert-NonEmptyFile -Path $Path
    [ordered]@{
        path = $RelativePath
        bytes = [int64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Show-Help {
@"
ClassMesh Phase 12B4 system-action qualification helper

Modes:
  Help
  IndexBundle
  ValidateBundle
  CollectPreflight

This helper is deliberately NON-DESTRUCTIVE.
It never invokes Lock, Restart, Shutdown, classmesh-service.exe, or any power API.

CI example:
  .\scripts\phase12b4-system-actions.ps1 -Mode IndexBundle -BundleDir .\phase12b4-system-action-bundle -SourceRevision <git-sha>
  .\scripts\phase12b4-system-actions.ps1 -Mode ValidateBundle -BundleDir .\phase12b4-system-action-bundle
  .\scripts\phase12b4-system-actions.ps1 -Mode CollectPreflight -BundleDir .\phase12b4-system-action-bundle -EvidenceDir .\phase12b4-system-action-bundle\ci-evidence -HostedCi

Physical execution is a separate 12B4b gate:
  - safe Lock execution requires explicit retained evidence;
  - Restart/Shutdown requires an explicitly disposable Windows target;
  - a preflight result must never be reported as physical acceptance.
"@ | Write-Host
}

function Read-Index {
    $path = Bundle-Path -Name $IndexName
    Assert-NonEmptyFile -Path $path | Out-Null
    Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
}

function Assert-UndeterminedExecution {
    param([Parameter(Mandatory = $true)]$Index)

    foreach ($field in @(
        "physical_qualification_passed",
        "lock_execution",
        "restart_execution",
        "shutdown_execution",
        "destructive_target_disposable"
    )) {
        if ($null -ne $Index.$field) {
            throw "Bundle index $field must remain null in non-destructive 12B4a tooling"
        }
    }
}

function Validate-Bundle {
    $index = Read-Index

    if ([int]$index.schema_version -ne $SchemaVersion) {
        throw "Unsupported bundle schema version: $($index.schema_version)"
    }
    if ([string]$index.target -ne $Target) {
        throw "Bundle target must be $Target"
    }
    if ($index.non_destructive -ne $true) {
        throw "Bundle non_destructive must be true"
    }
    if ($index.actions_invoked -ne $false) {
        throw "Bundle actions_invoked must be false"
    }

    Assert-UndeterminedExecution -Index $index

    if ([string]$index.routing.lock -ne "interactive_worker") {
        throw "Lock routing expectation must remain interactive_worker"
    }
    if ([string]$index.routing.restart -ne "service_power_executor") {
        throw "Restart routing expectation must remain service_power_executor"
    }
    if ([string]$index.routing.shutdown -ne "service_power_executor") {
        throw "Shutdown routing expectation must remain service_power_executor"
    }
    if ([int]$index.routing.dispatch_queue_capacity -ne 1) {
        throw "System-action dispatch queue capacity expectation must remain 1"
    }
    if ([string]$index.routing.power_acceptance -ne "accepted_async_only") {
        throw "Power acceptance expectation must remain accepted_async_only"
    }

    $indexedFiles = @($index.files)
    if ($indexedFiles.Count -ne $RequiredFiles.Count) {
        throw "Bundle index must contain exactly $($RequiredFiles.Count) required files"
    }

    foreach ($required in $RequiredFiles) {
        $matches = @($indexedFiles | Where-Object { [string]$_.path -eq $required })
        if ($matches.Count -ne 1) {
            throw "Bundle index must contain exactly one entry for: $required"
        }

        $path = Bundle-Path -Name $required
        $item = Assert-NonEmptyFile -Path $path
        $expectedBytes = [int64]$matches[0].bytes
        $expectedHash = ([string]$matches[0].sha256).ToLowerInvariant()
        $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()

        if ($item.Length -ne $expectedBytes) {
            throw "Bundle size mismatch: $required"
        }
        if ($actualHash -ne $expectedHash) {
            throw "Bundle SHA-256 mismatch: $required"
        }
    }

    Write-Host "bundle_valid=true"
    Write-Host "non_destructive=true"
    Write-Host "physical_qualification_passed=undetermined"
}

switch ($Mode) {
    "Help" {
        Show-Help
    }

    "IndexBundle" {
        if (-not (Test-Path -LiteralPath $BundleDir -PathType Container)) {
            throw "Bundle directory not found: $BundleDir"
        }

        if ([string]::IsNullOrWhiteSpace($SourceRevision)) {
            if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_SHA)) {
                $SourceRevision = $env:GITHUB_SHA
            } else {
                $SourceRevision = "unknown"
            }
        }

        $files = @()
        foreach ($name in $RequiredFiles) {
            $files += File-Evidence -Path (Bundle-Path -Name $name) -RelativePath $name
        }

        [ordered]@{
            schema_version = $SchemaVersion
            generated_utc = (Get-Date).ToUniversalTime().ToString("o")
            source_revision = $SourceRevision
            target = $Target
            non_destructive = $true
            actions_invoked = $false
            physical_qualification_passed = $null
            lock_execution = $null
            restart_execution = $null
            shutdown_execution = $null
            destructive_target_disposable = $null
            routing = [ordered]@{
                lock = "interactive_worker"
                restart = "service_power_executor"
                shutdown = "service_power_executor"
                dispatch_queue_capacity = 1
                power_acceptance = "accepted_async_only"
            }
            files = $files
            note = "12B4a tooling/integrity evidence only. Physical execution remains the separate 12B4b gate."
        } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Bundle-Path -Name $IndexName) -Encoding utf8

        Write-Host "bundle_index=$(Bundle-Path -Name $IndexName)"
        Write-Host "source_revision=$SourceRevision"
        Write-Host "actions_invoked=false"
    }

    "ValidateBundle" {
        Validate-Bundle
    }

    "CollectPreflight" {
        if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
            throw "CollectPreflight requires Windows"
        }

        Validate-Bundle
        $index = Read-Index

        New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null
        $servicePath = Bundle-Path -Name $ServiceExecutable
        $serviceItem = Assert-NonEmptyFile -Path $servicePath
        $indexPath = Bundle-Path -Name $IndexName

        $os = Get-CimInstance Win32_OperatingSystem
        $sessionId = (Get-Process -Id $PID).SessionId

        [ordered]@{
            schema_version = $SchemaVersion
            observed_utc = (Get-Date).ToUniversalTime().ToString("o")
            source_revision = [string]$index.source_revision
            target = $Target
            hosted_ci = [bool]$HostedCi
            non_destructive = $true
            actions_invoked = $false
            service_executable = [ordered]@{
                path = $ServiceExecutable
                bytes = [int64]$serviceItem.Length
                sha256 = (Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash.ToLowerInvariant()
            }
            bundle_index_sha256 = (Get-FileHash -LiteralPath $indexPath -Algorithm SHA256).Hash.ToLowerInvariant()
            environment = [ordered]@{
                os_caption = [string]$os.Caption
                os_version = [string]$os.Version
                os_build = [string]$os.BuildNumber
                os_architecture = [string]$os.OSArchitecture
                process_architecture = [string]$env:PROCESSOR_ARCHITECTURE
                session_id = [int]$sessionId
            }
            routing = $index.routing
            physical_qualification_passed = $null
            lock_execution = $null
            restart_execution = $null
            shutdown_execution = $null
            destructive_target_disposable = $null
            note = "Preflight/integrity evidence only. No system action was invoked."
        } | ConvertTo-Json -Depth 7 | Set-Content -LiteralPath (Join-Path $EvidenceDir "system-action-preflight-evidence.json") -Encoding utf8

        Write-Host "preflight_collected=true"
        Write-Host "actions_invoked=false"
        Write-Host "physical_qualification_passed=undetermined"
    }
}
