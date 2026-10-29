[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Help", "IndexBundle", "ValidateBundle", "PreflightRuntime", "Smoke")]
    [string]$Mode,

    [string]$BundleDir = "phase11f4-teacher-ui-bundle",
    [string]$EvidenceDir = "phase11f4-teacher-ui-evidence",

    [ValidateRange(1, 30)]
    [int]$StartupSeconds = 5,

    [switch]$RequireResponsiveWindow,
    [switch]$LeaveRunning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SchemaVersion = 2
$Target = "windows-x64"
$ExecutableName = "classmesh-teacher-ui.exe"
$IndexName = "teacher-ui-bundle-index.json"
$RequiredFiles = @(
    $ExecutableName,
    "phase11f4-teacher-ui-smoke.ps1",
    "PHASE11_TEACHER_UI_SMOKE.md",
    "PHASE11_TEACHER_UI_SMOKE_RESULTS.md"
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

function Parse-VcVersion {
    param([AllowEmptyString()][string]$Text)
    if ($Text -notmatch '^v?(14)\.(\d+)\.(\d+)(?:\.(\d+))?$') {
        throw "Invalid Visual C++ runtime/toolset version: $Text"
    }
    $revision = if ($Matches[4]) { $Matches[4] } else { '0' }
    [version]::Parse("$($Matches[1]).$($Matches[2]).$($Matches[3]).$revision")
}

function Assert-RuntimeSatisfiesToolset {
    param([version]$Minimum, [AllowNull()][version]$Installed)
    if ($null -eq $Installed) {
        throw "Microsoft Visual C++ x64 Redistributable is missing. Install the current Microsoft-signed x64 package: https://aka.ms/vc14/vc_redist.x64.exe"
    }
    if ($Installed -lt $Minimum) {
        throw "Microsoft Visual C++ x64 Redistributable $Installed is older than this bundle's MSVC toolset $Minimum. Update from https://aka.ms/vc14/vc_redist.x64.exe"
    }
}

function Get-BuildToolsetVersion {
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        throw 'Bundle indexing requires the Windows MSVC build host'
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw 'vswhere.exe is missing' }
    $installation = (& $vswhere -latest -products '*' -property installationPath | Select-Object -First 1)
    if (-not $installation) { throw 'MSVC x64 build tools are missing' }
    $versionPath = Join-Path $installation 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt'
    if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) { throw 'MSVC toolset version file is missing' }
    Parse-VcVersion ((Get-Content -LiteralPath $versionPath -Raw).Trim())
}

function Get-X64VcRuntimeVersion {
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        throw 'Visual C++ runtime preflight requires Windows'
    }
    Assert-X64CompatibleArchitecture ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)
    $versions = @()
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try {
            $key = $root.OpenSubKey('SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64')
            if ($null -eq $key) { continue }
            try {
                if ([int]$key.GetValue('Installed', 0) -eq 1) {
                    $versions += Parse-VcVersion ([string]$key.GetValue('Version', ''))
                }
            } finally { $key.Close() }
        } finally { $root.Close() }
    }
    if ($versions.Count -eq 0) { return $null }
    if ($versions.Count -eq 2 -and $versions[0] -ne $versions[1]) {
        throw 'Conflicting Visual C++ x64 Redistributable registry versions'
    }
    $versions[0]
}

function Assert-X64CompatibleArchitecture {
    param([System.Runtime.InteropServices.Architecture]$Architecture)
    if ($Architecture -ne [System.Runtime.InteropServices.Architecture]::X64 -and
        $Architecture -ne [System.Runtime.InteropServices.Architecture]::Arm64) {
        throw "The Windows x64 Teacher UI bundle requires x64 Windows or Windows ARM64 with x64 emulation; found $Architecture"
    }
}

function Assert-BundleRuntime {
    param([Parameter(Mandatory = $true)]$Index)
    $minimum = Parse-VcVersion ([string]$Index.minimum_vc_runtime_version)
    $installed = Get-X64VcRuntimeVersion
    Assert-RuntimeSatisfiesToolset $minimum $installed
    Write-Host "vc_runtime_x64_version=$installed"
    Write-Host "minimum_vc_runtime_version=$minimum"
    Write-Host "os_architecture=$([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"
    $installed
}

function Show-Help {
@"
ClassMesh Phase 11F4 Teacher UI smoke helper

Modes:
  Help
  IndexBundle
  ValidateBundle
  PreflightRuntime
  Smoke

CI usage:
  .\scripts\phase11f4-teacher-ui-smoke.ps1 -Mode IndexBundle -BundleDir .\phase11f4-teacher-ui-bundle
  .\scripts\phase11f4-teacher-ui-smoke.ps1 -Mode ValidateBundle -BundleDir .\phase11f4-teacher-ui-bundle

Interactive Windows usage from the extracted artifact:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\phase11f4-teacher-ui-smoke.ps1 -Mode ValidateBundle -BundleDir .
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\phase11f4-teacher-ui-smoke.ps1 -Mode PreflightRuntime -BundleDir .
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\phase11f4-teacher-ui-smoke.ps1 -Mode Smoke -BundleDir . -EvidenceDir .\evidence -StartupSeconds 5 -LeaveRunning

The Bypass flag applies only to the launched PowerShell process; it does not change machine/user execution policy.

Smoke mode:
  - requires an interactive Windows user session (Session 0 is rejected);
  - verifies the exact artifact SHA-256 before launch;
  - checks the installed x64 Visual C++ Redistributable against the bundle's MSVC toolset version;
  - starts classmesh-teacher-ui.exe and requires a responsive ClassMesh Teacher window in the same interactive session;
  - writes launch-smoke-evidence.json only after the window check passes;
  - does NOT mark visual/accessibility review complete;
  - does NOT qualify any Phase 4/6/7/8/9/10 physical media or transport gate.
"@ | Write-Host
}

function Read-Index {
    $indexPath = Bundle-Path -Name $IndexName
    Assert-NonEmptyFile -Path $indexPath | Out-Null
    Get-Content -LiteralPath $indexPath -Raw | ConvertFrom-Json
}

function Validate-Bundle {
    $index = Read-Index

    if ([int]$index.schema_version -ne $SchemaVersion) {
        throw "Unsupported bundle schema version: $($index.schema_version)"
    }
    $null = Parse-VcVersion ([string]$index.minimum_vc_runtime_version)
    if ([string]$index.target -ne $Target) {
        throw "Bundle target must be $Target"
    }
    if ($index.ui_scope_only -ne $true) {
        throw "Bundle ui_scope_only must be true"
    }
    if ($null -ne $index.visual_accessibility_reviewed) {
        throw "Bundle visual_accessibility_reviewed must remain null until interactive review"
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
    Write-Host "target=$Target"
    Write-Host "minimum_vc_runtime_version=$($index.minimum_vc_runtime_version)"
    Write-Host "visual_accessibility_reviewed=undetermined"
    $index
}

switch ($Mode) {
    "Help" {
        Show-Help
    }

    "IndexBundle" {
        if (-not (Test-Path -LiteralPath $BundleDir -PathType Container)) {
            throw "Bundle directory not found: $BundleDir"
        }

        $files = @()
        foreach ($name in $RequiredFiles) {
            $files += File-Evidence -Path (Bundle-Path -Name $name) -RelativePath $name
        }

        $index = [ordered]@{
            schema_version = $SchemaVersion
            generated_utc = (Get-Date).ToUniversalTime().ToString("o")
            target = $Target
            minimum_vc_runtime_version = (Get-BuildToolsetVersion).ToString()
            ui_scope_only = $true
            visual_accessibility_reviewed = $null
            files = $files
            note = "Delivery integrity only. Runtime launch and visual/accessibility review require an interactive Windows session."
        }

        $indexPath = Bundle-Path -Name $IndexName
        $index | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $indexPath -Encoding utf8

        Write-Host "bundle_index=$indexPath"
        Write-Host "target=$Target"
    }

    "ValidateBundle" {
        $null = Validate-Bundle
    }

    "PreflightRuntime" {
        $index = Validate-Bundle
        $null = Assert-BundleRuntime -Index $index
        Write-Host 'runtime_preflight_passed=true'
    }

    "Smoke" {
        # This fixed filename is managed output. A failed retry must never
        # leave a previous successful launch record looking current.
        $evidencePath = Join-Path $EvidenceDir "launch-smoke-evidence.json"
        if (Test-Path -LiteralPath $evidencePath -PathType Leaf) {
            Remove-Item -LiteralPath $evidencePath -Force
        }
        if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
            throw "Smoke mode requires Windows"
        }

        $index = Validate-Bundle
        $runtimeVersion = Assert-BundleRuntime -Index $index

        $sessionId = (Get-Process -Id $PID).SessionId
        if ($sessionId -eq 0) {
            throw "Smoke mode must run in an interactive Windows user session; Session 0 is not accepted"
        }

        $exePath = Bundle-Path -Name $ExecutableName
        $exeItem = Assert-NonEmptyFile -Path $exePath
        $exeHash = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash.ToLowerInvariant()

        New-Item -ItemType Directory -Path $EvidenceDir -Force | Out-Null

        $process = $null
        $smokeSucceeded = $false
        try {
            $process = Start-Process -FilePath $exeItem.FullName -PassThru
            Start-Sleep -Seconds $StartupSeconds
            $process.Refresh()

            if ($process.HasExited) {
                throw "Teacher UI exited during bounded startup smoke with exit code $($process.ExitCode)"
            }

            if ($process.SessionId -ne $sessionId) {
                throw "Teacher UI window smoke rejected: process session does not match the interactive caller"
            }
            $windowTitle = [string]$process.MainWindowTitle
            if ($process.MainWindowHandle -eq [IntPtr]::Zero -or -not $process.Responding -or $windowTitle -cne "ClassMesh Teacher") {
                throw "Teacher UI window smoke failed: no responsive ClassMesh Teacher window; inspect Windows loader errors and runtime prerequisites"
            }

            [ordered]@{
                schema_version = $SchemaVersion
                observed_utc = (Get-Date).ToUniversalTime().ToString("o")
                ui_scope_only = $true
                executable = $ExecutableName
                executable_sha256 = $exeHash
                minimum_vc_runtime_version = [string]$index.minimum_vc_runtime_version
                installed_vc_runtime_version = $runtimeVersion.ToString()
                os_architecture = [string][System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
                startup_seconds = $StartupSeconds
                process_id = $process.Id
                process_alive_after_startup = $true
                main_window_observed = $true
                session_id = $sessionId
                user = [System.Environment]::UserName
                left_running = [bool]$LeaveRunning
                visual_accessibility_reviewed = $null
                physical_media_transport_qualified = $null
                note = "Launch smoke only. Visual/accessibility acceptance and unrelated physical qualification remain separate."
            } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $evidencePath -Encoding utf8
            $smokeSucceeded = $true

            Write-Host "launch_smoke_passed=true"
            Write-Host "process_id=$($process.Id)"
            Write-Host "session_id=$sessionId"
            Write-Host 'main_window_observed=true'
            Write-Host "evidence=$evidencePath"
            Write-Host "visual_accessibility_reviewed=undetermined"
        }
        finally {
            if ($null -ne $process -and (-not $LeaveRunning -or -not $smokeSucceeded)) {
                $process.Refresh()
                if (-not $process.HasExited) {
                    # Use the retained process object; a recycled PID must not
                    # allow smoke cleanup to terminate an unrelated process.
                    try { $process.Kill() }
                    catch {
                        $process.Refresh()
                        if (-not $process.HasExited) { throw }
                    }
                    $process.WaitForExit(5000) | Out-Null
                }
            }
        }
    }
}
