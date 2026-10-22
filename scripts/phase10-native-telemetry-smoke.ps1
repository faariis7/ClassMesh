# ClassMesh Phase 10 Windows-native independent-process telemetry smoke.
# This is NOT classroom physical qualification and NEVER opts into Service telemetry.
[CmdletBinding()]
param(
    [ValidateSet("Help","IndexBundle","ValidateBundle","Run")]
    [string]$Mode = "Help",
    [string]$BundleDir = $PSScriptRoot,
    [string]$SourceRevision = "",
    [string]$ResultsDir = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$exeName = "classmesh-win32-native-tests.exe"
$indexName = "native-smoke-index.json"

function Resolve-BundleFile {
    param([string]$Name)
    $dir = (Resolve-Path -LiteralPath $BundleDir -ErrorAction Stop).Path
    $file = Join-Path $dir $Name
    $item = Get-Item -LiteralPath $file -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw "Phase10 native bundle requires a regular file (no directory/symlink): $Name"
    }
    return $item.FullName
}

function Get-Binary {
    Resolve-BundleFile -Name $exeName
}

function Read-And-Validate-Index {
    $binary = Get-Binary
    $indexPath = Resolve-BundleFile -Name $indexName
    $manifest = Get-Content -LiteralPath $indexPath -Raw | ConvertFrom-Json
    if ($manifest.schema_version -ne 1 -or
        $manifest.executable -cne $exeName -or
        $manifest.source_revision -cnotmatch '^[0-9a-f]{40}$' -or
        $manifest.sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw "Invalid Phase10 native-smoke index fields"
    }
    if ([long]$manifest.bytes -le 0 -or
        [long]$manifest.bytes -ne (Get-Item -LiteralPath $binary).Length) {
        throw "Invalid Phase10 native-smoke binary size"
    }
    $actual = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $manifest.sha256) {
        throw "Phase10 native-smoke binary SHA256 mismatch"
    }
    return $manifest
}

switch ($Mode) {
    "Help" {
        Write-Output "Phase10 independent-process Windows telemetry native smoke"
        Write-Output "IndexBundle: -BundleDir PATH -SourceRevision 40-hex-sha"
        Write-Output "ValidateBundle: -BundleDir PATH; validates exact filename, size, SHA256, source SHA"
        Write-Output "Run: -BundleDir PATH [-ResultsDir NEW_PATH]; runs fixed native OS identity + telemetry tests"
        Write-Output "This does NOT enable production Service telemetry, choose network topology or qualify physical classrooms."
    }
    "IndexBundle" {
        if ($SourceRevision -cnotmatch '^[0-9a-f]{40}$') {
            throw "SourceRevision must be a complete 40-character lowercase Git SHA"
        }
        $binary = Get-Binary
        $indexPath = Join-Path (Resolve-Path -LiteralPath $BundleDir).Path $indexName
        if (Test-Path -LiteralPath $indexPath) {
            throw "Refusing to overwrite existing Phase10 native-smoke bundle index"
        }
        [ordered]@{
            schema_version = 1
            source_revision = $SourceRevision
            executable = $exeName
            bytes = (Get-Item -LiteralPath $binary).Length
            sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
            physical_qualification = $false
            production_default_selected = $false
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $indexPath -Encoding utf8
        [void](Read-And-Validate-Index)
        Write-Output "Phase10 native-smoke bundle indexed and verified"
    }
    "ValidateBundle" {
        $manifest = Read-And-Validate-Index
        if ($manifest.physical_qualification -ne $false -or $manifest.production_default_selected -ne $false) {
            throw "Phase10 native-smoke index cannot claim physical qualification or production defaults"
        }
        Write-Output "Phase10 native-smoke bundle valid: $($manifest.source_revision)"
    }
    "Run" {
        $manifest = Read-And-Validate-Index
        if ($manifest.physical_qualification -ne $false -or $manifest.production_default_selected -ne $false) {
            throw "Phase10 native bundle may not claim physical qualification"
        }
        if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
            throw "Phase10 native smoke only runs on Windows"
        }
        $binary = Get-Binary
        $selected = @(
            'telemetry_pipe::tests::native_two_process_telemetry_wire_uses_real_os_pid_and_fixed_frame',
            'telemetry_pipe::tests::native_idle_poll_cancels_drained_reads_but_stays_connected_for_next_report',
            'telemetry_pipe::tests::revocation_after_idle_poll_rejects_old_worker_without_new_read',
            'session_process::tests::duplicated_launched_process_handle_survives_original_owner_shutdown'
        )
        if ([string]::IsNullOrWhiteSpace($ResultsDir)) {
            $ResultsDir = Join-Path ([System.IO.Path]::GetTempPath()) ("classmesh-phase10-native-" + [guid]::NewGuid().ToString("N"))
        }
        if (Test-Path -LiteralPath $ResultsDir) {
            throw "Use a fresh, non-existing native-smoke results directory"
        }
        $available = @(& $binary --list)
        if ($LASTEXITCODE -ne 0) {
            throw "Cannot list native Windows telemetry tests"
        }
        foreach ($testName in $selected) {
            if (-not ($available -contains ($testName + ': test'))) {
                throw "Required native telemetry test absent from exact-source binary: $testName"
            }
            Write-Output "Running native Windows qualification: $testName"
            $output = & $binary $testName --exact --nocapture 2>&1
            $exit = $LASTEXITCODE
            $output | ForEach-Object { Write-Output $_ }
            if ($exit -ne 0 -or
                ($output -join [Environment]::NewLine) -notmatch 'test result: ok\. 1 passed;') {
                throw "Native OS telemetry test failed or ran zero tests: $testName exit=$exit"
            }
        }
        New-Item -ItemType Directory -Path $ResultsDir | Out-Null
        [ordered]@{
            schema_version = 1
            source_revision = $manifest.source_revision
            observed_utc = (Get-Date).ToUniversalTime().ToString('o')
            windows_native_process_transport_tested = $true
            tests_passed = $selected
            physical_qualification = $false
            production_default_selected = $false
        } | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath (Join-Path $ResultsDir 'native-smoke-result.json') -Encoding utf8
        Write-Output "PHASE10_NATIVE_VM_SMOKE_ALL_PASSED results=$ResultsDir"
    }
}
