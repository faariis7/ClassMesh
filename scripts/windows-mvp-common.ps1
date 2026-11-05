Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-MvpExecutables {
    @('classmesh-teacher-ui.exe', 'classmesh-service.exe', 'classmesh-worker.exe')
}

function Get-MvpRequiredFiles {
    @(Get-MvpExecutables) + @(
        'phase11f4-teacher-ui-smoke.ps1', 'phase13-service-worker-bundle.ps1',
        'phase13-vc-runtime.ps1', 'phase13-release-manifest.ps1',
        'PHASE11_TEACHER_UI_SMOKE.md', 'PHASE11_TEACHER_UI_SMOKE_RESULTS.md',
        'PHASE13_SERVICE_WORKER_PREREQUISITES.md', 'WINDOWS_MVP_QUICKSTART.md',
        'windows-mvp-common.ps1', 'windows-mvp-bundle.ps1', 'windows-mvp-launch.ps1',
        'mvp-launcher-config.json'
    )
}

function Assert-MvpBuildContext {
    param($Actual, $Expected)
    $patterns = [ordered]@{
        source_revision = '^[0-9a-f]{40}$'; ci_run_id = '^[1-9][0-9]{0,19}$'
        ci_run_attempt = '^[1-9][0-9]{0,5}$'; ci_repository = '^faariis7/ClassMesh$'; ci_job = '^windows$'
    }
    foreach ($field in $patterns.Keys) {
        foreach ($value in @($Actual, $Expected)) {
            if ($null -eq $value -or $null -eq $value.PSObject.Properties[$field] -or
                $value.$field -isnot [string] -or $value.$field -cnotmatch $patterns[$field]) {
                throw "Invalid MVP build provenance context: $field"
            }
        }
        if ($Actual.$field -cne $Expected.$field) { throw "MVP build provenance mismatch: $field" }
    }
}

function Get-MvpFileEvidence {
    param([string]$Path, [string]$Name)
    try { $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop }
    catch { throw "Required MVP file unavailable: $Name : $($_.Exception.Message)" }
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 134217728) { throw "Invalid MVP file: $Name" }
    [pscustomobject]@{
        path = $Name; bytes = [long]$item.Length
        sha256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Read-MvpJson {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 65536) { throw "Invalid MVP JSON file size/type: $Path" }
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Test-MvpBundle {
    param([string]$BundleDir, $Expected)
    $root = Get-Item -LiteralPath $BundleDir -Force -ErrorAction Stop
    if (-not $root.PSIsContainer -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'MVP bundle directory must be a plain directory'
    }
    $names = @(Get-MvpRequiredFiles) + @('teacher-ui-bundle-index.json','service-worker-bundle-index.json')
    $entries = @(Get-ChildItem -LiteralPath $root.FullName -Force)
    if ($entries.Count -ne $names.Count + 1) { throw 'MVP bundle file count mismatch' }
    foreach ($entry in $entries) {
        if ($entry.Name -cnotin ($names + @('mvp-bundle-index.json')) -or $entry.PSIsContainer -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Unexpected MVP file: $($entry.Name)" }
    }
    $index = Read-MvpJson (Join-Path $root.FullName 'mvp-bundle-index.json')
    if ($index.schema_version -ne 1 -or $index.target -cne 'windows-x64' -or
        $index.production_qualified -isnot [bool] -or $index.production_qualified) {
        throw 'Unsupported MVP file schema, target or production claim'
    }
    Assert-MvpBuildContext $index $Expected
    if (@($index.files).Count -ne $names.Count) { throw 'MVP indexed file count mismatch' }
    foreach ($name in $names) {
        $records = @($index.files | Where-Object { $_.path -ceq $name })
        if ($records.Count -ne 1) { throw "Missing or duplicate MVP file record: $name" }
        $record = $records[0]
        $actual = Get-MvpFileEvidence (Join-Path $root.FullName $name) $name
        if (($record.bytes -isnot [int] -and $record.bytes -isnot [long]) -or
            $record.bytes -ne $actual.bytes -or [string]$record.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            $record.sha256 -cne $actual.sha256) { throw "MVP file size or SHA256 mismatch: $name" }
    }
    if (@($index.components).Count -ne 3) { throw 'MVP component count mismatch' }
    foreach ($name in @(Get-MvpExecutables)) {
        $components = @($index.components | Where-Object { $_.path -ceq $name })
        if ($components.Count -ne 1) { throw "Missing or duplicate MVP component: $name" }
        Assert-MvpBuildContext $components[0] $Expected
        $file = @($index.files | Where-Object { $_.path -ceq $name })[0]
        if ($components[0].sha256 -cne $file.sha256 -or $components[0].bytes -ne $file.bytes) {
            throw "MVP component receipt mismatch: $name"
        }
    }
    $config = Read-MvpJson (Join-Path $root.FullName 'mvp-launcher-config.json')
    if ($config.schema_version -ne 1 -or $config.service_name -cne 'ClassMeshService' -or
        ($config.teacher_startup_seconds -isnot [int] -and $config.teacher_startup_seconds -isnot [long]) -or $config.teacher_startup_seconds -lt 1 -or
        $config.teacher_startup_seconds -gt 30) { throw 'Invalid MVP launcher configuration file' }
    # Execute existing helpers only after every bundled script has passed its hash check.
    & (Join-Path $root.FullName 'phase11f4-teacher-ui-smoke.ps1') -Mode ValidateBundle -BundleDir $root.FullName | Out-Null
    & (Join-Path $root.FullName 'phase13-service-worker-bundle.ps1') -Mode ValidateBundle -BundleDir $root.FullName | Out-Null
    & {
        param($Root)
        . (Join-Path $Root 'phase13-service-worker-bundle.ps1') -Mode Help | Out-Null
        Assert-X64Pe (Join-Path $Root 'classmesh-teacher-ui.exe')
    } $root.FullName
    $index
}

function Get-MvpRuntimeDecision {
    param($Observation)
    $blockers = @()
    switch ($Observation.service.status) {
        'NOT_REGISTERED' { $blockers += 'SERVICE_NOT_REGISTERED' }
        'RUNNING' {
            if ($null -eq $Observation.service.binary_matches) { $blockers += 'SERVICE_BINARY_UNKNOWN' }
            elseif ($Observation.service.binary_matches -eq $false) { $blockers += 'SERVICE_BINARY_MISMATCH' }
            if ($Observation.service.session_id -ne 0) { $blockers += 'SERVICE_SESSION_UNKNOWN_OR_INVALID' }
        }
        'STOPPED' { $blockers += 'SERVICE_NOT_RUNNING' }
        default { $blockers += 'SERVICE_OBSERVATION_UNKNOWN' }
    }
    if ($Observation.enrollment.status -eq 'MISSING') { $blockers += 'ENROLLMENT_MISSING' }
    else { $blockers += 'ENROLLMENT_APPROVAL_UNKNOWN' }
    switch ($Observation.worker.status) {
        'MATCHING_PROCESS_OBSERVED' { }
        'WRONG_SESSION' { $blockers += 'WORKER_WRONG_SESSION' }
        'WRONG_PARENT' { $blockers += 'WORKER_WRONG_PARENT' }
        'BINARY_MISMATCH' { $blockers += 'WORKER_BINARY_MISMATCH' }
        'NOT_RUNNING' { $blockers += 'WORKER_NOT_RUNNING' }
        default { $blockers += 'WORKER_OBSERVATION_UNKNOWN' }
    }
    $blockers += 'AUTHENTICATED_IPC_UNVERIFIED'
    [pscustomobject]@{
        status = 'BLOCKED'; blockers = $blockers
        enrollment_approved = 'UNKNOWN'; ipc_status = 'NOT_VERIFIED'
        integrated_test_passed = $false; merge_authorized = $false
        next_action = 'Service owner: verify protected enrollment/authorization, then record an authenticated Service-owned Worker exchange; no installation is attempted.'
    }
}

function Open-MvpBundleLease {
    param([string]$BundleDir)
    $handles = @()
    try {
        foreach ($name in (@(Get-MvpRequiredFiles) + @('teacher-ui-bundle-index.json','service-worker-bundle-index.json','mvp-bundle-index.json'))) {
            $path = Join-Path $BundleDir $name
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Invalid MVP leased file: $name"
            }
            # Keep Windows write/delete sharing denied through validation and launch.
            $handles += [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        }
        $handles
    } catch {
        foreach ($handle in $handles) { $handle.Dispose() }
        throw
    }
}

function New-MvpReportDirectory {
    param([string]$Path)
    $temp = (Get-Item -LiteralPath ([IO.Path]::GetTempPath())).FullName.TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ([string]::IsNullOrEmpty($Path)) { $Path = Join-Path $temp ('ClassMesh-MVP-' + [guid]::NewGuid().ToString('N')) }
    $full = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar)
    $parent = (Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($full))).FullName.TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ($parent -ne $temp -or [IO.Path]::GetFileName($full) -cnotmatch '^ClassMesh-MVP-[0-9a-f]{32}$') {
        throw 'MVP report must be a new direct TEMP child named ClassMesh-MVP-<32 lowercase hex>'
    }
    if (Test-Path -LiteralPath $full) { throw 'MVP report directory already exists; previous evidence is never adopted' }
    $created = New-Item -ItemType Directory -Path $full -ErrorAction Stop
    $created.FullName
}

function Get-MvpCiContext {
    param([string]$RepositoryRoot)
    if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_OS -cne 'Windows') {
        throw 'MVP build receipts require a Windows GitHub Actions build, not local/imported binaries'
    }
    $context = [pscustomobject]@{
        source_revision = $env:GITHUB_SHA; ci_run_id = $env:GITHUB_RUN_ID
        ci_run_attempt = $env:GITHUB_RUN_ATTEMPT; ci_repository = $env:GITHUB_REPOSITORY; ci_job = $env:GITHUB_JOB
    }
    Assert-MvpBuildContext $context $context
    $head = & git -C $RepositoryRoot rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or [string]$head -cne $context.source_revision) {
        throw 'MVP build provenance does not match the actual checkout HEAD'
    }
    & git -C $RepositoryRoot diff --quiet HEAD --
    if ($LASTEXITCODE -ne 0) { throw 'MVP build provenance requires clean tracked sources' }
    $context
}

function Write-MvpNewJson {
    param($Value, [string]$Path)
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json -Depth 16))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush() } finally { $stream.Dispose() }
}

function Get-MvpWorkerMatch {
    param($Candidates, [int]$SessionId, [uint32]$ServiceProcessId, $ServiceStartedUtc)
    $Candidates = @($Candidates | Where-Object { $null -ne $_ })
    if (@($Candidates).Count -eq 0) { return 'NOT_RUNNING' }
    $sameSession = @($Candidates | Where-Object { $_.session_id -eq $SessionId -and $SessionId -gt 0 })
    if ($sameSession.Count -eq 0) { return 'WRONG_SESSION' }
    $owned = @($sameSession | Where-Object {
        $ServiceProcessId -gt 0 -and $_.parent_process_id -eq $ServiceProcessId -and
        $null -ne $ServiceStartedUtc -and $null -ne $_.started_utc -and $_.started_utc -ge $ServiceStartedUtc
    })
    if ($owned.Count -eq 0) { return 'WRONG_PARENT' }
    if (@($owned | Where-Object { $null -eq $_.binary_matches }).Count -gt 0) { return 'UNKNOWN' }
    $matching = @($owned | Where-Object { $_.binary_matches -eq $true })
    if ($matching.Count -eq 0) { return 'BINARY_MISMATCH' }
    if (@($matching | Where-Object { $_.pipe_binding_matches -eq $true }).Count -ne 1 -or $matching.Count -ne 1) {
        return 'IPC_BINDING_UNKNOWN'
    }
    'MATCHING_PROCESS_OBSERVED'
}

function Assert-MvpTeacherSession {
    param([bool]$Elevated, [int]$SessionId)
    if ($Elevated) { throw 'Teacher must be launched from a standard-user PowerShell; elevation is refused' }
    if ($SessionId -le 0) { throw 'Teacher requires a signed-in interactive session, not Session 0' }
}

function Get-MvpBinaryMatch {
    param([AllowNull()][string]$Path, [string]$ExpectedSha256)
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.StartsWith('\\') -or -not [IO.Path]::IsPathRooted($Path)) { return $null }
    try { ((Get-MvpFileEvidence $Path ([IO.Path]::GetFileName($Path))).sha256 -ceq $ExpectedSha256) }
    catch { return $null }
}

function Get-MvpEnrollmentObservation {
    # Presence/metadata are deliberately not cryptographic or protected-state approval.
    $records = @()
    $principal = $null; $expiry = $null
    $paths = @('state\machine-identity.json','state\authorization.json','config\control-runtime.json')
    $root = Join-Path $env:ProgramData 'ClassMesh'
    foreach ($relative in $paths) {
        $path = Join-Path $root $relative
        $record = [ordered]@{path=$path;status='UNKNOWN';error=$null}
        try {
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Protected state path is not a plain file' }
            $record.status = 'PRESENT_UNVERIFIED'
            if ($relative -eq 'state\machine-identity.json') {
                $json = Read-MvpJson $path
                if ($json.version -ne 1 -or @($json.principal_id).Count -ne 32) { throw 'Unrecognized identity metadata schema' }
                $principal = ([BitConverter]::ToString([byte[]]$json.principal_id)).Replace('-','').ToLowerInvariant()
                $expiry = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$json.not_after_unix_ms).ToString('o')
            }
        } catch {
            if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) { $record.status='MISSING' }
            else { $record.status='UNKNOWN'; $record.error=$_.Exception.Message }
        }
        $records += [pscustomobject]$record
    }
    $status = if (@($records | Where-Object status -EQ 'MISSING').Count -gt 0) {'MISSING'}
        elseif (@($records | Where-Object status -EQ 'UNKNOWN').Count -gt 0) {'UNKNOWN'} else {'PRESENT_UNVERIFIED'}
    [pscustomobject]@{
        status=$status; approval='UNKNOWN'; files=$records
        declared_principal_id=$principal; declared_not_after=$expiry; key_binding='UNKNOWN'
        reason='Read-only metadata observation; issuer trust, CNG ownership, ACL/rollback provenance and live authorization are not attested.'
    }
}

function Get-MvpWindowsObservation {
    param($Index, [int]$SessionId)
    $service = [pscustomobject]@{status='UNKNOWN';name='ClassMeshService';process_id=0;session_id=$null;start_name=$null;binary_matches=$null;error=$null}
    $worker = [pscustomobject]@{status='UNKNOWN';expected_session_id=$SessionId;candidates=@();error=$null}
    $serviceStarted = $null
    try {
        $services = @(Get-CimInstance Win32_Service -Filter "Name='ClassMeshService'" -OperationTimeoutSec 10 -ErrorAction Stop)
        if ($services.Count -eq 0) { $service.status='NOT_REGISTERED' }
        elseif ($services.Count -ne 1) { throw 'SCM returned an unexpected Service count' }
        else {
            $s = $services[0]
            $service.status = if ($s.State -eq 'Running') {'RUNNING'} elseif ($s.State -eq 'Stopped') {'STOPPED'} else {'UNKNOWN'}
            $service.start_name = [string]$s.StartName; $service.process_id = [uint32]$s.ProcessId
            $expected = @($Index.components | Where-Object path -CEQ 'classmesh-service.exe')[0].sha256
            $path = $null
            # Do not execute or expose SCM arguments; reject ambiguous unquoted paths.
            if ([string]$s.PathName -match '^"([^"\r\n]+\.exe)"(?:\s|$)') { $path=$Matches[1] }
            elseif ([string]$s.PathName -match '^(\S+\.exe)(?:\s|$)') { $path=$Matches[1] }
            $service.binary_matches = Get-MvpBinaryMatch $path $expected
            if ($service.process_id -gt 0) {
                $sp = @(Get-CimInstance Win32_Process -Filter "ProcessId=$($service.process_id)" -OperationTimeoutSec 10 -ErrorAction Stop)
                if ($sp.Count -eq 1) {
                    $service.session_id = [int]$sp[0].SessionId
                    $serviceStarted = $sp[0].CreationDate.ToUniversalTime()
                    $liveMatch = Get-MvpBinaryMatch ([string]$sp[0].ExecutablePath) $expected
                    if ($liveMatch -ne $true) { $service.binary_matches=$liveMatch }
                }
            }
        }
    } catch { $service.status='UNKNOWN'; $service.error=$_.Exception.Message }
    try {
        $records = @()
        $expectedHash = @($Index.components | Where-Object path -CEQ 'classmesh-worker.exe')[0].sha256
        foreach ($p in @(Get-CimInstance Win32_Process -Filter "Name='classmesh-worker.exe'" -OperationTimeoutSec 10 -ErrorAction Stop)) {
            $binding = $false
            $prefix = 'ClassMesh-{0:x8}-{1:x8}-' -f [uint32]$service.process_id, [uint32]$SessionId
            $command = [string]$p.CommandLine
            if ($command -match ('(?:^|\s)--pipe\s+"?' + [regex]::Escape($prefix) + '[0-9a-f]{16}"?(?:\s|$)') -and
                $command -match ('(?:^|\s)--session\s+' + $SessionId + '(?:\s|$)')) { $binding=$true }
            $records += [pscustomobject]@{
                process_id=[uint32]$p.ProcessId; parent_process_id=[uint32]$p.ParentProcessId
                session_id=[int]$p.SessionId; started_utc=$p.CreationDate.ToUniversalTime()
                binary_matches=(Get-MvpBinaryMatch ([string]$p.ExecutablePath) $expectedHash)
                pipe_binding_matches=$binding
            }
        }
        $worker.candidates=$records
        $worker.status=Get-MvpWorkerMatch $records $SessionId $service.process_id $serviceStarted
    } catch { $worker.status='UNKNOWN'; $worker.error=$_.Exception.Message }
    [pscustomobject]@{service=$service;worker=$worker;enrollment=(Get-MvpEnrollmentObservation)}
}
