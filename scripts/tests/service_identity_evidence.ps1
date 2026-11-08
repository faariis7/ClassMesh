param([Parameter(Mandatory)][string]$Binary, [Parameter(Mandatory)][string]$EvidenceDir)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../service-identity-output.ps1')
if (Test-Path -LiteralPath $EvidenceDir) { throw 'Evidence directory must be new; do not reuse old success evidence' }
$null = New-Item -ItemType Directory -Path $EvidenceDir
$exe = (Resolve-Path -LiteralPath $Binary).Path
$start = [Diagnostics.ProcessStartInfo]::new($exe)
$start.ArgumentList.Add('--observe-existing-service')
$start.UseShellExecute = $false
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$child = [Diagnostics.Process]::new()
$child.StartInfo = $start
$started = $false
$originalFailure = $null
try {
    $started = $child.Start()
    if (-not $started) { throw 'Could not launch owned measurement process' }
    $null = $child.SafeHandle # Retain original object; never reopen by PID.
    $output = [ClassMeshIdentityBoundedOutput]::Read($child.StandardOutput, 16384)
    $errors = [ClassMeshIdentityBoundedOutput]::Read($child.StandardError, 4096)
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (-not $child.HasExited) {
        if ($output.IsFaulted -or $errors.IsFaulted) { throw 'Measurement stream overflow or read failure; no qualifying result' }
        if ($timer.ElapsedMilliseconds -ge 20000) { throw 'Measurement deadline exceeded; no qualifying result' }
        $null = $child.WaitForExit(50)
    }
    if (-not $output.Wait(5000) -or -not $errors.Wait(5000)) { throw 'Measurement output did not drain' }
    if ($child.ExitCode -ne 0) { throw "Measurement failed: $($errors.Result)" }
    if ($output.Result.Length -gt 16384) { throw 'Oversized native report' }
    $report = $output.Result | ConvertFrom-Json
    if ($report.schema -ne 1 -or $report.authenticated_service_worker -ne $false) { throw 'Invalid or authorizing measurement report' }
    $allowed = @('NOT_MEASURED_CALLER_CONTEXT','MEASUREMENT_ERROR','INVALIDATED_CALLER_CONTEXT_CHANGED','PROCESS_ACCESS_DENIED_OR_UNAVAILABLE','PROCESS_ACCESS_OBSERVED_NOT_AUTHENTICATED')
    if ($report.outcome -notin $allowed) { throw 'Unknown evidence outcome' }
    if ($report.outcome -eq 'NOT_MEASURED_CALLER_CONTEXT' -and $null -ne $report.target) { throw 'Refused context touched target' }
    if ($null -ne $report.target -and $report.target.loaded_signed_image -ne 'UNVERIFIED') { throw 'Probe must not claim signed running-image trust' }
    if ($report.outcome -eq 'PROCESS_ACCESS_OBSERVED_NOT_AUTHENTICATED') {
        if ($report.target.actual_access -ne 0x101000 -or $report.target.inheritable -ne $false -or $null -eq $report.target.object) { throw 'Missing actual minimum-right process evidence' }
    }
    $record = [ordered]@{
        source_revision = $env:GITHUB_SHA
        review_head_revision = $env:CLASSMESH_EVIDENCE_HEAD_SHA
        executable_sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
        observed_utc = [DateTime]::UtcNow.ToString('o')
        actual_native_report = $report
        protected_classmesh_runtime_proven = $false
        qualified_security_approval = $false
    }
    $record | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $EvidenceDir 'measurement.json') -Encoding utf8
    Write-Host "Native current-context outcome: $($report.outcome)"
    if ($report.outcome -eq 'NOT_MEASURED_CALLER_CONTEXT') { Write-Host 'Ordinary-account to actual SYSTEM access remains NOT MEASURED; no synthetic/filtered account substituted' }
} catch {
    $originalFailure = $_
    throw
} finally {
    try {
        try {
            if ($started -and -not $child.HasExited) {
                $child.Kill()
                if (-not $child.WaitForExit(5000)) { throw 'Owned measurement process cleanup not confirmed' }
            }
        } catch {
            if ($null -eq $originalFailure) { throw }
            $originalFailure.Exception.Data['OwnedProbeCleanupFailure'] = $_.Exception.ToString()
            Write-Warning 'Retained probe cleanup failed; original failure preserved with separate cleanup detail'
        }
    } finally { $child.Dispose() }
}
