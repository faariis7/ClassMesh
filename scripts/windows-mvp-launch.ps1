[CmdletBinding()]
param(
    [ValidateSet('Help','Validate','Diagnose','Smoke','Launch')][string]$Mode = 'Diagnose',
    [string]$BundleDir = '.', [string]$ExpectedSourceRevision, [string]$ExpectedCiRunId,
    [string]$ExpectedCiRunAttempt = '1', [string]$ExpectedIndexSha256, [string]$ReportDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-mvp-common.ps1')
if ($Mode -eq 'Help') {
    Write-Host 'Windows MVP modes: Validate, Diagnose, Smoke, Launch. Supply the expected source SHA, run ID, attempt, and trusted index SHA256.'
    return
}
$reportRoot = New-MvpReportDirectory $ReportDir
$report = [ordered]@{
    schema_version=1;observed_utc=[DateTime]::UtcNow.ToString('o');mode=$Mode
    expected_source_revision=$ExpectedSourceRevision;expected_ci_run_id=$ExpectedCiRunId;expected_ci_run_attempt=$ExpectedCiRunAttempt
    bundle=[ordered]@{status='UNKNOWN';source_revision=$null;ci_run_id=$null;index_sha256=$null}
    runtime=[ordered]@{status='NOT_REQUESTED'};teacher=[ordered]@{status='NOT_REQUESTED';evidence=$null}
    observation=$null;decision=$null;errors=@();integrated_test_passed=$false;merge_authorized=$false
    production_qualified=$false;exit_code=1
}
$leases = @(); $exitCode=1; $phase='bundle'
try {
    $expected=[pscustomobject]@{source_revision=$ExpectedSourceRevision;ci_run_id=$ExpectedCiRunId;ci_run_attempt=$ExpectedCiRunAttempt;ci_repository='faariis7/ClassMesh';ci_job='windows'}
    $BundleDir=(Get-MvpBundleDirectory $BundleDir).FullName
    $leases=@(Open-MvpBundleLease $BundleDir)
    $index=Test-MvpBundle $BundleDir $expected $ExpectedIndexSha256
    $report.bundle.status='PASSED'; $report.bundle.source_revision=$index.source_revision; $report.bundle.ci_run_id=$index.ci_run_id
    $report.bundle.index_sha256=$ExpectedIndexSha256.ToLowerInvariant()
    if ($Mode -eq 'Validate') { $exitCode=0 }
    else {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Runtime diagnosis/launch requires Windows' }
        $session = (Get-Process -Id $PID).SessionId
        $elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $interactive = [Environment]::UserInteractive
        $report['caller']=[ordered]@{session_id=$session;elevated=$elevated;interactive=$interactive;user=[Environment]::UserName}
        $phase='observation'
        $report.observation=Get-MvpWindowsObservation $index $session
        $report.decision=Get-MvpRuntimeDecision $report.observation
        $phase='runtime'
        & (Join-Path $PSScriptRoot 'phase11f4-teacher-ui-smoke.ps1') -Mode PreflightRuntime -BundleDir $BundleDir
        & (Join-Path $PSScriptRoot 'phase13-service-worker-bundle.ps1') -Mode PreflightRuntime -BundleDir $BundleDir
        $report.runtime.status='PASSED'
        $exitCode=2
        if ($Mode -in @('Smoke','Launch')) {
            $phase='teacher'
            Assert-MvpTeacherSession $elevated $session $interactive
            $config=Read-MvpJson (Join-Path $BundleDir 'mvp-launcher-config.json')
            $teacherDir=Join-Path $reportRoot 'teacher'
            & (Join-Path $PSScriptRoot 'phase11f4-teacher-ui-smoke.ps1') -Mode Smoke -BundleDir $BundleDir -EvidenceDir $teacherDir -StartupSeconds $config.teacher_startup_seconds -RequireResponsiveWindow -LeaveRunning:($Mode -eq 'Launch')
            $smoke=Read-MvpJson (Join-Path $teacherDir 'launch-smoke-evidence.json')
            $report.teacher.status='PASSED'; $report.teacher.evidence=$smoke
        }
    }
} catch {
    $exitCode=1
    $report.errors += [ordered]@{phase=$phase;message=$_.Exception.Message;error_type=$_.Exception.GetType().FullName}
    if ($phase -in @('bundle','runtime','teacher')) { $report[$phase].status='FAILED' }
} finally {
    foreach ($h in $leases) { $h.Dispose() }
    $report.exit_code=$exitCode
    Write-MvpNewJson $report (Join-Path $reportRoot 'mvp-report.json')
    Write-Host "mvp_report=$(Join-Path $reportRoot 'mvp-report.json')"
    Write-Host "mvp_exit_code=$exitCode (0=integrity validation only; 1=failed; 2=runtime evidence blocked/unverified)"
    if ($null -ne $report.decision) { Write-Host ('blockers=' + ($report.decision.blockers -join ',')) }
}
exit $exitCode
