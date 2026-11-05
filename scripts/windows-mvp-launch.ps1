[CmdletBinding()]
param(
    [ValidateSet('Help','Validate','Diagnose','Smoke','Launch')][string]$Mode = 'Diagnose',
    [string]$BundleDir = '.', [string]$ExpectedSourceRevision, [string]$ExpectedCiRunId,
    [string]$ExpectedCiRunAttempt = '1', [string]$ReportDir
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-mvp-common.ps1')
if ($Mode -eq 'Help') {
    Write-Host 'Windows MVP: Validate integrity; Diagnose read-only SCM/identity/Worker; Smoke starts and closes Teacher; Launch explicitly leaves a successful Teacher window running. No Service installation/start or ProgramData changes.'
    return
}
$reportRoot = New-MvpReportDirectory $ReportDir
$report = [ordered]@{
    schema_version=1;observed_utc=[DateTime]::UtcNow.ToString('o');mode=$Mode
    expected_source_revision=$ExpectedSourceRevision;expected_ci_run_id=$ExpectedCiRunId;expected_ci_run_attempt=$ExpectedCiRunAttempt
    bundle=[ordered]@{status='UNKNOWN';source_revision=$null;ci_run_id=$null}
    runtime=[ordered]@{status='NOT_REQUESTED'};teacher=[ordered]@{status='NOT_REQUESTED';evidence=$null}
    observation=$null;decision=$null;errors=@();integrated_test_passed=$false;merge_authorized=$false
    production_qualified=$false;exit_code=1
}
$leases = @(); $exitCode=1; $phase='bundle'
try {
    $expected=[pscustomobject]@{source_revision=$ExpectedSourceRevision;ci_run_id=$ExpectedCiRunId;ci_run_attempt=$ExpectedCiRunAttempt;ci_repository='faariis7/ClassMesh';ci_job='windows'}
    $leases=@(Open-MvpBundleLease $BundleDir)
    $index=Test-MvpBundle $BundleDir $expected
    $report.bundle.status='PASSED'; $report.bundle.source_revision=$index.source_revision; $report.bundle.ci_run_id=$index.ci_run_id
    if ($Mode -eq 'Validate') { $exitCode=0 }
    else {
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Runtime diagnosis/launch requires Windows' }
        $phase='runtime'
        & (Join-Path $BundleDir 'phase11f4-teacher-ui-smoke.ps1') -Mode PreflightRuntime -BundleDir $BundleDir
        & (Join-Path $BundleDir 'phase13-service-worker-bundle.ps1') -Mode PreflightRuntime -BundleDir $BundleDir
        $report.runtime.status='PASSED'
        $session = (Get-Process -Id $PID).SessionId
        $elevated=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $report['caller']=[ordered]@{session_id=$session;elevated=$elevated;user=[Environment]::UserName}
        $phase='observation'
        $report.observation=Get-MvpWindowsObservation $index $session
        $report.decision=Get-MvpRuntimeDecision $report.observation
        $exitCode=2
        if ($Mode -in @('Smoke','Launch')) {
            $phase='teacher'
            Assert-MvpTeacherSession $elevated $session
            $config=Read-MvpJson (Join-Path $BundleDir 'mvp-launcher-config.json')
            $teacherDir=Join-Path $reportRoot 'teacher'
            & (Join-Path $BundleDir 'phase11f4-teacher-ui-smoke.ps1') -Mode Smoke -BundleDir $BundleDir -EvidenceDir $teacherDir -StartupSeconds $config.teacher_startup_seconds -RequireResponsiveWindow -LeaveRunning:($Mode -eq 'Launch')
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
