$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Join-Path $PSScriptRoot '..') 'windows-mvp-common.ps1')

$passed = 0; $failed = 0
function Expect($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Observation {
    [pscustomobject]@{
        service = [pscustomobject]@{status='RUNNING'; binary_matches=$true; session_id=0}
        enrollment = [pscustomobject]@{status='PRESENT_UNVERIFIED'; approval='UNKNOWN'}
        worker = [pscustomobject]@{status='MATCHING_PROCESS_OBSERVED'}
    }
}
foreach ($case in @('missing-service','api-failure','service-binary-unknown','service-binary-mismatch','missing-enrollment','wrong-session','wrong-parent','mismatching-worker','apparently-healthy')) {
    try {
        $o = Observation
        switch ($case) {
            'missing-service' { $o.service.status='NOT_REGISTERED' }
            'api-failure' { $o.service.status='UNKNOWN' }
            'service-binary-unknown' { $o.service.binary_matches=$null }
            'service-binary-mismatch' { $o.service.binary_matches=$false }
            'missing-enrollment' { $o.enrollment.status='MISSING' }
            'wrong-session' { $o.worker.status='WRONG_SESSION' }
            'wrong-parent' { $o.worker.status='WRONG_PARENT' }
            'mismatching-worker' { $o.worker.status='BINARY_MISMATCH' }
        }
        $r = Get-MvpRuntimeDecision $o
        Expect ($r.integrated_test_passed -eq $false) 'observation must never authorize or prove IPC'
        Expect ($r.merge_authorized -eq $false) 'diagnostics never authorize a merge'
        Expect ($r.enrollment_approved -ceq 'UNKNOWN') 'file presence is not approved identity'
        Expect ($r.ipc_status -ne 'PASSED') 'process presence is not authenticated IPC'
        if ($case -eq 'missing-service') { Expect (@($r.blockers) -contains 'SERVICE_NOT_REGISTERED') 'missing Service reason was hidden' }
        if ($case -eq 'api-failure') { Expect (@($r.blockers) -contains 'SERVICE_OBSERVATION_UNKNOWN') 'API failure was hidden' }
        if ($case -eq 'service-binary-unknown') { Expect (@($r.blockers) -contains 'SERVICE_BINARY_UNKNOWN') 'unreadable Service executable was labeled as a known mismatch' }
        if ($case -eq 'service-binary-mismatch') { Expect (@($r.blockers) -contains 'SERVICE_BINARY_MISMATCH') 'confirmed Service mismatch was hidden' }
        if ($case -eq 'missing-enrollment') { Expect (@($r.blockers) -contains 'ENROLLMENT_MISSING') 'missing enrollment reason was hidden' }
        if ($case -eq 'wrong-session') { Expect (@($r.blockers) -contains 'WORKER_WRONG_SESSION') 'session mismatch was hidden' }
        $passed++; Write-Host "PASS $case"
    } catch { $failed++; Write-Host "FAIL $case : $($_.Exception.Message)" }
}
foreach ($case in @('matching','wrong-session','wrong-parent','old-process','wrong-binary','unknown-binary','wrong-pipe','duplicate','absent')) {
    try {
        $started = [datetime]'2026-11-05T10:00:00Z'
        $candidate = [pscustomobject]@{session_id=1;parent_process_id=100;started_utc=$started.AddSeconds(1);binary_matches=$true;pipe_binding_matches=$true}
        $want = switch ($case) {
            'matching' { 'MATCHING_PROCESS_OBSERVED' }
            'wrong-session' { $candidate.session_id=2; 'WRONG_SESSION' }
            'wrong-parent' { $candidate.parent_process_id=200; 'WRONG_PARENT' }
            'old-process' { $candidate.started_utc=$started.AddSeconds(-1); 'WRONG_PARENT' }
            'wrong-binary' { $candidate.binary_matches=$false; 'BINARY_MISMATCH' }
            'unknown-binary' { $candidate.binary_matches=$null; 'UNKNOWN' }
            'wrong-pipe' { $candidate.pipe_binding_matches=$false; 'IPC_BINDING_UNKNOWN' }
            'duplicate' { 'IPC_BINDING_UNKNOWN' }
            'absent' { 'NOT_RUNNING' }
        }
        $candidates = if ($case -eq 'absent') { @() } elseif ($case -eq 'duplicate') { @($candidate,$candidate) } else { @($candidate) }
        $r = Get-MvpWorkerMatch $candidates 1 100 $started
        Expect ($r -ceq $want) "Worker matching $case returned $r instead of $want"
        $passed++; Write-Host "PASS worker-$case"
    } catch { $failed++; Write-Host "FAIL worker-$case : $($_.Exception.Message)" }
}
foreach ($case in @('standard','elevated','session-zero')) {
    try {
        $rejected=$false
        try { Assert-MvpTeacherSession ($case -eq 'elevated') $(if ($case -eq 'session-zero') {0} else {1}) }
        catch { $rejected=$true }
        Expect ($rejected -eq ($case -ne 'standard')) "Teacher launch policy failed for $case"
        $passed++; Write-Host "PASS teacher-$case"
    } catch { $failed++; Write-Host "FAIL teacher-$case : $($_.Exception.Message)" }
}
foreach ($failure in @('Access denied','CIM operation timed out')) {
    $previousProgramData = $env:ProgramData
    $fakeRoot = Join-Path ([IO.Path]::GetTempPath()) ('ClassMesh-MVP-api-' + [guid]::NewGuid().ToString('N'))
    try {
        $env:ProgramData = $fakeRoot
        # Mock only the unavailable OS query; classification and filesystem reads are real.
        function Get-CimInstance {
            [CmdletBinding()]param([string]$ClassName,[string]$Filter,[int]$OperationTimeoutSec)
            throw $failure
        }
        $index = [pscustomobject]@{components=@([pscustomobject]@{path='classmesh-worker.exe';sha256=('0'*64)})}
        $o = Get-MvpWindowsObservation $index 1
        Expect ($o.service.status -eq 'UNKNOWN' -and $o.worker.status -eq 'UNKNOWN') 'CIM failure was treated as absence or success'
        Expect ($o.service.error -eq $failure -and $o.worker.error -eq $failure) 'actual CIM failure reason was lost'
        $passed++; Write-Host "PASS API-$failure"
    } catch { $failed++; Write-Host "FAIL API-$failure : $($_.Exception.Message)" }
    finally { Remove-Item Function:\Get-CimInstance -ErrorAction SilentlyContinue; $env:ProgramData=$previousProgramData }
}
Write-Host "windows_mvp_diagnostics_tests: passed=$passed failed=$failed"
if ($failed -ne 0) { exit 1 }
exit 0
