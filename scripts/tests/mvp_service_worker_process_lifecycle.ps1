# Real child-process regression for qualification ordering, portable to macOS.
# Only report/CIM admission is stubbed. This never registers SCM, fabricates
# LocalSystem identity, or claims a real Service/Worker pipe handshake.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../mvp-service-worker-runtime.ps1')

function Start-TestChild([string]$Command = '[Console]::WriteLine("ready"); Start-Sleep -Seconds 30') {
    $exe = if ($env:OS -eq 'Windows_NT') { 'pwsh.exe' } else { 'pwsh' }
    $info = [Diagnostics.ProcessStartInfo]::new((Join-Path $PSHOME $exe))
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    foreach ($arg in @('-NoProfile','-Command',$Command)) { $info.ArgumentList.Add($arg) }
    $child = [Diagnostics.Process]::Start($info)
    try {
        $null = $child.SafeHandle
        $ready = $child.StandardOutput.ReadLineAsync()
        if (-not $ready.Wait(10000) -or $ready.Result -ne 'ready') { throw 'Child startup handshake failed' }
        return $child
    } catch {
        if (-not $child.HasExited) { $child.Kill(); $null = $child.WaitForExit(5000) }
        $child.Dispose()
        throw
    }
}

foreach ($scenario in @('early-exit','follows-peer','wait-throws','service-exits')) {
$earlyExit = $scenario -eq 'early-exit'
$children = [Collections.Generic.List[Diagnostics.Process]]::new()
try {
    $serviceChild = Start-TestChild; $children.Add($serviceChild)
    $firstChild = Start-TestChild; $children.Add($firstChild)
    if ($scenario -ne 'follows-peer') { $restartedChild = Start-TestChild }
    else {
        # Real dependency: this child exits only after its retained parent-like
        # peer exits. It is not a Service, LocalSystem identity or IPC fixture.
        $command = '$peer=[Diagnostics.Process]::GetProcessById(' + $serviceChild.Id + '); [Console]::WriteLine("ready"); while (-not $peer.HasExited) { Start-Sleep -Milliseconds 20 }; exit 42'
        $restartedChild = Start-TestChild $command
    }
    $children.Add($restartedChild)
    $firstForRunner = [Diagnostics.Process]::GetProcessById($firstChild.Id)
    $restartedForRunner = [Diagnostics.Process]::GetProcessById($restartedChild.Id)
    $null = $firstForRunner.SafeHandle
    $null = $restartedForRunner.SafeHandle
    if ($scenario -eq 'wait-throws') {
        # Fault injection only at the wait API; the retained child and its
        # termination are real. The original admission/CIM stubs remain explicit.
        $restartedForRunner | Add-Member ScriptMethod WaitForExit { param([int]$Milliseconds) throw 'INJECTED_WORKER_WAIT_FAILURE' } -Force
    }
    if ($earlyExit) {
        $restartedChild.Kill()
        if (-not $restartedChild.WaitForExit(5000)) { throw 'Test child did not exit' }
    }

    function Wait-ClassMeshWorkerReport([uint32]$ServiceProcessId, [uint64]$AfterGeneration = 0) {
        if ($scenario -eq 'service-exits' -and $AfterGeneration -gt 0) {
            $serviceChild.Kill()
            if (-not $serviceChild.WaitForExit(5000)) { throw 'Unexpected-exit fixture did not stop' }
        }
        $pidValue = if ($AfterGeneration -eq 0) { $firstChild.Id } else { $restartedChild.Id }
        [pscustomobject]@{ service_pid=$ServiceProcessId; worker_pid=$pidValue; generation=$AfterGeneration+1 }
    }
    function Assert-ClassMeshWorkerReport($Report, [string]$WorkerPath, [string]$WorkerHash) {
        if ($Report.generation -eq 1) { return $firstForRunner }
        return $restartedForRunner
    }

    $failure = $null
    $evidence = $null
    try { $evidence = Invoke-ClassMeshWorkerRuntimeQualification $serviceChild.Id 'fixture-only' 'fixture-only' }
    catch { $failure = $_ }
    if ($scenario -eq 'service-exits') {
        if ($null -eq $failure -or $failure.Exception.Message -notmatch 'Service exited before intentional loss') { throw 'Unexpected Service-exit failure was not preserved' }
        if (-not $restartedChild.WaitForExit(1000)) { throw 'Unexpected Service exit left the retained test Worker alive' }
        if ($null -ne $evidence) { throw 'Unexpected exit emitted success evidence' }
        'PASS: unexpected peer exit also cleans retained child (not SCM/IPC proof)'
        continue
    }
    if ($scenario -eq 'wait-throws') {
        if ($null -eq $failure -or $failure.Exception.Message -notmatch 'INJECTED_WORKER_WAIT_FAILURE') { throw 'Original wait failure was not preserved' }
        if (-not $restartedChild.WaitForExit(1000)) { throw 'Exceptional Service loss left the retained test Worker alive' }
        if (-not $failure.Exception.Data.Contains('RetainedWorkerCleanupFailure')) { throw 'Cleanup failure was not reported alongside original error' }
        if ($null -ne $evidence) { throw 'Exceptional qualification emitted success evidence' }
        'PASS: exceptional loss cleans retained child and preserves original failure (not SCM/IPC proof)'
        continue
    }
    if (-not $earlyExit) {
        if ($null -ne $failure) { throw $failure }
        $record = $evidence | ConvertFrom-Json
        if ($record.worker_exit_code -ne 42 -or
            [DateTime]$record.worker_exit_at_utc -lt [DateTime]$record.service_exit_at_utc -or
            [DateTime]$record.service_exit_at_utc -lt [DateTime]$record.service_loss_injected_at_utc) {
            throw 'Real process exit chronology was not recorded'
        }
        'PASS: live dependent child exits after peer loss; actual exit code/time recorded (not SCM/IPC proof)'
        continue
    }
    if ($null -eq $failure) {
        throw "Qualification accepted an already-exited restarted Worker: $evidence"
    }
    if ($failure.Exception.Message -notmatch 'Worker.*exited.*before Service loss') { throw $failure }
    if ($serviceChild.HasExited) { throw 'Service-loss injection ran despite already-dead Worker' }
    if ($null -ne $evidence) { throw 'Failed qualification emitted success evidence' }
    'PASS: already-exited Worker rejected before Service loss; no false success evidence'
} finally {
    if (Get-Variable firstForRunner -ErrorAction SilentlyContinue) { $firstForRunner.Dispose() }
    if (Get-Variable restartedForRunner -ErrorAction SilentlyContinue) { $restartedForRunner.Dispose() }
    foreach ($child in $children) {
        try { if (-not $child.HasExited) { $child.Kill(); $null = $child.WaitForExit(5000) } }
        finally { $child.Dispose() }
    }
}
}
