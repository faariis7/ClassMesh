# Called ONLY inside the approved create/verify/cleanup lifetime of the SCM gate.
# This file defines functions; importing it never starts a service or changes ACLs.
Set-StrictMode -Version Latest

function Read-ClassMeshRuntimeReport([uint32]$ServiceProcessId) {
    if (-not ('ClassMesh.RuntimePipePeer' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace ClassMesh {
 public static class RuntimePipePeer {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool GetNamedPipeServerProcessId(SafePipeHandle h, out uint pid);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool GetNamedPipeServerSessionId(SafePipeHandle h, out uint session);
 }
}
'@
    }
    $name = 'ClassMesh-runtime-{0:x8}' -f $ServiceProcessId
    $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', $name, [IO.Pipes.PipeDirection]::In, [IO.Pipes.PipeOptions]::Asynchronous)
    $cancel = [Threading.CancellationTokenSource]::new(1500)
    try {
        $pipe.ConnectAsync(1000, $cancel.Token).GetAwaiter().GetResult()
        [uint32]$peer = 0; [uint32]$session = 99
        if (-not [ClassMesh.RuntimePipePeer]::GetNamedPipeServerProcessId($pipe.SafePipeHandle, [ref]$peer) -or
            -not [ClassMesh.RuntimePipePeer]::GetNamedPipeServerSessionId($pipe.SafePipeHandle, [ref]$session) -or
            $peer -ne $ServiceProcessId -or $session -ne 0) {
            throw 'FAIL_CLOSED: runtime probe is not owned by the exact Session 0 SCM process'
        }
        $bytes = [Collections.Generic.List[byte]]::new()
        $one = [byte[]]::new(1)
        while ($bytes.Count -lt 128) {
            $count = $pipe.ReadAsync($one, 0, 1, $cancel.Token).GetAwaiter().GetResult()
            if ($count -eq 0) { throw 'FAIL_CLOSED: incomplete runtime probe record' }
            if ($one[0] -eq 10) { return ([Text.Encoding]::UTF8.GetString($bytes.ToArray()) | ConvertFrom-Json) }
            $bytes.Add($one[0])
        }
        throw 'FAIL_CLOSED: oversized runtime probe record'
    } finally { $cancel.Dispose(); $pipe.Dispose() }
}

function Wait-ClassMeshWorkerReport([uint32]$ServiceProcessId, [uint64]$AfterGeneration = 0) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $registration = Get-CimInstance Win32_Service -Filter "Name='ClassMeshService'"
        if ($null -eq $registration -or $registration.State -ne 'Running' -or $registration.ProcessId -ne $ServiceProcessId) {
            throw 'FAIL_CLOSED: Service lost during Worker IPC qualification'
        }
        # Retry only absent/not-yet-listening endpoints; identity/protocol errors fail.
        try { $report = Read-ClassMeshRuntimeReport $ServiceProcessId }
        catch [TimeoutException] { continue }
        catch [OperationCanceledException] { continue }
        if ($report.service_pid -ne $ServiceProcessId) { throw 'FAIL_CLOSED: report Service PID mismatch' }
        if ($report.generation -gt $AfterGeneration -and $report.worker_pid -gt 0) { return $report }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'FAIL_CLOSED: no current decoded Worker IPC report within deadline'
}

function Assert-ClassMeshWorkerReport($Report, [string]$WorkerPath, [string]$WorkerHash) {
    $worker = Get-CimInstance Win32_Process -Filter "ProcessId=$($Report.worker_pid)"
    $operator = [Security.Principal.WindowsIdentity]::GetCurrent()
    $session = [Diagnostics.Process]::GetCurrentProcess().SessionId
    if ($null -eq $worker -or $worker.ParentProcessId -ne $Report.service_pid -or
        $worker.SessionId -ne $session -or $Report.session -ne $session -or
        -not [string]::Equals($worker.ExecutablePath, $WorkerPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'FAIL_CLOSED: Worker PID/parent/session/image mismatch'
    }
    $owner = Invoke-CimMethod -InputObject $worker -MethodName GetOwnerSid
    if ($owner.ReturnValue -ne 0 -or $owner.Sid -ne $operator.User.Value -or $owner.Sid -eq 'S-1-5-18') {
        throw 'FAIL_CLOSED: Worker is not the intended interactive user'
    }
    Assert-ProtectedFile $WorkerPath $WorkerHash
    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$($Report.service_pid)" | Where-Object Name -eq 'classmesh-worker.exe')
    if ($children.Count -ne 1 -or $children[0].ProcessId -ne $Report.worker_pid) { throw 'FAIL_CLOSED: expected exactly one Service-owned Worker' }
    $service = Get-CimInstance Win32_Process -Filter "ProcessId=$($Report.service_pid)"
    $serviceOwner = Invoke-CimMethod -InputObject $service -MethodName GetOwnerSid
    if ($service.SessionId -ne 0 -or $serviceOwner.ReturnValue -ne 0 -or $serviceOwner.Sid -ne 'S-1-5-18') {
        throw 'FAIL_CLOSED: Service runtime token/session changed'
    }
    $process = [Diagnostics.Process]::GetProcessById($Report.worker_pid)
    $null = $process.SafeHandle # Retain the actual process object across termination/wait.
    return $process
}

function Invoke-ClassMeshWorkerRuntimeQualification([uint32]$ServiceProcessId, [string]$WorkerPath, [string]$WorkerHash) {
    $service = [Diagnostics.Process]::GetProcessById($ServiceProcessId)
    $null = $service.SafeHandle # Keep the SCM process object alive; prevent PID reuse.
    try {
    $first = Wait-ClassMeshWorkerReport $ServiceProcessId
    $worker = Assert-ClassMeshWorkerReport $first $WorkerPath $WorkerHash
    try {
        # Kill only the attested test-owned process; exercise the production watchdog.
        $worker.Kill()
        if (-not $worker.WaitForExit(5000)) { throw 'Worker test termination timed out' }
    } finally { $worker.Dispose() }
    $restarted = Wait-ClassMeshWorkerReport $ServiceProcessId $first.generation
    $worker = Assert-ClassMeshWorkerReport $restarted $WorkerPath $WorkerHash
    try {
        if ($restarted.worker_pid -eq $first.worker_pid) { throw 'Worker PID was reused during qualification; evidence ambiguous' }
        # Abrupt loss must close the real retained Service process boundary in Worker.
        if ($service.HasExited) { throw 'FAIL_CLOSED: Service exited before intentional loss test' }
        $service.Kill()
        if (-not $service.WaitForExit(5000)) { throw 'Service loss timed out' }
        if (-not $worker.WaitForExit(5000)) { throw 'FAIL_CLOSED: Worker survived Service loss' }
    } finally { $worker.Dispose() }
    [pscustomobject]@{
        service_pid = $ServiceProcessId
        first_worker_pid = $first.worker_pid
        restarted_worker_pid = $restarted.worker_pid
        first_generation = $first.generation
        restarted_generation = $restarted.generation
        decoded_worker_report = $true
        worker_restart = $true
        worker_exited_after_service_loss = $true
        physical_qualification = $false
    } | ConvertTo-Json -Compress
    } finally { $service.Dispose() }
}
