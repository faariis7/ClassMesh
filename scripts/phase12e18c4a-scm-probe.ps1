[CmdletBinding()]
param(
    [ValidateSet("Help", "Run")]
    [string]$Mode = "Help"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Mode -eq "Help") {
    @"
ClassMesh Phase 12E18c4a: DISPOSABLE SCM/LocalSystem Session0 identity probe

  .\scripts\phase12e18c4a-scm-probe.ps1 -Mode Help
  .\scripts\phase12e18c4a-scm-probe.ps1 -Mode Run

Run requires a disposable Windows test machine, an elevated interactive
administrator session (>0), and PowerShell 5.1 with .NET Framework.
It compiles and starts one unique test-only ServiceBase executable under
the REAL Windows Service Control Manager as LocalSystem. It verifies OS
process/token/session/lifetime evidence and deliberately failing identities,
stops and deletes only its own service, and deletes its temporary executable.

It does NOT open a named pipe, grant Worker control, transfer secrets,
bootstrap future v12, or execute clipboard operations. Do NOT interpret it
as positive Service-to-Worker authentication or physical two-PC evidence.
"@ | Write-Output
    return
}

if ($env:OS -ne "Windows_NT") {
    throw "This native SCM probe can only run on Windows."
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Disposable SCM probe requires an elevated Administrator token."
}
$workerPid = [Diagnostics.Process]::GetCurrentProcess().Id
$workerSession = [Diagnostics.Process]::GetCurrentProcess().SessionId
if ($workerSession -le 0 -or $identity.User.Value -eq "S-1-5-18") {
    throw "Probe requires a signed-in non-SYSTEM interactive Worker session."
}

# No existing service is ever modified. The ephemeral name and directory are
# unpredictable; no pipe, password, bearer credential or IPC channel is used.
$id = [Guid]::NewGuid().ToString("N")
$name = "ClassMeshE18c4a" + $id.Substring(0, 12)
$workDir = Join-Path $env:ProgramData ("classmesh-e18c4a-" + $id)
New-Item -ItemType Directory -Path $workDir -ErrorAction Stop | Out-Null
# LocalSystem must never execute a service binary from a directory writable
# by a standard user. Lock inherited permissions before creating the binary.
$aclOutput = & icacls.exe $workDir "/inheritance:r" "/grant:r" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" 2>&1
if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    throw "Could not lock down ephemeral SCM binary directory: $aclOutput"
}
$serviceExe = Join-Path $workDir "inert-scm-probe.exe"
$created = $false
$serviceHandle = [IntPtr]::Zero

# Compiled executable implements the genuine service entrypoint accepted by
# StartServiceCtrlDispatcher, not a scheduled task or an SC failure fallback.
$serviceSource = @'
using System;
using System.ServiceProcess;
public sealed class InertProbeService : ServiceBase {
    public InertProbeService() { ServiceName = "__SERVICE_NAME__"; CanStop = true; }
    public static void Main() { ServiceBase.Run(new InertProbeService()); }
    protected override void OnStart(string[] args) { }
    protected override void OnStop() { }
}
'@.Replace("__SERVICE_NAME__", $name)

# The observer reads the genuine OS process HANDLE and token. It does not
# authenticate a named pipe or grant a process authority.
$nativeSource = @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
public static class ClassMeshNativeScmProbe {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int processId);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint GetProcessId(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetProcessTimes(IntPtr handle, out long creation,
        out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr process, uint rights, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(IntPtr token, int infoClass,
        IntPtr buffer, uint length, out uint needed);

    public static IntPtr Pin(int processId) {
        // PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE
        IntPtr handle = OpenProcess(0x00101000, false, processId);
        if (handle == IntPtr.Zero) throw new InvalidOperationException("pin native process");
        if (GetProcessId(handle) != (uint)processId || WaitForSingleObject(handle, 0) != 0x102) {
            CloseHandle(handle);
            throw new InvalidOperationException("process mismatch or not running");
        }
        return handle;
    }

    public static long Birth(IntPtr process) {
        long creation, exit, kernel, user;
        if (!GetProcessTimes(process, out creation, out exit, out kernel, out user))
            throw new InvalidOperationException("native process creation time");
        return creation;
    }

    public static uint Session(IntPtr process) {
        uint session;
        if (!ProcessIdToSessionId(GetProcessId(process), out session))
            throw new InvalidOperationException("native process session");
        return session;
    }

    public static uint TokenSession(IntPtr process) {
        return BitConverter.ToUInt32(ReadTokenInfo(process, 12), 0);
    }

    public static string TokenUserSid(IntPtr process) {
        IntPtr token;
        if (!OpenProcessToken(process, 0x0008, out token))
            throw new InvalidOperationException("native process token query");
        try {
            uint needed = 0;
            GetTokenInformation(token, 1, IntPtr.Zero, 0, out needed);
            if (needed < IntPtr.Size || needed > 4096)
                throw new InvalidOperationException("invalid bounded TokenUser size");
            IntPtr buffer = Marshal.AllocHGlobal((int)needed);
            try {
                if (!GetTokenInformation(token, 1, buffer, needed, out needed))
                    throw new InvalidOperationException("read native TokenUser");
                return new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value;
            } finally { Marshal.FreeHGlobal(buffer); }
        } finally { CloseHandle(token); }
    }

    static byte[] ReadTokenInfo(IntPtr process, int cls) {
        IntPtr token;
        if (!OpenProcessToken(process, 0x0008, out token))
            throw new InvalidOperationException("native process token query");
        try {
            uint needed;
            GetTokenInformation(token, cls, IntPtr.Zero, 0, out needed);
            if (needed == 0 || needed > 4096)
                throw new InvalidOperationException("invalid bounded token buffer");
            IntPtr buffer = Marshal.AllocHGlobal((int)needed);
            try {
                if (!GetTokenInformation(token, cls, buffer, needed, out needed))
                    throw new InvalidOperationException("read native token info");
                byte[] copy = new byte[(int)needed];
                Marshal.Copy(buffer, copy, 0, (int)needed);
                return copy;
            } finally { Marshal.FreeHGlobal(buffer); }
        } finally { CloseHandle(token); }
    }
}
'@

function Assert-Probe {
    param([bool]$Condition, [string]$Invariant)
    if (-not $Condition) { throw "SCM_NATIVE_RED: $Invariant" }
    Write-Output "PASS: $Invariant"
}

try {
    Add-Type -TypeDefinition $serviceSource -OutputAssembly $serviceExe `
        -OutputType ConsoleApplication -ReferencedAssemblies "System.ServiceProcess.dll" -ErrorAction Stop
    Add-Type -TypeDefinition $nativeSource -ErrorAction Stop

    # LocalSystem is explicit; service type is own-process, non-interactive.
    $quotedExecutable = '"' + $serviceExe + '"'
    $createOutput = & sc.exe create $name "binPath=" $quotedExecutable "start=" "demand" "type=" "own" "obj=" "LocalSystem" 2>&1
    if ($LASTEXITCODE -ne 0) { throw "sc create failed: $createOutput" }
    $created = $true
    Start-Service -Name $name -ErrorAction Stop

    $service = $null
    $deadline = [DateTime]::UtcNow.AddSeconds(12)
    do {
        $service = Get-CimInstance Win32_Service -Filter ("Name='" + $name + "'")
        if ($null -ne $service -and $service.State -eq "Running" -and $service.ProcessId -gt 0) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)

    Assert-Probe ($null -ne $service -and $service.State -eq "Running") "real SCM service entered Running"
    Assert-Probe ($service.StartName -in @("LocalSystem", "NT AUTHORITY\SYSTEM")) "SCM configured actual LocalSystem"
    $servicePid = [int]$service.ProcessId
    $serviceHandle = [ClassMeshNativeScmProbe]::Pin($servicePid)
    $serviceBirth = [ClassMeshNativeScmProbe]::Birth($serviceHandle)
    $serviceSession = [ClassMeshNativeScmProbe]::Session($serviceHandle)
    $serviceTokenSession = [ClassMeshNativeScmProbe]::TokenSession($serviceHandle)
    $serviceSid = [ClassMeshNativeScmProbe]::TokenUserSid($serviceHandle)

    Assert-Probe ([ClassMeshNativeScmProbe]::GetProcessId($serviceHandle) -eq $servicePid) "pinned native HANDLE equals live SCM PID"
    Assert-Probe ([ClassMeshNativeScmProbe]::WaitForSingleObject($serviceHandle, 0) -eq 0x102) "real SCM process HANDLE is live"
    Assert-Probe ($serviceSid -eq "S-1-5-18") "native service TokenUser is LocalSystem"
    Assert-Probe ($serviceSession -eq 0 -and $serviceTokenSession -eq 0) "native service process AND token are Session0"

    $workerHandle = [ClassMeshNativeScmProbe]::Pin($workerPid)
    try {
        Assert-Probe ([ClassMeshNativeScmProbe]::Session($workerHandle) -eq [uint32]$workerSession) "native client session equals interactive session"
        Assert-Probe ([ClassMeshNativeScmProbe]::TokenUserSid($workerHandle) -ne "S-1-5-18") "interactive Worker client rejects LocalSystem SID"
        Assert-Probe ([ClassMeshNativeScmProbe]::TokenSession($workerHandle) -gt 0) "native Worker token is not Session0"
        Assert-Probe ([ClassMeshNativeScmProbe]::TokenUserSid($workerHandle) -ne $serviceSid) "native Worker/Service SIDs differ"
        Assert-Probe ([ClassMeshNativeScmProbe]::Session($workerHandle) -ne $serviceSession) "native Worker/Service sessions differ"
        Assert-Probe ([ClassMeshNativeScmProbe]::Birth($workerHandle) -ne $serviceBirth) "native Worker cannot impersonate Service creation stamp"
    } finally {
        [void][ClassMeshNativeScmProbe]::CloseHandle($workerHandle)
    }
    Assert-Probe ($serviceSession -ne [uint32]$workerSession) "deliberate wrong expected Service session rejected"
    Assert-Probe ($serviceBirth -ne ($serviceBirth + 1)) "deliberate wrong Service birth stamp rejected"

    # Stop the exact uniquely named test service, then prove the PINNED handle
    # is signaled: a PID that used to be trusted must not remain authorized.
    Stop-Service -Name $name -ErrorAction Stop
    $exitWait = [ClassMeshNativeScmProbe]::WaitForSingleObject($serviceHandle, 12000)
    Assert-Probe ($exitWait -eq 0) "stopped SCM process fails live-HANDLE check"
    Write-Output "SCM_SESSION0_NATIVE_INERT_PASS"
    Write-Output "NOT_AUTHENTICATED_V12_NOT_PIPE_NOT_CLIPBOARD"
} finally {
    if ($serviceHandle -ne [IntPtr]::Zero) {
        [void][ClassMeshNativeScmProbe]::CloseHandle($serviceHandle)
    }
    if ($created) {
        try {
            $present = Get-Service -Name $name -ErrorAction SilentlyContinue
            if ($null -ne $present -and $present.Status -ne "Stopped") {
                & sc.exe stop $name 2>&1 | Out-Null
                $present.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(12))
            }
        } catch {
            Write-Warning "Could not confirm bounded test service stop: $name"
        } finally {
            & sc.exe delete $name 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Test-only service deletion not confirmed: $name"
            }
        }
    }
    if (Test-Path -LiteralPath $workDir) {
        Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
