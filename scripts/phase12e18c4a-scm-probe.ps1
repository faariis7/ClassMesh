[CmdletBinding()]
param(
    [ValidateSet("Help", "Run", "Pipe", "DenyLocalService")]
    [string]$Mode = "Help"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Mode -eq "Help") {
    @"
ClassMesh Phase 12E18c4a/c4b: DISPOSABLE SCM/Session0 native probe

  .\scripts\phase12e18c4a-scm-probe.ps1 -Mode Help
  .\scripts\phase12e18c4a-scm-probe.ps1 -Mode Run
  .\scripts\phase12e18c4a-scm-probe.ps1 -Mode Pipe
  .\scripts\phase12e18c4a-scm-probe.ps1 -Mode DenyLocalService

Run, Pipe and DenyLocalService require a disposable Windows test machine, an elevated interactive
administrator session (>0), and PowerShell 5.1 with .NET Framework.
It compiles and starts one unique test-only ServiceBase executable under
the REAL Windows Service Control Manager as LocalSystem. It verifies OS
process/token/session/lifetime evidence and deliberately failing identities,
stops and deletes only its own service, and deletes its temporary executable.

Pipe opens one inert, one-instance native OUTBOUND pipe with explicit
SYSTEM + current-user read ACL and rejects remote clients; no payload is sent.
DenyLocalService additionally starts an SCM LocalService (S-1-5-19)
service which must get ERROR_ACCESS_DENIED on the pipe before the authorized
client connects. None of these modes authenticate v12, prove a normal
Service-launched Worker, grant Worker control, or read clipboard.
No physical two-PC acceptance is claimed.
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

# No existing service is ever modified. Public pipe metadata is unique and
# non-bearer; no password, privileged grant or sensitive payload is used.
$id = [Guid]::NewGuid().ToString("N")
$name = "ClassMeshE18c4a" + $id.Substring(0, 12)
$pipeName = "ClassMeshE18c4b" + $id.Substring(0, 12)
$deniedName = "ClassMeshE18c4c" + $id.Substring(0, 12)
$pipePath = "\\.\pipe\$pipeName"
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
$pipeHandle = [IntPtr]::Zero
$deniedHandle = [IntPtr]::Zero
$deniedCreated = $false
$pipeProbe = $Mode -in @("Pipe", "DenyLocalService")

# Native pipe exists in the real SCM-controlled SYSTEM service only in Pipe
# mode; Run remains the original inert topology probe.
$serviceExtras = ""
$startBody = ""
$stopBody = ""
if ($pipeProbe) {
    $serviceExtras = @'
    [StructLayout(LayoutKind.Sequential)]
    struct NativeSecurityAttributes {
        public uint nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
    }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true,
        EntryPoint="ConvertStringSecurityDescriptorToSecurityDescriptorW")]
    static extern bool ConvertSddl(string sddl, uint revision, out IntPtr descriptor, out uint size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true,
        EntryPoint="CreateNamedPipeW")]
    static extern IntPtr CreateNativePipe(string path, uint openMode, uint pipeMode,
        uint instances, uint outBytes, uint inBytes, uint timeout, ref NativeSecurityAttributes attr);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    private IntPtr pipe = IntPtr.Zero;
'@
    $startBody = @'
        // The DACL is PROTECTED, has no Everyone/Anonymous ACE, and grants
        // full access only to SYSTEM, and read-only access to this exact SID.
        string sddl = "D:P(A;;GA;;;SY)(A;;GR;;;__CLIENT_SID__)";
        IntPtr descriptor = IntPtr.Zero;
        uint descriptorSize;
        if (!ConvertSddl(sddl, 1, out descriptor, out descriptorSize))
            throw new InvalidOperationException("explicit native pipe DACL");
        try {
            NativeSecurityAttributes attributes = new NativeSecurityAttributes();
            attributes.nLength = (uint)Marshal.SizeOf(typeof(NativeSecurityAttributes));
            attributes.lpSecurityDescriptor = descriptor;
            attributes.bInheritHandle = false;
            // PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE;
            // PIPE_REJECT_REMOTE_CLIENTS; one server instance; NO payload.
            pipe = CreateNativePipe(@"\\.\pipe\__PIPE_NAME__",
                0x00080002, 0x00000008, 1, 256, 256, 1000, ref attributes);
            if (pipe == IntPtr.Zero || pipe == new IntPtr(-1))
                throw new InvalidOperationException("restricted native pipe creation");
        } finally {
            if (descriptor != IntPtr.Zero) LocalFree(descriptor);
        }
'@
    $stopBody = @'
        if (pipe != IntPtr.Zero && pipe != new IntPtr(-1)) {
            CloseHandle(pipe);
            pipe = IntPtr.Zero;
        }
'@
}

# Additional real SCM identity: LocalService tries to open the existing
# SYSTEM-owned pipe before the intended interactive SID. It sends zero data.
$deniedClass = ""
$mainBody = "ServiceBase.Run(new InertProbeService());"
if ($Mode -eq "DenyLocalService") {
    $deniedClass = @'
public sealed class DeniedClientService : ServiceBase {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true,
        EntryPoint="CreateFileW")]
    static extern IntPtr OpenNativePipe(string path, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    public DeniedClientService() { ServiceName = "__DENIED_NAME__"; CanStop = true; }
    protected override void OnStart(string[] args) {
        // Same desired READ access and security SQOS as intended user.
        IntPtr handle = OpenNativePipe(@"\\.\pipe\__PIPE_NAME__",
            0x80000000, 0, IntPtr.Zero, 3, 0x00110000, IntPtr.Zero);
        int error = Marshal.GetLastWin32Error();
        if (handle != IntPtr.Zero && handle != new IntPtr(-1)) {
            CloseHandle(handle);
            throw new InvalidOperationException("security FAIL: wrong user opened pipe");
        }
        if (error != 5) {
            throw new InvalidOperationException(
                "security FAIL: wrong-user error not ACCESS_DENIED, code " + error);
        }
    }
    protected override void OnStop() { }
}
'@
    $mainBody = @'
if (args.Length == 1 && args[0] == "--wrong-user")
    ServiceBase.Run(new DeniedClientService());
else
    ServiceBase.Run(new InertProbeService());
'@
}

# Compiled executable implements the genuine service entrypoint accepted by
# StartServiceCtrlDispatcher, not a scheduled task or SC failure fallback.
$serviceSource = @'
using System;
using System.Runtime.InteropServices;
using System.ServiceProcess;
public sealed class InertProbeService : ServiceBase {
__EXTRA_NATIVE__
    public InertProbeService() { ServiceName = "__SERVICE_NAME__"; CanStop = true; }
    public static void Main(string[] args) {
__MAIN_BODY__
    }
    protected override void OnStart(string[] args) {
__START_BODY__
    }
    protected override void OnStop() {
__STOP_BODY__
    }
}
__DENIED_CLASS__
'@.Replace("__SERVICE_NAME__", $name).
    Replace("__EXTRA_NATIVE__", $serviceExtras).
    Replace("__MAIN_BODY__", $mainBody).
    Replace("__START_BODY__", $startBody).
    Replace("__STOP_BODY__", $stopBody).
    Replace("__DENIED_CLASS__", $deniedClass).
    Replace("__DENIED_NAME__", $deniedName).
    Replace("__CLIENT_SID__", $identity.User.Value).
    Replace("__PIPE_NAME__", $pipeName)

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
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true,
        EntryPoint="CreateFileW")]
    public static extern IntPtr OpenPipe(string path, uint access, uint share,
        IntPtr securityAttributes, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverPid);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetNamedPipeServerSessionId(IntPtr pipe, out uint serverSession);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true,
        EntryPoint="CreateNamedPipeW")]
    public static extern IntPtr TryFirstInstance(string name, uint openMode, uint pipeMode,
        uint instances, uint outBytes, uint inBytes, uint timeout, IntPtr securityAttributes);

    public static int LastPipeOpenError;
    public static IntPtr OpenReadonlyClient(string name) {
        // GENERIC_READ, OPEN_EXISTING, SECURITY_SQOS_PRESENT | IDENTIFICATION.
        IntPtr handle = OpenPipe(name, 0x80000000, 0, IntPtr.Zero, 3,
            0x00110000, IntPtr.Zero);
        LastPipeOpenError = (handle == IntPtr.Zero || handle == new IntPtr(-1))
            ? Marshal.GetLastWin32Error() : 0;
        return handle;
    }

    public static bool FirstInstanceCollisionDenied(string name) {
        IntPtr attempt = TryFirstInstance(name, 0x00080002, 0x00000008,
            1, 256, 256, 1000, IntPtr.Zero);
        int error = Marshal.GetLastWin32Error();
        if (attempt != new IntPtr(-1) && attempt != IntPtr.Zero) {
            CloseHandle(attempt);
            return false;
        }
        // ERROR_ACCESS_DENIED is the documented first-instance conflict;
        // do NOT pass an invalid-path or other unexpected native error.
        return error == 5;
    }

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
    if ($Mode -eq "DenyLocalService") {
        # Grant LocalService read/execute on the test binary, NEVER write.
        # The directory stays non-writable to this adversarial OS identity.
        $rx = & icacls.exe $workDir "/grant:r" "*S-1-5-19:(OI)(CI)RX" 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Unable to grant LocalService RX: $rx" }
    }
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

    if ($pipeProbe) {
        if ($Mode -eq "DenyLocalService") {
            # An OS account other than SYSTEM AND the intended target user:
            # real SCM LocalService, not a forged SID string in our process.
            $deniedPath = '"' + $serviceExe + '" --wrong-user'
            $denyCreate = & sc.exe create $deniedName "binPath=" $deniedPath `
                "start=" "demand" "type=" "own" "obj=" "NT AUTHORITY\LocalService" 2>&1
            if ($LASTEXITCODE -ne 0) { throw "wrong-user sc create failed: $denyCreate" }
            $deniedCreated = $true
            Start-Service -Name $deniedName -ErrorAction Stop
            $wrong = Get-CimInstance Win32_Service -Filter ("Name='" + $deniedName + "'")
            Assert-Probe ($null -ne $wrong -and $wrong.State -eq "Running" -and
                $wrong.ProcessId -gt 0) "wrong-OS-SID SCM Service started only after exact ACCESS_DENIED"
            Assert-Probe ($wrong.StartName -in @("NT AUTHORITY\LocalService", "LocalService")) "wrong client SCM identity is LocalService"
            $deniedHandle = [ClassMeshNativeScmProbe]::Pin([int]$wrong.ProcessId)
            Assert-Probe ([ClassMeshNativeScmProbe]::TokenUserSid($deniedHandle) -eq "S-1-5-19") "actual wrong client TokenUser is LocalService SID"
            Assert-Probe ([ClassMeshNativeScmProbe]::Session($deniedHandle) -eq 0 -and
                [ClassMeshNativeScmProbe]::TokenSession($deniedHandle) -eq 0) "real wrong client service runs in Session0"
            Assert-Probe ([ClassMeshNativeScmProbe]::WaitForSingleObject($deniedHandle, 0) -eq 0x102 -and
                [ClassMeshNativeScmProbe]::GetProcessId($deniedHandle) -eq [uint32]$wrong.ProcessId) "wrong-identity process HANDLE remains pinned and live"
            Assert-Probe ([ClassMeshNativeScmProbe]::TokenUserSid($deniedHandle) -ne $serviceSid -and
                [ClassMeshNativeScmProbe]::TokenUserSid($deniedHandle) -ne $identity.User.Value) "unauthorized OS account is distinct from server and intended user"
            Stop-Service -Name $deniedName -ErrorAction Stop
            Assert-Probe ([ClassMeshNativeScmProbe]::WaitForSingleObject($deniedHandle, 12000) -eq 0) "wrong-user service process exited and pinned handle is dead"
            [void][ClassMeshNativeScmProbe]::CloseHandle($deniedHandle)
            $deniedHandle = [IntPtr]::Zero
        }

        # Probe the actual, local, non-secret pipe client HANDLE; do not trust
        # the public pipe name as an authentication credential.
        $pipeDeadline = [DateTime]::UtcNow.AddSeconds(8)
        do {
            $pipeHandle = [ClassMeshNativeScmProbe]::OpenReadonlyClient($pipePath)
            if ($pipeHandle -ne [IntPtr]::Zero -and $pipeHandle -ne [IntPtr](-1)) { break }
            Start-Sleep -Milliseconds 120
        } while ([DateTime]::UtcNow -lt $pipeDeadline)
        if ($pipeHandle -eq [IntPtr]::Zero -or $pipeHandle -eq [IntPtr](-1)) {
            Write-Output ("NATIVE_PIPE_OPEN_LAST_WIN32_ERROR=" + [ClassMeshNativeScmProbe]::LastPipeOpenError)
        }
        Assert-Probe ($pipeHandle -ne [IntPtr]::Zero -and $pipeHandle -ne [IntPtr](-1)) "target SID can open real LocalSystem outbound pipe"
        [uint32]$reportedPid = 0
        [uint32]$reportedSession = 4294967295
        Assert-Probe ([ClassMeshNativeScmProbe]::GetNamedPipeServerProcessId($pipeHandle, [ref]$reportedPid)) "pipe OS reports server process ID"
        Assert-Probe ([ClassMeshNativeScmProbe]::GetNamedPipeServerSessionId($pipeHandle, [ref]$reportedSession)) "pipe OS reports server Windows session"
        Assert-Probe ($reportedPid -eq [uint32]$servicePid) "pipe OS server PID matches owned SCM Service process HANDLE"
        Assert-Probe ($reportedSession -eq 0 -and $reportedSession -eq $serviceSession) "pipe OS server Session0 matches live SCM token"
        Assert-Probe ([ClassMeshNativeScmProbe]::GetProcessId($serviceHandle) -eq $reportedPid -and
            [ClassMeshNativeScmProbe]::WaitForSingleObject($serviceHandle, 0) -eq 0x102 -and
            [ClassMeshNativeScmProbe]::Birth($serviceHandle) -eq $serviceBirth) "pipe server PID still pinned to living original SCM birth stamp"
        $scmAgain = Get-CimInstance Win32_Service -Filter ("Name='" + $name + "'")
        Assert-Probe ($null -ne $scmAgain -and $scmAgain.State -eq "Running" -and
            $scmAgain.ProcessId -eq $reportedPid) "SCM still reports same running Service after peer query"
        Assert-Probe ([ClassMeshNativeScmProbe]::FirstInstanceCollisionDenied($pipePath)) "second native pipe instance denied (first-instance or restricted ACL)"
        Assert-Probe ($reportedPid -ne [uint32]$workerPid -and $reportedSession -ne [uint32]$workerSession) "interactive non-SYSTEM decoy cannot satisfy native pipe server identity"
        [void][ClassMeshNativeScmProbe]::CloseHandle($pipeHandle)
        $pipeHandle = [IntPtr]::Zero
    }

    # Stop the exact uniquely named test service, then prove the PINNED handle
    # is signaled: a PID that used to be trusted must not remain authorized.
    Stop-Service -Name $name -ErrorAction Stop
    $exitWait = [ClassMeshNativeScmProbe]::WaitForSingleObject($serviceHandle, 12000)
    Assert-Probe ($exitWait -eq 0) "stopped SCM process fails live-HANDLE check"
    if ($pipeProbe) {
        $stale = [ClassMeshNativeScmProbe]::OpenReadonlyClient($pipePath)
        $staleDenied = ($stale -eq [IntPtr]::Zero -or $stale -eq [IntPtr](-1))
        if (-not $staleDenied) { [void][ClassMeshNativeScmProbe]::CloseHandle($stale) }
        Assert-Probe $staleDenied "stale outbound pipe refuses new client after SCM Service death"
        if ($Mode -eq "DenyLocalService") {
            Write-Output "SCM_LOCAL_SERVICE_WRONG_SID_ACL_DENY_PASS"
        } else {
            Write-Output "SCM_SESSION0_NATIVE_PIPE_INERT_PASS"
        }
    } else {
        Write-Output "SCM_SESSION0_NATIVE_INERT_PASS"
    }
    Write-Output "NOT_AUTHENTICATED_V12_NOT_PIPE_NOT_CLIPBOARD"
} finally {
    if ($deniedHandle -ne [IntPtr]::Zero) {
        [void][ClassMeshNativeScmProbe]::CloseHandle($deniedHandle)
    }
    if ($deniedCreated) {
        try {
            $wrongService = Get-Service -Name $deniedName -ErrorAction SilentlyContinue
            if ($null -ne $wrongService -and $wrongService.Status -ne "Stopped") {
                & sc.exe stop $deniedName 2>&1 | Out-Null
                $wrongService.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(12))
            }
        } catch {
            Write-Warning "Could not confirm bounded wrong-user test service stop: $deniedName"
        } finally {
            & sc.exe delete $deniedName 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Wrong-user test service deletion not confirmed: $deniedName"
            }
        }
    }
    if ($pipeHandle -ne [IntPtr]::Zero -and $pipeHandle -ne [IntPtr](-1)) {
        [void][ClassMeshNativeScmProbe]::CloseHandle($pipeHandle)
    }
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
