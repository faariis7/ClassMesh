[CmdletBinding()]
param(
    [ValidateSet("Help", "Run", "Pipe", "DenyLocalService", "LaunchWorker", "CancelConnect", "WorkerPipePositive", "WorkerPipeDecoy", "WorkerPipeDeath")]
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
  .\scripts\phase12e18c4a-scm-probe.ps1 -Mode LaunchWorker
  .\scripts\phase12e18c4a-scm-probe.ps1 -Mode CancelConnect
  .\scripts\phase12e18c4a-scm-probe.ps1 -Mode WorkerPipePositive
  .\scripts\phase12e18c4a-scm-probe.ps1 -Mode WorkerPipeDecoy
  .\scripts\phase12e18c4a-scm-probe.ps1 -Mode WorkerPipeDeath

Run, Pipe, DenyLocalService, LaunchWorker and CancelConnect require a disposable Windows test machine, an elevated interactive
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
LaunchWorker uses WTSQueryUserToken + CreateProcessAsUser under true SCM SYSTEM
 to launch one inert signed-in user child; checks native parent PID and
 non-elevated token. Worker pipe identity/control remains a separate gate.
CancelConnect uses true LocalSystem SCM to prove native pending OVERLAPPED pipe
 connect cancellation + kernel completion drain without a client or payload.
WorkerPipePositive and WorkerPipeDecoy test genuine SCM-launched Worker
 process identity versus the kernel-reported inbound pipe client process PID.
 Neither mode sends or accepts any payload or authentication credential.
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
$launchedHandle = [IntPtr]::Zero
$witnessFile = Join-Path $workDir "launched-worker.witness"
$cancelWitness = Join-Path $workDir "cancel-connect.witness"
$peerWitness = Join-Path $workDir "worker-pipe.witness"
$deathWitness = Join-Path $workDir "worker-death.witness"
$workerPipeMode = $Mode -in @("WorkerPipePositive", "WorkerPipeDecoy", "WorkerPipeDeath")
$launchMode = $Mode -eq "LaunchWorker" -or $workerPipeMode
$pipeOpenMode = if ($Mode -eq "CancelConnect" -or $workerPipeMode) { "0x40080002" } else { "0x00080002" }
$pipeProbe = $Mode -in @("Pipe", "DenyLocalService", "CancelConnect") -or $workerPipeMode

# Native pipe exists in the real SCM-controlled SYSTEM service only in Pipe
# mode; Run remains the original inert topology probe.
$serviceExtras = ""
$startBody = ""
$stopBody = ""
$mainBody = "ServiceBase.Run(new InertProbeService());"
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
                __PIPE_OPEN_MODE__, 0x00000008, 1, 256, 256, 1000, ref attributes);
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



if ($Mode -eq "CancelConnect") {
    # A genuine no-client SCM Session0 asynchronous connection. Do not use
    # managed movable buffers for OS-owned pending OVERLAPPED state.
    $serviceExtras += @'
    [StructLayout(LayoutKind.Sequential)]
    struct PendingConnectOverlap {
        public IntPtr internalPtr;
        public IntPtr internalHigh;
        public uint offset;
        public uint offsetHigh;
        public IntPtr eventHandle;
    }
    [DllImport("kernel32.dll", SetLastError=true, EntryPoint="CreateEventW",
        CharSet=CharSet.Unicode)]
    static extern IntPtr CreateNativeEvent(IntPtr attr, bool manualReset,
        bool initiallySignaled, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool ConnectNamedPipe(IntPtr pipe, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CancelIoEx(IntPtr pipe, IntPtr overlapped);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetOverlappedResult(IntPtr pipe, IntPtr overlapped,
        out uint transferred, bool wait);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    private readonly System.Threading.ManualResetEvent connectDone =
        new System.Threading.ManualResetEvent(false);
    void QualifyNoClientCancellation() {
        IntPtr nativeEvent = IntPtr.Zero;
        IntPtr stableOverlapped = IntPtr.Zero;
        bool pendingUndrained = false;
        try {
            nativeEvent = CreateNativeEvent(IntPtr.Zero, true, false, null);
            if (nativeEvent == IntPtr.Zero || nativeEvent == new IntPtr(-1))
                throw new InvalidOperationException("manual-reset native event");
            PendingConnectOverlap state = new PendingConnectOverlap();
            state.eventHandle = nativeEvent;
            stableOverlapped = Marshal.AllocHGlobal(
                Marshal.SizeOf(typeof(PendingConnectOverlap)));
            Marshal.StructureToPtr(state, stableOverlapped, false);
            bool immediate = ConnectNamedPipe(pipe, stableOverlapped);
            int connectError = Marshal.GetLastWin32Error();
            if (immediate || connectError != 997)
                throw new InvalidOperationException("security RED: no genuine pending ConnectNamedPipe");
            pendingUndrained = true;
            // Deliberately no client. The pending OS request MUST time out.
            uint wait = WaitForSingleObject(nativeEvent, 750);
            if (wait != 0x102)
                throw new InvalidOperationException("security RED: pending connect not timed out");
            bool cancel = CancelIoEx(pipe, stableOverlapped);
            int cancelError = Marshal.GetLastWin32Error();
            if (!cancel && cancelError != 1168)
                throw new InvalidOperationException("targeted CancelIoEx failed");
            uint transferred;
            // This drain is REQUIRED before reusing/freeing the native memory.
            bool completed = GetOverlappedResult(
                pipe, stableOverlapped, out transferred, true);
            int finalError = Marshal.GetLastWin32Error();
            pendingUndrained = false;
            if (completed || finalError != 995)
                throw new InvalidOperationException("security RED: canceled I/O not aborted");
            System.IO.File.WriteAllText(@"__CANCEL_WITNESS__", "CANCELLED_AND_DRAINED");
        } catch {
            // A single nonsensitive status flag: no HANDLE or SID in artifacts.
            try { System.IO.File.WriteAllText(@"__CANCEL_WITNESS__", "RED"); }
            catch { }
        } finally {
            if (pendingUndrained && stableOverlapped != IntPtr.Zero) {
                // Exception path must likewise drain the exact pending OS I/O.
                CancelIoEx(pipe, stableOverlapped);
                uint ignored;
                GetOverlappedResult(pipe, stableOverlapped, out ignored, true);
            }
            if (stableOverlapped != IntPtr.Zero) Marshal.FreeHGlobal(stableOverlapped);
            if (nativeEvent != IntPtr.Zero && nativeEvent != new IntPtr(-1))
                CloseHandle(nativeEvent);
            connectDone.Set();
        }
    }
'@
    $startBody += @'
        System.Threading.ThreadPool.QueueUserWorkItem(
            delegate(object ignored) { QualifyNoClientCancellation(); });
'@
    # Existing base stop body closes pipe only AFTER the dedicated cancellation
    # has reported completion and released its native pending I/O storage.
    $stopBody = @'
        if (!connectDone.WaitOne(5000))
            throw new InvalidOperationException("security RED: pending connect did not drain");
        connectDone.Dispose();
'@ + $stopBody
}

if ($launchMode) {
    # OS-created SYSTEM -> real signed-in user child, with a protected public
    # lifetime witness. This DOES NOT authenticate a pipe or Worker grants.
    $serviceExtras += @'
    [DllImport("wtsapi32.dll", SetLastError=true)]
    static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode,
        EntryPoint="CreateProcessAsUserW")]
    static extern bool CreateProcessAsUser(IntPtr token, string application,
        System.Text.StringBuilder commandLine, IntPtr processAttributes,
        IntPtr threadAttributes, bool inheritHandles, uint creationFlags,
        IntPtr environment, string currentDirectory, ref NativeStartupInfo startup,
        out NativeProcessInfo information);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetProcessTimes(IntPtr process, out long creation,
        out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", EntryPoint="CloseHandle", SetLastError=true)]
    static extern bool CloseLaunchedHandle(IntPtr handle);
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    struct NativeStartupInfo {
        public uint cb;
        public string reserved;
        public string desktop;
        public string title;
        public uint x, y, xsize, ysize, xcount, ycount, fill, flags;
        public ushort show;
        public ushort reserved2;
        public IntPtr reservedPtr, stdin, stdout, stderr;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct NativeProcessInfo {
        public IntPtr process;
        public IntPtr thread;
        public uint id, threadId;
    }
    private IntPtr launchedProcess = IntPtr.Zero;
    private uint launchedPid = 0;
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true,
        EntryPoint="CreateFileW")]
    static extern IntPtr OpenInteractivePipe(string path, uint access,
        uint share, IntPtr sec, uint disposition, uint flags, IntPtr template);
    static void InteractiveWorker(string[] args) {
        if (args.Length >= 3 && args[1] == "--client-pipe") {
            // Signed-in medium-integrity child opens an inert read-only handle.
            // The SYSTEM service MUST still independently attest its native PID.
            IntPtr client = new IntPtr(-1);
            for (int n = 0; n < 80; n++) {
                client = OpenInteractivePipe(@"\\.\pipe\" + args[2],
                    0x80000000, 0, IntPtr.Zero, 3, 0x00110000, IntPtr.Zero);
                if (client != IntPtr.Zero && client != new IntPtr(-1)) break;
                System.Threading.Thread.Sleep(100);
            }
            if (client == IntPtr.Zero || client == new IntPtr(-1))
                throw new InvalidOperationException("inert Worker could not open pipe");
            // No payload: death mode deliberately completes the process
            // naturally after a bounded time, after observer pins its HANDLE.
            try { System.Threading.Thread.Sleep(
                args.Length == 4 && args[3] == "--self-expire" ? 12000 : 20000); }
            finally { CloseLaunchedHandle(client); }
        } else {
            // WorkerPipeDecoy starts only this sleeping, real owned child.
            System.Threading.Thread.Sleep(60000);
        }
    }
    void StartInteractiveWorker() {
        IntPtr userToken = IntPtr.Zero;
        if (!WTSQueryUserToken(__SESSION_ID__, out userToken))
            throw new InvalidOperationException("SCM SYSTEM WTSQueryUserToken failed");
        try {
            string sid = new System.Security.Principal.WindowsIdentity(userToken).User.Value;
            if (sid != "__CLIENT_SID__" || sid == "S-1-5-18")
                throw new InvalidOperationException("signed-in user SID mismatch");
            NativeStartupInfo startup = new NativeStartupInfo();
            startup.cb = (uint)Marshal.SizeOf(typeof(NativeStartupInfo));
            startup.desktop = @"winsta0\default";
            NativeProcessInfo child;
            string executable = @"__EXE_PATH__";
            var arguments = new System.Text.StringBuilder(
                "\"" + executable + "\" --interactive-worker__WORKER_CLIENT_ARGS__");
            // CreateProcessAsUser inherits the calling LocalSystem SERVICE
            // environment when lpEnvironment is NULL. Supply a tiny Unicode
            // block so its non-elevated Worker never receives Service vars.
            // One explicit NUL plus the marshaler terminator = double NUL.
            IntPtr cleanEnvironment = Marshal.StringToHGlobalUni(
                "SystemRoot=" + Environment.GetEnvironmentVariable("SystemRoot") + "\0");
            try {
                // CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT
                if (!CreateProcessAsUser(userToken, executable, arguments,
                    IntPtr.Zero, IntPtr.Zero, false, 0x08000400,
                    cleanEnvironment, null, ref startup, out child))
                    throw new InvalidOperationException("SCM CreateProcessAsUser failed " + Marshal.GetLastWin32Error());
            } finally { Marshal.FreeHGlobal(cleanEnvironment); }
            launchedProcess = child.process;
            launchedPid = child.id;
            CloseLaunchedHandle(child.thread);
            if (launchedPid == 0 || launchedProcess == IntPtr.Zero ||
                WaitForSingleObject(launchedProcess, 0) != 0x102)
                throw new InvalidOperationException("SCM-created Worker not live");
            long born, exited, kernel, user;
            if (!GetProcessTimes(launchedProcess, out born,
                out exited, out kernel, out user))
                throw new InvalidOperationException("SCM Worker birth FILETIME absent");
            // Public non-bearer metadata only. The child has RX, not WRITE, on
            // the directory. Observer rechecks original pinned native HANDLE.
            System.IO.File.WriteAllText(@"__WITNESS_PATH__",
                launchedPid + "|" + born + "|" + __SESSION_ID__);
        } finally { if (userToken != IntPtr.Zero) CloseLaunchedHandle(userToken); }
    }
'@
    $startBody += @'
        StartInteractiveWorker();
'@
    $stopBody += @'
        if (launchedProcess != IntPtr.Zero && launchedProcess != new IntPtr(-1)) {
            if (WaitForSingleObject(launchedProcess, 0) == 0x102) {
                TerminateProcess(launchedProcess, 0);
                WaitForSingleObject(launchedProcess, 5000);
            }
            CloseLaunchedHandle(launchedProcess);
            launchedProcess = IntPtr.Zero;
        }
'@
    $mainBody = @'
if (args.Length >= 1 && args[0] == "--interactive-worker")
    InteractiveWorker(args);
else
    ServiceBase.Run(new InertProbeService());
'@
}


if ($workerPipeMode) {
    # OS CLIENT PID/session is acquired from the ALREADY-CONNECTED native
    # pipe; the expected PID and process birth come from the SERVICE-owned
    # exact HANDLE returned by CreateProcessAsUser, not an observer's claim.
    $serviceExtras += @'
    [StructLayout(LayoutKind.Sequential)]
    struct WorkerPipeOverlap {
        public IntPtr internalPtr, internalHigh;
        public uint offset, offsetHigh;
        public IntPtr eventHandle;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode,
        EntryPoint="CreateEventW", SetLastError=true)]
    static extern IntPtr CreateWorkerEvent(IntPtr attr, bool manual,
        bool initial, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool ConnectNamedPipe(IntPtr pipe, IntPtr overlap);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CancelIoEx(IntPtr pipe, IntPtr overlap);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetOverlappedResult(IntPtr pipe, IntPtr overlap,
        out uint done, bool wait);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientPid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetNamedPipeClientSessionId(IntPtr pipe, out uint sessionId);
    private readonly bool simulateWorkerExpiry = __SELF_EXPIRE_MODE__;
    private readonly System.Threading.ManualResetEvent workerPeerDone =
        new System.Threading.ManualResetEvent(false);
    void AttestNativeWorkerPeer() {
        IntPtr nativeEvent = IntPtr.Zero;
        IntPtr overlap = IntPtr.Zero;
        bool ioUndrained = false;
        try {
            nativeEvent = CreateWorkerEvent(IntPtr.Zero, true, false, null);
            if (nativeEvent == IntPtr.Zero || nativeEvent == new IntPtr(-1))
                throw new InvalidOperationException("native peer event failed");
            WorkerPipeOverlap state = new WorkerPipeOverlap();
            state.eventHandle = nativeEvent;
            overlap = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WorkerPipeOverlap)));
            Marshal.StructureToPtr(state, overlap, false);
            bool immediate = ConnectNamedPipe(pipe, overlap);
            int error = Marshal.GetLastWin32Error();
            if (!immediate && error == 997) {
                ioUndrained = true;
                uint wait = WaitForSingleObject(nativeEvent, 7000);
                if (wait == 0) {
                    uint transferred;
                    bool complete = GetOverlappedResult(pipe, overlap, out transferred, false);
                    int finalError = Marshal.GetLastWin32Error();
                    ioUndrained = false;
                    if (!complete) throw new InvalidOperationException(
                        "native connect completion error " + finalError);
                } else {
                    // Timeout/unexpected wait: targeted cancel then exact
                    // kernel completion drain BEFORE the allocation is freed.
                    CancelIoEx(pipe, overlap);
                    uint ignored;
                    GetOverlappedResult(pipe, overlap, out ignored, true);
                    ioUndrained = false;
                    throw new InvalidOperationException("native peer connect timeout");
                }
            } else if (!immediate && error != 535) {
                throw new InvalidOperationException("native connect failed " + error);
            }
            uint reportedPid = 0, reportedSession = 0;
            if (!GetNamedPipeClientProcessId(pipe, out reportedPid) ||
                !GetNamedPipeClientSessionId(pipe, out reportedSession))
                throw new InvalidOperationException("native kernel client OS identity unavailable");
            bool sourceAlive = launchedProcess != IntPtr.Zero &&
                launchedProcess != new IntPtr(-1) &&
                WaitForSingleObject(launchedProcess, 0) == 0x102;
            uint ownedPid = launchedPid;
            long born, exited, kernel, user;
            if (!sourceAlive ||
                !GetProcessTimes(launchedProcess, out born, out exited, out kernel, out user))
                throw new InvalidOperationException("original SCM-launched Worker dead");
            if (reportedSession != __SESSION_ID__)
                throw new InvalidOperationException("wrong native interactive session");
            if (reportedPid == ownedPid && reportedPid != 0) {
                System.IO.File.WriteAllText(@"__PEER_WITNESS__",
                    "MATCHED|" + reportedPid + "|" + born + "|" + reportedSession);
                if (simulateWorkerExpiry) {
                    // The peer was valid at connection, but its original OS
                    // process may die. A stale accepted PID cannot remain
                    // authorized solely because it matched before.
                    if (WaitForSingleObject(launchedProcess, 18000) != 0 ||
                        WaitForSingleObject(launchedProcess, 0) != 0)
                        throw new InvalidOperationException("Worker lifetime not signaled");
                    System.IO.File.WriteAllText(@"__DEATH_WITNESS__",
                        "DEAD_WORKER_DENIED|" + reportedPid + "|" +
                        born + "|" + reportedSession);
                }
            } else {
                // Explicit denial, NOT a successful authenticated handshake.
                System.IO.File.WriteAllText(@"__PEER_WITNESS__",
                    "REJECTED_PID|" + reportedPid + "|" + ownedPid + "|" + reportedSession);
            }
        } catch {
            try { System.IO.File.WriteAllText(@"__PEER_WITNESS__", "RED"); } catch { }
        } finally {
            if (ioUndrained && overlap != IntPtr.Zero) {
                CancelIoEx(pipe, overlap);
                uint ignored;
                GetOverlappedResult(pipe, overlap, out ignored, true);
            }
            if (overlap != IntPtr.Zero) Marshal.FreeHGlobal(overlap);
            if (nativeEvent != IntPtr.Zero && nativeEvent != new IntPtr(-1))
                CloseHandle(nativeEvent);
            workerPeerDone.Set();
        }
    }
'@
    # Spawn after the real service creates the pipe, then complete the
    # connection on a separate thread. SCM OnStart never blocks for a client.
    $startBody += @'
        System.Threading.ThreadPool.QueueUserWorkItem(
            delegate(object ignored) { AttestNativeWorkerPeer(); });
'@
    $stopBody = @'
        if (!workerPeerDone.WaitOne(7000))
            throw new InvalidOperationException("native peer did not drain before shutdown");
        workerPeerDone.Dispose();
'@ + $stopBody
}

# Additional real SCM identity: LocalService tries to open the existing
# SYSTEM-owned pipe before the intended interactive SID. It sends zero data.
$deniedClass = ""
# Keep the LaunchWorker/WorkerPipe entrypoint selected above; only the
# LocalService negative mode needs a separate dispatcher.
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
    Replace("__PIPE_NAME__", $pipeName).
    Replace("__SESSION_ID__", ([string]$workerSession)).
    Replace("__EXE_PATH__", $serviceExe).
    Replace("__WITNESS_PATH__", $witnessFile).
    Replace("__PIPE_OPEN_MODE__", $pipeOpenMode).
    Replace("__CANCEL_WITNESS__", $cancelWitness).
    Replace("__PEER_WITNESS__", $peerWitness).
    Replace("__DEATH_WITNESS__", $deathWitness).
    Replace("__SELF_EXPIRE_MODE__", $(if ($Mode -eq "WorkerPipeDeath") { "true" } else { "false" })).
    Replace("__WORKER_CLIENT_ARGS__", $(if ($Mode -in @("WorkerPipePositive", "WorkerPipeDeath")) { " --client-pipe " + $pipeName + $(if ($Mode -eq "WorkerPipeDeath") { " --self-expire" } else { "" }) } else { "" }))

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

    public static bool WorkerMatchesExpected(IntPtr process, uint expectedPid,
        uint expectedSession, string expectedSid, long expectedBirth) {
        return GetProcessId(process) == expectedPid &&
            WaitForSingleObject(process, 0) == 0x102 &&
            Session(process) == expectedSession &&
            TokenSession(process) == expectedSession &&
            TokenUserSid(process) == expectedSid &&
            Birth(process) == expectedBirth &&
            !IsElevated(process);
    }

    public static bool IsElevated(IntPtr process) {
        // TokenElevation struct: DWORD TokenIsElevated (TOKEN_INFORMATION_CLASS 20).
        byte[] elevation = ReadTokenInfo(process, 20);
        return elevation.Length >= 4 && BitConverter.ToUInt32(elevation, 0) != 0;
    }

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
    if ($launchMode) {
        # The WTS-derived medium-integrity interactive token cannot execute
        # from an Administrators-only directory. Grant the *exact* target SID
        # RX (traverse/load) but never WRITE/MODIFY to protected test binary.
        $targetRx = "*" + $identity.User.Value + ":(OI)(CI)RX"
        $acl = & icacls.exe $workDir "/grant:r" $targetRx 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Unable to grant target Worker SID RX: $acl" }
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

    if ($Mode -eq "CancelConnect") {
        $cancelDeadline = [DateTime]::UtcNow.AddSeconds(8)
        while (-not (Test-Path -LiteralPath $cancelWitness) -and
            [DateTime]::UtcNow -lt $cancelDeadline) {
            Start-Sleep -Milliseconds 100
        }
        Assert-Probe (Test-Path -LiteralPath $cancelWitness) "SCM bounded async connect cancellation emitted protected completion witness"
        $actual = [IO.File]::ReadAllText($cancelWitness).Trim()
        Assert-Probe ($actual -ceq "CANCELLED_AND_DRAINED") "no-client native ConnectNamedPipe pending operation canceled AND completion drained"
        $stillRunning = Get-CimInstance Win32_Service -Filter ("Name='" + $name + "'")
        Assert-Probe ($null -ne $stillRunning -and $stillRunning.State -eq "Running" -and
            $stillRunning.ProcessId -eq $servicePid -and
            [ClassMeshNativeScmProbe]::WaitForSingleObject($serviceHandle, 0) -eq 0x102) "SCM remained responsive and pinned process alive after cancellation drain"
    }

    if ($Mode -eq "WorkerPipeDecoy") {
        $pipeDeadline = [DateTime]::UtcNow.AddSeconds(6)
        do {
            $pipeHandle = [ClassMeshNativeScmProbe]::OpenReadonlyClient($pipePath)
            if ($pipeHandle -ne [IntPtr]::Zero -and $pipeHandle -ne [IntPtr](-1)) { break }
            Start-Sleep -Milliseconds 100
        } while ([DateTime]::UtcNow -lt $pipeDeadline)
        Assert-Probe ($pipeHandle -ne [IntPtr]::Zero -and $pipeHandle -ne [IntPtr](-1)) "same-target-SID but unrelated observer opened protected native pipe as decoy"
    }

    if ($launchMode) {
        $deadline = [DateTime]::UtcNow.AddSeconds(12)
        while (-not (Test-Path -LiteralPath $witnessFile) -and
            [DateTime]::UtcNow -lt $deadline) {
            Start-Sleep -Milliseconds 120
        }
        Assert-Probe (Test-Path -LiteralPath $witnessFile) "SCM emitted protected witness after CreateProcessAsUser"
        $witness = [IO.File]::ReadAllText($witnessFile).Trim()
        Assert-Probe ($witness -match '^(\d+)\|(\d+)\|(\d+)$') "protected witness is bounded public PID/birth/session metadata"
        $launchedPid = [int]$Matches[1]
        $launchedBirth = [long]$Matches[2]
        $launchedSession = [uint32]$Matches[3]
        Assert-Probe ($launchedPid -gt 0 -and $launchedPid -ne $servicePid -and
            $launchedPid -ne $workerPid) "SCM-created Worker is a different native process"
        $launchedHandle = [ClassMeshNativeScmProbe]::Pin($launchedPid)
        $realChild = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $launchedPid)
        Assert-Probe ($null -ne $realChild -and
            [uint32]$realChild.ParentProcessId -eq [uint32]$servicePid) "Windows kernel process ancestry points to real SCM Service PID"
        Assert-Probe ([ClassMeshNativeScmProbe]::GetProcessId($launchedHandle) -eq [uint32]$launchedPid -and
            [ClassMeshNativeScmProbe]::WaitForSingleObject($launchedHandle, 0) -eq 0x102) "launched Worker original process HANDLE remains live"
        Assert-Probe ([ClassMeshNativeScmProbe]::TokenUserSid($launchedHandle) -eq $identity.User.Value) "SCM-launched Worker native TokenUser equals signed-in target SID"
        Assert-Probe ([ClassMeshNativeScmProbe]::Session($launchedHandle) -eq [uint32]$workerSession -and
            [ClassMeshNativeScmProbe]::TokenSession($launchedHandle) -eq [uint32]$workerSession -and
            $launchedSession -eq [uint32]$workerSession) "SCM-launched Worker process/token session matches signed-in interactive session"
        Assert-Probe (-not [ClassMeshNativeScmProbe]::IsElevated($launchedHandle)) "SCM-launched Worker has non-elevated native access token"
        Assert-Probe ([ClassMeshNativeScmProbe]::Birth($launchedHandle) -eq $launchedBirth) "SCM-launched Worker native FILETIME equals independently pinned birth"
        Assert-Probe ([ClassMeshNativeScmProbe]::TokenUserSid($launchedHandle) -ne $serviceSid -and
            [ClassMeshNativeScmProbe]::Session($launchedHandle) -ne $serviceSession) "launched interactive Worker cannot be LocalSystem Session0"
        Assert-Probe ([ClassMeshNativeScmProbe]::WorkerMatchesExpected($launchedHandle,
            [uint32]$launchedPid, [uint32]$workerSession, $identity.User.Value,
            $launchedBirth)) "OS Worker process matches all pinned Service-issued identity fields"
        Assert-Probe (-not [ClassMeshNativeScmProbe]::WorkerMatchesExpected($launchedHandle,
            [uint32]($launchedPid + 1), [uint32]$workerSession,
            $identity.User.Value, $launchedBirth)) "wrong Worker OS PID explicitly rejected"
        Assert-Probe (-not [ClassMeshNativeScmProbe]::WorkerMatchesExpected($launchedHandle,
            [uint32]$launchedPid, 0, $identity.User.Value,
            $launchedBirth)) "wrong Session0 Worker expectation explicitly rejected"
        Assert-Probe (-not [ClassMeshNativeScmProbe]::WorkerMatchesExpected($launchedHandle,
            [uint32]$launchedPid, [uint32]$workerSession, $serviceSid,
            $launchedBirth)) "wrong LocalSystem SID Worker expectation explicitly rejected"
        Assert-Probe (-not [ClassMeshNativeScmProbe]::WorkerMatchesExpected($launchedHandle,
            [uint32]$launchedPid, [uint32]$workerSession,
            $identity.User.Value, ($launchedBirth + 1))) "wrong Worker birth FILETIME explicitly rejected"
    }

    if ($workerPipeMode) {
        $peerDeadline = [DateTime]::UtcNow.AddSeconds(11)
        while (-not (Test-Path -LiteralPath $peerWitness) -and
            [DateTime]::UtcNow -lt $peerDeadline) {
            Start-Sleep -Milliseconds 100
        }
        Assert-Probe (Test-Path -LiteralPath $peerWitness) "SCM generated protected kernel peer PID/session classification witness"
        $report = [IO.File]::ReadAllText($peerWitness).Trim()
        if ($Mode -in @("WorkerPipePositive", "WorkerPipeDeath")) {
            Assert-Probe ($report -match '^MATCHED\|(\d+)\|(\d+)\|(\d+)$') "kernel client OS PID matches original SCM-launched child"
            $actualPid = [uint32]$Matches[1]
            $actualBirth = [long]$Matches[2]
            $actualSession = [uint32]$Matches[3]
            Assert-Probe ($actualPid -eq [uint32]$launchedPid -and
                $actualBirth -eq $launchedBirth -and
                $actualSession -eq [uint32]$workerSession) "native connected peer is EXACT pinned live Worker PID/birth/interactive Session"
            if ($Mode -eq "WorkerPipeDeath") {
                Assert-Probe ([ClassMeshNativeScmProbe]::WaitForSingleObject($launchedHandle, 0) -eq 0x102) "accepted Worker originally live on the owned native process HANDLE"
                $deathDeadline = [DateTime]::UtcNow.AddSeconds(21)
                while (-not (Test-Path -LiteralPath $deathWitness) -and
                    [DateTime]::UtcNow -lt $deathDeadline) {
                    Start-Sleep -Milliseconds 100
                }
                Assert-Probe (Test-Path -LiteralPath $deathWitness) "SCM detects natural Worker process exit after peer acceptance"
                $deathReport = [IO.File]::ReadAllText($deathWitness).Trim()
                Assert-Probe ($deathReport -ceq ("DEAD_WORKER_DENIED|" + $actualPid + "|" + $actualBirth + "|" + $actualSession)) "stale once-accepted peer identity is explicitly rejected after original Worker dies"
                Assert-Probe ([ClassMeshNativeScmProbe]::WaitForSingleObject($launchedHandle, 0) -eq 0 -and
                    [ClassMeshNativeScmProbe]::WaitForSingleObject($serviceHandle, 0) -eq 0x102) "original Worker signaled while authentic SCM service remains live"
                Assert-Probe (-not [ClassMeshNativeScmProbe]::WorkerMatchesExpected(
                    $launchedHandle, $actualPid, $actualSession,
                    $identity.User.Value, $actualBirth)) "live Worker acceptance predicate rejects its own previously matched dead HANDLE"
            }
        } else {
            Assert-Probe ($report -match '^REJECTED_PID\|(\d+)\|(\d+)\|(\d+)$') "same-user decoy native client rejected SPECIFICALLY for wrong OS PID"
            $actualPid = [uint32]$Matches[1]
            $expectedPid = [uint32]$Matches[2]
            $actualSession = [uint32]$Matches[3]
            Assert-Probe ($actualPid -eq [uint32]$workerPid -and
                $expectedPid -eq [uint32]$launchedPid -and
                $actualPid -ne $expectedPid -and $actualSession -eq [uint32]$workerSession) "native wrong PID denial despite same SID and interactive Session"
            [void][ClassMeshNativeScmProbe]::CloseHandle($pipeHandle)
            $pipeHandle = [IntPtr]::Zero
        }
    }

    if ($Mode -in @("Pipe", "DenyLocalService")) {
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
    if ($Mode -eq "CancelConnect") {
        $stale = [ClassMeshNativeScmProbe]::OpenReadonlyClient($pipePath)
        $staleDenied = $stale -eq [IntPtr]::Zero -or $stale -eq [IntPtr](-1)
        if (-not $staleDenied) { [void][ClassMeshNativeScmProbe]::CloseHandle($stale) }
        Assert-Probe $staleDenied "canceled test pipe rejects new client after Service death"
        Write-Output "SCM_SESSION0_OVERLAPPED_CANCEL_DRAIN_PASS"
    }
    if ($launchMode) {
        Assert-Probe ([ClassMeshNativeScmProbe]::WaitForSingleObject($launchedHandle, 8000) -eq 0) "SCM Service stop terminates exact launched Worker HANDLE"
        if ($workerPipeMode) {
            Write-Output $(if ($Mode -eq "WorkerPipePositive") { "SCM_LAUNCHED_WORKER_NATIVE_PIPE_PEER_PASS" } elseif ($Mode -eq "WorkerPipeDeath") { "SCM_DEAD_WORKER_STALE_PIPE_AUTHORITY_DENIED_PASS" } else { "SCM_SAME_USER_DECOY_NATIVE_PID_DENIED_PASS" })
        } else {
            Write-Output "SCM_SESSION0_LAUNCHED_INTERACTIVE_WORKER_INERT_PASS"
        }
    }
    if ($Mode -in @("Pipe", "DenyLocalService")) {
        $stale = [ClassMeshNativeScmProbe]::OpenReadonlyClient($pipePath)
        $staleDenied = ($stale -eq [IntPtr]::Zero -or $stale -eq [IntPtr](-1))
        if (-not $staleDenied) { [void][ClassMeshNativeScmProbe]::CloseHandle($stale) }
        Assert-Probe $staleDenied "stale outbound pipe refuses new client after SCM Service death"
        if ($Mode -eq "DenyLocalService") {
            Write-Output "SCM_LOCAL_SERVICE_WRONG_SID_ACL_DENY_PASS"
        } else {
            Write-Output "SCM_SESSION0_NATIVE_PIPE_INERT_PASS"
        }
    } elseif ($Mode -eq "Run") {
        Write-Output "SCM_SESSION0_NATIVE_INERT_PASS"
    }
    Write-Output "NOT_AUTHENTICATED_V12_NOT_PIPE_NOT_CLIPBOARD"
} finally {
    if ($launchedHandle -ne [IntPtr]::Zero) {
        [void][ClassMeshNativeScmProbe]::CloseHandle($launchedHandle)
    }
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
