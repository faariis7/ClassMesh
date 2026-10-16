[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RustTestExe,
    [ValidatePattern('^[A-Za-z0-9_:]*$')][string]$TestFilter = 'policy_file_origin::tests',
    [ValidateRange(1,64)][int]$ExpectedPassCount = 4
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') {throw 'Native Windows only'}
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($id)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    $id.User.Value -eq 'S-1-5-18' -or [Diagnostics.Process]::GetCurrentProcess().SessionId -le 0) {
    throw 'Elevated non-SYSTEM interactive administrator required to create disposable SCM test'
}
if (-not (Test-Path -LiteralPath $RustTestExe -PathType Leaf)) {
    throw "Rust test binary missing: $RustTestExe"
}
$guid=[Guid]::NewGuid().ToString('N')
$name='ClassMeshRustQ'+$guid.Substring(0,12)
$root=Join-Path $env:ProgramData ('classmesh-rust-scm-'+$guid)
$binary=Join-Path $root 'policy-native-test.exe'
$serviceExe=Join-Path $root 'policy-native-service.exe'
$witness=Join-Path $root 'scm-proof.witness'
$created=$false
function NativeAcl {
    param([string]$Path,[string[]]$Options)
    $result=& icacls.exe $Path @Options 2>&1
    if ($LASTEXITCODE -ne 0) {throw "icacls failed: $($result -join ' | ')"}
}
try {
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    NativeAcl $root @('/inheritance:r','/grant:r','*S-1-5-18:(OI)(CI)F','*S-1-5-32-544:(OI)(CI)F')
    NativeAcl $root @('/setowner','*S-1-5-32-544')
    Copy-Item -LiteralPath $RustTestExe -Destination $binary -ErrorAction Stop
    NativeAcl $binary @('/inheritance:r','/grant:r','*S-1-5-18:F','*S-1-5-32-544:F')
    $source=@'
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.ServiceProcess;
public sealed class ClassMeshNativeRustService : ServiceBase {
    public ClassMeshNativeRustService() {
        ServiceName = "__NAME__";
        CanStop = true;
    }
    public static void Main(string[] args) {
        ServiceBase.Run(new ClassMeshNativeRustService());
    }
    protected override void OnStart(string[] args) {
        string sid = WindowsIdentity.GetCurrent().User.Value;
        int session = Process.GetCurrentProcess().SessionId;
        int exit = -999;
        string output = "";
        try {
            using (Process p = new Process()) {
                p.StartInfo.FileName = @"__BINARY__";
                p.StartInfo.Arguments = "__FILTER__ --test-threads=1";
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.CreateNoWindow = true;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;
                p.Start();
                string stdout = p.StandardOutput.ReadToEnd();
                string stderr = p.StandardError.ReadToEnd();
                if (!p.WaitForExit(20000)) {
                    p.Kill();
                    throw new Exception("Rust test timed out");
                }
                exit = p.ExitCode;
                output = stdout + "\n" + stderr;
            }
        } catch (Exception e) {
            output = "RUST_EXCEPTION: " + e.ToString();
        }
        File.WriteAllText(@"__WITNESS__",
            "SID=" + sid + "\nSESSION=" + session + "\nEXIT=" + exit + "\n" + output);
    }
    protected override void OnStop() {}
}
'@
    $source=$source.Replace('__NAME__',$name).Replace('__BINARY__',$binary).Replace('__WITNESS__',$witness).Replace('__FILTER__',$TestFilter)
    Add-Type -TypeDefinition $source -OutputAssembly $serviceExe -OutputType ConsoleApplication -ReferencedAssemblies 'System.ServiceProcess.dll' -ErrorAction Stop
    NativeAcl $serviceExe @('/inheritance:r','/grant:r','*S-1-5-18:F','*S-1-5-32-544:F')
    $sc=& sc.exe create $name 'binPath=' ('"'+$serviceExe+'"') 'start=' 'demand' 'type=' 'own' 'obj=' 'LocalSystem' 2>&1
    if ($LASTEXITCODE -ne 0) {throw "SCM create failed: $($sc -join ' | ')"}
    $created=$true
    Start-Service -Name $name -ErrorAction Stop
    $deadline=[DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path -LiteralPath $witness -PathType Leaf) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 120
    }
    if (-not (Test-Path -LiteralPath $witness -PathType Leaf)) {
        throw 'SCM Rust service witness timed out'
    }
    $content=[IO.File]::ReadAllText($witness)
    if (-not $content.Contains("SID=S-1-5-18`nSESSION=0`nEXIT=0`n") -or
        -not $content.Contains("test result: ok. $ExpectedPassCount passed; 0 failed")) {
        throw "Unqualified SCM Rust native result: $content"
    }
    $svc=Get-CimInstance Win32_Service -Filter ("Name='"+$name+"'")
    if ($null -eq $svc -or $svc.State -ne 'Running' -or
        $svc.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM') -or $svc.ProcessId -le 0) {
        throw 'Failed SCM LocalSystem own-process verification'
    }
    "SCM_NATIVE_RUST_LOCALSYSTEM_$($ExpectedPassCount)_PASS"
} finally {
    if ($created) {
        try {
            $live=Get-Service -Name $name -ErrorAction SilentlyContinue
            if ($null -ne $live -and $live.Status -ne 'Stopped') {
                Stop-Service -Name $name -ErrorAction SilentlyContinue
                $live.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))
            }
        } finally {& sc.exe delete $name 2>&1 | Out-Null}
    }
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    }
    'SCM_NATIVE_RUST_CLEANUP_COMPLETE'
}
