[CmdletBinding()]
param([ValidateSet('Help','All')][string]$Mode='Help')
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($Mode -eq 'Help') {
@'
Phase12E18c4k: disposable REAL SCM LocalSystem policy-file probe.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\phase12e18c4k-scm-policy-probe.ps1 -Mode All
Requires elevated non-SYSTEM interactive admin. Starts/stops a unique
test-only SCM own-process ServiceBase as LocalSystem Session0.
Reuses c4j exact-HANDLE OWNER/DACL/reparse predicate inside Service.
No real policy file or clipboard touched. Not a production loader,
pinned multi-ancestor path, durable epoch or SCM authorization gateway.
'@ | Write-Output
return
}
if ($env:OS -ne 'Windows_NT') {throw 'Windows only'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$admin=New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    [Diagnostics.Process]::GetCurrentProcess().SessionId -le 0 -or $identity.User.Value -eq 'S-1-5-18') {
    throw 'Elevated interactive non-SYSTEM admin required'
}
$c4j=Join-Path $PSScriptRoot 'phase12e18c4j-protected-file-probe.ps1'
if (-not (Test-Path -LiteralPath $c4j -PathType Leaf)) {throw 'c4j predicate source unavailable'}
$match=[regex]::Match([IO.File]::ReadAllText($c4j),"(?ms)^\`$nativeSource = @'\r?\n(.*?)\r?\n'@\r?$")
if (-not $match.Success) {throw 'Reviewed native c4j file predicate not found'}
$nativeSource=$match.Groups[1].Value
$id=[Guid]::NewGuid().ToString('N')
$name='ClassMeshE18c4k'+$id.Substring(0,12)
$root=Join-Path $env:ProgramData ('classmesh-e18c4k-'+$id)
$leaf=Join-Path $root 'authorization.json'
$target=Join-Path $root 'authorization-target.json'
$witness=Join-Path $root 'service-file.witness'
$exe=Join-Path $root 'test-system-service.exe'
$sy='*S-1-5-18'
$ba='*S-1-5-32-544'
$bu='*S-1-5-32-545'
$created=$false
function NativeAcl {
    param([string]$Path,[string[]]$Options)
    $result=& icacls.exe $Path @Options 2>&1
    if ($LASTEXITCODE -ne 0) {throw "icacls failed: $($result -join ' | ')"}
}
function Invoke-Witness {
    param([string]$Label,[string]$ExpectedDir,[string]$ExpectedFile)
    if (Test-Path -LiteralPath $witness) {Remove-Item -LiteralPath $witness -Force}
    Start-Service -Name $name -ErrorAction Stop
    $deadline=[DateTime]::UtcNow.AddSeconds(12)
    while (-not (Test-Path -LiteralPath $witness -PathType Leaf) -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 120
    }
    if (-not (Test-Path -LiteralPath $witness -PathType Leaf)) {throw "SCM witness timeout $Label"}
    $actual=[IO.File]::ReadAllText($witness).Trim().Split('|')
    if ($actual.Count -ne 4 -or $actual[0] -ne 'S-1-5-18' -or $actual[1] -ne '0' -or
        $actual[2] -cne $ExpectedDir -or $actual[3] -cne $ExpectedFile) {
        throw "Unexpected genuine SCM $Label witness: $($actual -join '|')"
    }
    $service=Get-CimInstance Win32_Service -Filter ("Name='"+$name+"'")
    if ($null -eq $service -or $service.State -ne 'Running' -or
        $service.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM') -or $service.ProcessId -le 0) {
        throw "Service not genuine SCM own-process LocalSystem: $Label"
    }
    Stop-Service -Name $name -ErrorAction Stop
    (Get-Service -Name $name).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(12))
    Write-Output $Label
}
try {
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    NativeAcl $root @('/inheritance:r','/grant:r',"$($sy):(OI)(CI)F","$($ba):(OI)(CI)F")
    NativeAcl $root @('/setowner',$ba)
    [IO.File]::WriteAllText($leaf,'{"testOnly":true}')
    NativeAcl $leaf @('/inheritance:r','/grant:r',"$($sy):F","$($ba):F")
    NativeAcl $leaf @('/setowner',$ba)
    $serviceSource=@'
public sealed class PolicyFileProbeService : System.ServiceProcess.ServiceBase {
    public PolicyFileProbeService() { ServiceName="__SERVICE_NAME__"; CanStop=true; }
    public static void Main(string[] args) {
        System.ServiceProcess.ServiceBase.Run(new PolicyFileProbeService());
    }
    protected override void OnStart(string[] args) {
        string sid=System.Security.Principal.WindowsIdentity.GetCurrent().User.Value;
        int session=System.Diagnostics.Process.GetCurrentProcess().SessionId;
        string dir=ClassMeshPolicyHandleAttestation.Check(@"__ROOT__",true);
        string leaf=ClassMeshPolicyHandleAttestation.Check(@"__LEAF__",false);
        System.IO.File.WriteAllText(@"__WITNESS__",sid+"|"+session+"|"+dir+"|"+leaf);
    }
    protected override void OnStop() {}
}
'@
    $source=$nativeSource+[Environment]::NewLine+$serviceSource.Replace('__SERVICE_NAME__',$name).Replace('__ROOT__',$root).Replace('__LEAF__',$leaf).Replace('__WITNESS__',$witness)
    Add-Type -TypeDefinition $source -OutputAssembly $exe -OutputType ConsoleApplication -ReferencedAssemblies 'System.ServiceProcess.dll' -ErrorAction Stop
    NativeAcl $exe @('/inheritance:r','/grant:r',"$($sy):F","$($ba):F")
    $quoted='"'+$exe+'"'
    $out=& sc.exe create $name 'binPath=' $quoted 'start=' 'demand' 'type=' 'own' 'obj=' 'LocalSystem' 2>&1
    if ($LASTEXITCODE -ne 0) {throw "sc create failed $($out -join ';')"}
    $created=$true
    Invoke-Witness 'SCM_LOCAL_SYSTEM_SESSION0' 'ALLOW' 'ALLOW'
    Invoke-Witness 'SCM_PROTECTED_POLICY_ALLOW' 'ALLOW' 'ALLOW'
    NativeAcl $leaf @('/grant',"$($bu):M")
    Invoke-Witness 'SCM_USER_WRITABLE_FILE_DENIED' 'ALLOW' 'OTHER_TRUSTEE_DENIED'
    NativeAcl $leaf @('/remove:g',$bu)
    NativeAcl $root @('/grant',"$($bu):(OI)(CI)M")
    Invoke-Witness 'SCM_USER_WRITABLE_DIRECTORY_DENIED' 'OTHER_TRUSTEE_DENIED' 'ALLOW'
    NativeAcl $root @('/remove:g',$bu)
    NativeAcl $leaf @('/setowner',('*'+$identity.User.Value))
    Invoke-Witness 'SCM_WRONG_OWNER_DENIED' 'ALLOW' 'OWNER_DENIED'
    NativeAcl $leaf @('/setowner',$ba)
    Move-Item -LiteralPath $leaf -Destination $target -ErrorAction Stop
    New-Item -ItemType SymbolicLink -Path $leaf -Target $target -ErrorAction Stop | Out-Null
    Invoke-Witness 'SCM_LEAF_REPARSE_DENIED' 'ALLOW' 'REPARSE_DENIED'
    Remove-Item -LiteralPath $leaf -Force
    Invoke-Witness 'SCM_MISSING_PRIMARY_DENIED' 'ALLOW' 'OPEN_DENIED'
} finally {
    if ($created) {
        try {
            $live=Get-Service -Name $name -ErrorAction SilentlyContinue
            if ($null -ne $live -and $live.Status -ne 'Stopped') {
                Stop-Service -Name $name -ErrorAction SilentlyContinue
                $live.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(12))
            }
        } finally {& sc.exe delete $name 2>&1 | Out-Null}
    }
    if (Test-Path -LiteralPath $root) {Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop}
    'SCM_CLEANUP_COMPLETE'
}
