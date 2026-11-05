# Disposable native SCM gate. Never provisions identity, CA, or ProgramData.
[CmdletBinding()]
param(
    [ValidateSet('Plan','Run')][string]$Mode = 'Plan',
    [string]$ServiceExe,
    [string]$TrustedProvisionExe,
    [string]$ExpectedServiceSha256,
    [string]$ExpectedProvisionSha256,
    [switch]$SecurityReviewApproved,
    [switch]$DisposableVmApproved
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'ClassMeshService'
if ($Mode -eq 'Plan') {
    'SCM_PLAN_ONLY: requires independently approved enrollment, protected install, elevated interactive admin, exact binary SHA256, successful --verify-startup, protected path/ACL, and exclusive disposable VM. No mutation.'
    return
}
if (-not $SecurityReviewApproved -or -not $DisposableVmApproved) {
    throw 'FAIL_CLOSED: independent security review and exclusive disposable VM approval required'
}
if ($env:OS -ne 'Windows_NT') { throw 'FAIL_CLOSED: native Windows required' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    $identity.User.Value -eq 'S-1-5-18' -or [Diagnostics.Process]::GetCurrentProcess().SessionId -le 0) {
    throw 'FAIL_CLOSED: elevated interactive non-SYSTEM administrator required'
}
if ($ExpectedServiceSha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or
    $ExpectedProvisionSha256 -cnotmatch '^[a-fA-F0-9]{64}$') {
    throw 'FAIL_CLOSED: exact SHA256 pins required'
}
function Assert-ProtectedFile([string]$Path, [string]$ExpectedHash) {
    if (-not [IO.Path]::IsPathFullyQualified($Path)) { throw 'FAIL_CLOSED: absolute path required' }
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Extension -ne '.exe') { throw 'FAIL_CLOSED: executable file required' }
    if ((Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -ne $ExpectedHash) {
        throw 'FAIL_CLOSED: executable SHA256 mismatch'
    }
    $cursor = $item
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'FAIL_CLOSED: reparse point in executable ancestry'
        }
        $acl = Get-Acl -LiteralPath $cursor.FullName
        if ($acl.Owner -notmatch '^(BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM|S-1-5-32-544|S-1-5-18)$') {
            throw 'FAIL_CLOSED: executable ancestry owner is not SYSTEM/Administrators'
        }
        foreach ($rule in $acl.Access) {
            if ($rule.AccessControlType -ne 'Allow') { continue }
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if ($sid -in @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-4') -and
                ($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Write) -ne 0) {
                throw 'FAIL_CLOSED: low-privilege write permission in executable ancestry'
            }
        }
        $cursor = $cursor.Parent
    }
}
if (-not $ServiceExe -or -not $TrustedProvisionExe) { throw 'FAIL_CLOSED: both executable paths required' }
Assert-ProtectedFile $ServiceExe $ExpectedServiceSha256
Assert-ProtectedFile $TrustedProvisionExe $ExpectedProvisionSha256
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw 'FAIL_CLOSED: ClassMeshService already exists; never replace or delete it'
}
# This is a readiness gate, not CA validation. CA/CSR/issuer review must precede this invocation.
& $TrustedProvisionExe --verify-startup
if ($LASTEXITCODE -ne 0) { throw 'FAIL_CLOSED: trusted startup verification failed' }
$created = $false
try {
    $bin = '"' + (Get-Item -LiteralPath $ServiceExe).FullName + '"'
    $output = & sc.exe create $serviceName 'binPath=' $bin 'start=' 'demand' 'type=' 'own' 'obj=' 'LocalSystem' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "SCM create failed: $($output -join ' | ')" }
    $created = $true
    Start-Service -Name $serviceName -ErrorAction Stop
    $svc = Get-CimInstance Win32_Service -Filter "Name='ClassMeshService'"
    if ($null -eq $svc -or $svc.State -ne 'Running' -or $svc.StartName -notin @('LocalSystem','NT AUTHORITY\\SYSTEM') -or $svc.ProcessId -le 0) {
        throw 'FAIL_CLOSED: LocalSystem SCM runtime not verified'
    }
    "SCM_LOCALSYSTEM_RUNNING_PID=$($svc.ProcessId); WORKER_IPC_NOT_YET_PROVEN"
} finally {
    if ($created) {
        $live = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $live -and $live.Status -ne 'Stopped') {
            Stop-Service -Name $serviceName -ErrorAction Stop
            $live.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))
        }
        & sc.exe delete $serviceName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'SCM cleanup failed; manual investigation required' }
        'SCM_DISPOSABLE_SERVICE_REMOVED; protected enrollment state intentionally retained'
    }
}
