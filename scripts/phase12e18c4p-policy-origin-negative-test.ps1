[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows-only security qualification' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Elevated interactive administrator required'
}
$source = Join-Path $PSScriptRoot 'phase12e18c4j-protected-file-probe.ps1'
$match = [regex]::Match([IO.File]::ReadAllText($source), "(?ms)^\`$nativeSource = @'\r?\n(.*?)\r?\n'@\r?$")
if (-not $match.Success) { throw 'Native handle verification fixture unavailable' }
Add-Type -TypeDefinition $match.Groups[1].Value -ErrorAction Stop
$id = [Guid]::NewGuid().ToString('N')
$root = Join-Path $env:ProgramData ('classmesh-e18c4p-' + $id)
$leaf = Join-Path $root 'authorization.json'
try {
    New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
    & icacls.exe $root '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Fixture dir ACL failed' }
    [IO.File]::WriteAllText($leaf, '{"onlyTest":true}')
    & icacls.exe $leaf '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Fixture file ACL failed' }
    if ([ClassMeshPolicyHandleAttestation]::Check($leaf, $false) -ne 'ALLOW') {
        throw 'Positive protected control was rejected'
    }
    & icacls.exe $leaf '/grant' '*S-1-5-32-545:R' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Fixture read ACE failed' }
    $observed = [ClassMeshPolicyHandleAttestation]::Check($leaf, $false)
    if ($observed -ne 'OTHER_TRUSTEE_DENIED') {
        throw "Unexpected allowed read trustee: $observed"
    }
    & icacls.exe $leaf '/remove:g' '*S-1-5-32-545' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Fixture read ACE removal failed' }
    if ([ClassMeshPolicyHandleAttestation]::Check($leaf, $false) -ne 'ALLOW') {
        throw 'Original protected control did not recover after ACL restoration'
    }
    & icacls.exe $root '/grant' '*S-1-5-32-545:(OI)(CI)R' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Fixture ancestor read ACE failed' }
    $parentObserved = [ClassMeshPolicyHandleAttestation]::Check($root, $true)
    if ($parentObserved -ne 'OTHER_TRUSTEE_DENIED') {
        throw "Unexpected allowed ancestor read trustee: $parentObserved"
    }
    & icacls.exe $root '/remove:g' '*S-1-5-32-545' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Fixture ancestor ACE removal failed' }
    if ([ClassMeshPolicyHandleAttestation]::Check($root, $true) -ne 'ALLOW') {
        throw 'Original protected ancestor failed recovery'
    }
    'POLICY_ANCESTOR_UNTRUSTED_READ_ACE_DENIED'
    'POLICY_UNTRUSTED_READ_ACE_DENIED'
} finally {
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
}
