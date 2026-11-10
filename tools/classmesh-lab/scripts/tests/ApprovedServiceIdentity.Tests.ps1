$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../Assert-ApprovedService.ps1')
# Stub only external Windows CIM and signer reads: exercise the real production
# readiness policy without installing an unsigned/privileged SCM Service.
$script:reportedOwnerSid = 'S-1-5-21-1234-1000'
$script:reportedOwnerStatus = 0
$script:reportedPid = 4242
$script:reportedImage = 'C:\ClassMesh\classmesh-service.exe'
function Get-CimInstance {
    param([Parameter(Position=0)][string]$ClassName, [string]$Filter)
    if ($ClassName -eq 'Win32_Service') {
        return [pscustomobject]@{
            State='Running'; StartName='LocalSystem'; PathName='"C:\ClassMesh\classmesh-service.exe"'
            ServiceType='Own Process'; ProcessId=$script:reportedPid
        }
    }
    if ($ClassName -eq 'Win32_Process') {
        return [pscustomobject]@{
            SessionId=0; ExecutablePath=$script:reportedImage
            CreationDate='20261110120000.000000+180'
        }
    }
    throw "Unexpected CIM class: $ClassName"
}
function Invoke-CimMethod {
    param([object]$InputObject,[string]$MethodName,[string]$ErrorAction)
    if ($MethodName -ne 'GetOwnerSid') { throw 'Expected authoritative Win32_Process.GetOwnerSid' }
    return [pscustomobject]@{ ReturnValue=$script:reportedOwnerStatus; Sid=$script:reportedOwnerSid }
}
function Assert-NoReparsePath { param([string]$Path) }
function Assert-ApprovedSignature { param([string]$Path,[string]$ExpectedThumbprint) }
function MustReject([string]$Why) {
    $failed=$false
    try { Assert-ReadyService 'ClassMeshService' ('A'*40) | Out-Null }
    catch { $failed=$true }
    if (-not $failed) { throw "FAIL: untrusted Service identity accepted: $Why" }
}
MustReject 'SCM claims LocalSystem but actual owner SID is interactive user'
$script:reportedOwnerSid = 'S-1-5-18'
$script:reportedOwnerStatus = 5
MustReject 'Windows CIM denies owner query'
$script:reportedOwnerStatus = 0
$valid = Assert-ReadyService 'ClassMeshService' ('A'*40)
if ($valid -ne '4242|20261110120000.000000+180') { throw 'Trusted LocalSystem runtime correlation unexpectedly rejected' }
$script:reportedImage = 'C:\ClassMesh\other.exe'
MustReject 'running Service image replacement'
'PASS: real owner SID required, owner-query failures denied, pinned image and PID accepted'
