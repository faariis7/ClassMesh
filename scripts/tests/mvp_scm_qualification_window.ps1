$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$helper = Join-Path $PSScriptRoot '../Wait-ApprovedM2QualificationWindow.ps1'
if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) {
    throw 'RED: actual bounded SCM Teacher qualification window helper missing'
}
. $helper
$script:pid = 4242
$script:ownerSid = 'S-1-5-18'
$script:ownerCode = 0
$script:creationDate = '20261110120000.000000+180'
$script:image = 'C:\ClassMesh\classmesh-service.exe'
function Get-CimInstance {
    param([Parameter(Position=0)][string]$ClassName, [string]$Filter)
    if ($ClassName -eq 'Win32_Service') {
        return [pscustomobject]@{
            State='Running'; StartName='LocalSystem'; StartMode='Manual'
            PathName='"C:\ClassMesh\classmesh-service.exe"'; ServiceType='Own Process'
            ProcessId=$script:pid
        }
    }
    if ($ClassName -eq 'Win32_Process') {
        return [pscustomobject]@{
            SessionId=0; ExecutablePath=$script:image; CreationDate=$script:creationDate
        }
    }
    throw "Unexpected Win32 CIM class $ClassName"
}
function Invoke-CimMethod {
    param([object]$InputObject,[string]$MethodName,[string]$ErrorAction)
    if ($MethodName -ne 'GetOwnerSid') { throw 'Unexpected CIM method' }
    return [pscustomobject]@{ ReturnValue=$script:ownerCode; Sid=$script:ownerSid }
}
function MustReject([string]$scenario) {
    $rejected=$false
    try {
        Wait-ApprovedM2QualificationWindow -ServiceName ClassMeshService -ServicePid 4242 `
            -ExpectedImage 'C:\ClassMesh\classmesh-service.exe' `
            -ExpectedCreationDate '20261110120000.000000+180' `
            -Seconds 2 | Out-Null
    } catch { $rejected=$true }
    if (-not $rejected) { throw "FAIL: wrong SCM state accepted: $scenario" }
}
$script:ownerSid = 'S-1-5-21-1234-1000'
MustReject 'OS owner SID switched away from LocalSystem'
$script:ownerSid = 'S-1-5-18'
$script:pid = 9999
MustReject 'SCM process replaced during approval window'
$script:pid = 4242
$script:image = 'C:\ClassMesh\other.exe'
MustReject 'process image changed during approval window'
$script:image = 'C:\ClassMesh\classmesh-service.exe'
$script:ownerCode = 5
MustReject 'OS owner attestation denied'
$script:ownerCode = 0
Wait-ApprovedM2QualificationWindow -ServiceName ClassMeshService -ServicePid 4242 `
    -ExpectedImage 'C:\ClassMesh\classmesh-service.exe' `
    -ExpectedCreationDate '20261110120000.000000+180' `
    -Seconds 1 | Out-Null
'PASS: bounded SCM qualification window verifies PID, image, creation, Session0 and real LocalSystem SID'
