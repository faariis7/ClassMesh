#Requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$helper = Join-Path $PSScriptRoot '../Assert-NonElevatedTeacherSession.ps1'
if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) {
    throw 'RED: M2 Teacher admission helper missing; non-admin preflight not enforced'
}
. $helper
function Reject([bool]$elevated, [string]$sid, [int]$session, [bool]$interactive) {
    $rejected=$false
    try { Assert-TeacherSessionPolicy -IsElevated:$elevated -AccountSid $sid -SessionId $session -IsInteractive:$interactive }
    catch { $rejected=$true }
    if (-not $rejected) { throw 'FAIL: unsafe Teacher session accepted' }
}
Assert-TeacherSessionPolicy -IsElevated:$false -AccountSid 'S-1-5-21-123-456-789-1000' -SessionId 1 -IsInteractive:$true
Reject $true  'S-1-5-21-123-456-789-1000' 1 $true
Reject $false 'S-1-5-18' 1 $true
Reject $false 'S-1-5-19' 1 $true
Reject $false 'S-1-5-20' 1 $true
Reject $false 'S-1-5-21-123-456-789-1000' 0 $true
Reject $false 'S-1-5-21-123-456-789-1000' -1 $true
Reject $false 'S-1-5-21-123-456-789-1000' 1 $false
Reject $false '' 1 $true
$entry = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../Invoke-ApprovedTeacherAck.ps1') -Raw
$gateAt = $entry.IndexOf('Assert-NonElevatedTeacherSession', [StringComparison]::Ordinal)
$identityAt = $entry.IndexOf('Provisioned Teacher identity missing', [StringComparison]::Ordinal)
$launchAt = $entry.IndexOf('Start-Process -FilePath', [StringComparison]::Ordinal)
if ($gateAt -lt 0 -or $identityAt -le $gateAt -or $launchAt -le $gateAt) {
    throw 'FAIL: live Teacher entrypoint does not enforce non-admin admission before identity and process launch'
}
'PASS: Teacher requires real non-elevated interactive non-service token and positive desktop session'
