#Requires -Version 5.1
# An actual Teacher acceptance is meaningful only from a non-elevated,
# interactive desktop token. The protected Service runs independently in
# Session 0 as LocalSystem and never launches this process as administrator.
function Assert-TeacherSessionPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][bool]$IsElevated,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$AccountSid,
        [Parameter(Mandatory=$true)][int]$SessionId,
        [Parameter(Mandatory=$true)][bool]$IsInteractive
    )
    if ($IsElevated) {
        throw 'FAIL_CLOSED: Teacher qualification must not run as elevated Administrator'
    }
    if ([string]::IsNullOrWhiteSpace($AccountSid) -or
        $AccountSid -in @('S-1-5-18','S-1-5-19','S-1-5-20')) {
        throw 'FAIL_CLOSED: Teacher qualification requires a non-service user identity'
    }
    if ($SessionId -le 0 -or -not $IsInteractive) {
        throw 'FAIL_CLOSED: Teacher qualification requires an interactive desktop session'
    }
}

function Assert-NonElevatedTeacherSession {
    if ($env:OS -ne 'Windows_NT') {
        throw 'FAIL_CLOSED: native Windows Teacher session required'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -eq $identity -or $null -eq $identity.User) {
        throw 'FAIL_CLOSED: unable to attest current Teacher token'
    }
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $interactiveSid = [Security.Principal.SecurityIdentifier]::new('S-1-5-4')
    $process = [Diagnostics.Process]::GetCurrentProcess()
    Assert-TeacherSessionPolicy -IsElevated:$($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) `
        -AccountSid $identity.User.Value -SessionId $process.SessionId `
        -IsInteractive:$($principal.IsInRole($interactiveSid))
}
