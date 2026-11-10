#Requires -Version 5.1
# An isolated *approved* SCM installer invokes this after verifying its exact
# signed/protected LocalSystem Service executable, live process and token.
# Keep the Service running while a DIFFERENT non-elevated interactive account
# runs the signed Teacher ACK harness, then return control to SCM cleanup.
# A window closing is NEVER proof of a Worker ACK or an M2 acceptance.
# Use native PowerShell 5.1-compatible volume/path verification.
. (Join-Path $PSScriptRoot 'Assert-LocalAbsolutePath.ps1')
function Wait-ApprovedM2QualificationWindow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ServiceName,
        [Parameter(Mandatory=$true)][int]$ServicePid,
        [Parameter(Mandatory=$true)][string]$ExpectedImage,
        [Parameter(Mandatory=$true)][string]$ExpectedCreationDate,
        [Parameter(Mandatory=$true)][ValidateRange(1,120)][int]$Seconds
    )
    if ($ServicePid -le 0 -or [string]::IsNullOrWhiteSpace($ExpectedCreationDate)) {
        throw 'FAIL_CLOSED: no complete SCM process identity to qualify'
    }
    Assert-LocalAbsolutePath $ExpectedImage
    $expectedCommand = '"' + $ExpectedImage + '"'
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    "SCM_APPROVED_M2_WINDOW_OPEN_PID=$ServicePid; SECONDS=$Seconds; RUN_SIGNED_NONADMIN_TEACHER_ACK_SEPARATELY"
    do {
        $svc = Get-CimInstance Win32_Service -Filter ("Name='" + $ServiceName.Replace("'","''") + "'")
        if ($null -eq $svc -or $svc.State -ne 'Running' -or
            $svc.StartName -notin @('LocalSystem','NT AUTHORITY\SYSTEM') -or
            $svc.ServiceType -ne 'Own Process' -or $svc.StartMode -ne 'Manual' -or
            $svc.ProcessId -ne $ServicePid -or
            -not [string]::Equals(([string]$svc.PathName).Trim(), $expectedCommand,
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'FAIL_CLOSED: SCM PID, account or registration changed during M2 qualification'
        }
        $process = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $ServicePid)
        if ($null -eq $process -or $process.SessionId -ne 0 -or
            [string]$process.CreationDate -cne $ExpectedCreationDate -or
            [string]::IsNullOrWhiteSpace([string]$process.ExecutablePath) -or
            -not [string]::Equals([IO.Path]::GetFullPath([string]$process.ExecutablePath),
                [IO.Path]::GetFullPath($ExpectedImage),[StringComparison]::OrdinalIgnoreCase)) {
            throw 'FAIL_CLOSED: running Service process identity replaced during qualification'
        }
        try {
            $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
        } catch {
            throw 'FAIL_CLOSED: running Service owner SID cannot be verified'
        }
        if ($null -eq $owner -or $owner.ReturnValue -ne 0 -or $owner.Sid -cne 'S-1-5-18') {
            throw 'FAIL_CLOSED: running Service is not actual LocalSystem'
        }
        if ([DateTime]::UtcNow -ge $deadline) { break }
        Start-Sleep -Milliseconds 250
    } while ($true)
    'SCM_QUALIFICATION_WINDOW_CLOSED_NO_ACK_CLAIM; CLEANUP_MUST_FOLLOW'
}
