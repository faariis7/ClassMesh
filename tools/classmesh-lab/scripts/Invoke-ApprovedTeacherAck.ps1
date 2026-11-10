#Requires -Version 5.1
<#
Run a non-elevated, fail-closed Teacher -> installed Service -> Service-owned Worker
message qualification. This never installs or starts a Service or Worker.
The installed Service and enrollment must already be independently approved.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$TeacherExe,
    [Parameter(Mandatory=$true)][string]$Identity,
    [Parameter(Mandatory=$true)][string]$ServiceName,
    [Parameter(Mandatory=$true)][string]$Connect,
    [Parameter(Mandatory=$true)][string]$ServerName,
    [Parameter(Mandatory=$true)][string]$Message,
    [Parameter(Mandatory=$true)][string]$Receipt,
    [Parameter(Mandatory=$true)][string]$TrustedSignerThumbprint,
    [int]$TimeoutSeconds = 35
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-ApprovedSignature([string]$Path, [string]$ExpectedThumbprint) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing signed executable: $Path" }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
        throw "Executable Authenticode signature is not valid: $Path"
    }
    $actual = ($signature.SignerCertificate.Thumbprint -replace '\s','').ToUpperInvariant()
    $expected = ($ExpectedThumbprint -replace '\s','').ToUpperInvariant()
    if ($expected.Length -ne 40 -or $actual -cne $expected) {
        throw "Executable signer does not match approved thumbprint"
    }
}

function Assert-ReadyService([string]$Name, [string]$ExpectedThumbprint) {
    $service = Get-CimInstance Win32_Service -Filter ("Name='" + $Name.Replace("'","''") + "'")
    if ($null -eq $service -or $service.State -ne 'Running' -or $service.StartName -ne 'LocalSystem') {
        throw "Approved LocalSystem Service must already be running"
    }
    $commandLine = [string]$service.PathName
    if ($commandLine -match '^\s*"([^"]+\.exe)"(?:\s|$)') {
        $binary = $Matches[1]
    } elseif ($commandLine -match '^\s*([^\s"]+\.exe)(?:\s|$)') {
        $binary = $Matches[1]
    } else {
        throw "Cannot safely identify installed Service executable"
    }
    Assert-ApprovedSignature $binary $ExpectedThumbprint
    if ([int64]$service.ProcessId -le 0) { throw 'Service has no running process ID' }
    $serviceProcess = Get-CimInstance Win32_Process -Filter ("ProcessId=" + [string]$service.ProcessId)
    if ($null -eq $serviceProcess -or [int]$serviceProcess.SessionId -ne 0) {
        throw 'Approved LocalSystem Service must execute in Session 0'
    }
    return [int64]$service.ProcessId
}

if ($TimeoutSeconds -lt 5 -or $TimeoutSeconds -gt 120) { throw 'TimeoutSeconds must be 5..120' }
if ([string]::IsNullOrWhiteSpace($Message)) { throw 'Message is required' }
foreach ($value in @($Connect, $ServerName, $Identity, $Message, $Receipt)) {
    if ($value -match '[`"\r\n]') { throw 'Unsafe command argument (quote, newline or backtick)' }
}
if (-not (Test-Path -LiteralPath $Identity -PathType Leaf)) { throw 'Provisioned Teacher identity missing' }
if (Test-Path -LiteralPath $Receipt) { throw 'Receipt already exists; refusing overwrite' }
Assert-ApprovedSignature $TeacherExe $TrustedSignerThumbprint
$approvedServicePid = Assert-ReadyService $ServiceName $TrustedSignerThumbprint

# Service owns the interactive Worker. Never launch a Worker under this account.
# ArgumentList is an array to avoid PowerShell expression evaluation; inputs
# must be trusted lab-provisioned values, not arbitrary remote shell commands.
$arguments = @('--connect', $Connect, '--server-name', $ServerName,
    '--identity', $Identity, '--teacher-message', $Message, '--message-only',
    '--require-completed', '--ack-receipt', $Receipt)
$process = $null
$qualificationPassed = $false
try {
    $process = Start-Process -FilePath $TeacherExe -ArgumentList ($arguments | ForEach-Object { '"' + $_ + '"' }) -PassThru -NoNewWindow
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        throw 'Teacher qualification timed out before Worker Completed'
    }
    if ($process.ExitCode -ne 0) { throw "Teacher qualification failed (exit $($process.ExitCode))" }
    if (-not (Test-Path -LiteralPath $Receipt -PathType Leaf)) {
        throw 'No correlated Completed receipt was produced'
    }
    $lines = @(Get-Content -LiteralPath $Receipt)
    if ($lines.Count -ne 4 -or $lines[0] -ne 'classmesh_teacher_message_ack_v1' -or
        $lines[1] -notmatch '^control_session_id=[1-9][0-9]*$' -or
        $lines[2] -notmatch '^request_id=[1-9][0-9]*$' -or
        $lines[3] -ne 'worker_state=Completed') {
        throw 'Invalid completion receipt format'
    }
    $verifiedServicePid = Assert-ReadyService $ServiceName $TrustedSignerThumbprint
    if ($verifiedServicePid -ne $approvedServicePid) {
        throw 'Service process changed during ACK qualification; refusing evidence'
    }
    $qualificationPassed = $true
    Write-Output "ACK completed via approved Service: $Receipt"
} finally {
    if (-not $qualificationPassed -and (Test-Path -LiteralPath $Receipt -PathType Leaf)) {
        Remove-Item -LiteralPath $Receipt -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $process) {
        $process.Refresh()
        if (-not $process.HasExited) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            $process.WaitForExit(5000) | Out-Null
        }
        $process.Dispose()
    }
}
