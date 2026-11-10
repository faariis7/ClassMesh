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
    # The SCM image is also provisioned input. A valid signature at a
    # symlink/junction target does not approve a redirectable service path.
    Assert-NoReparsePath $binary
    Assert-ApprovedSignature $binary $ExpectedThumbprint
    # A shared-process service cannot establish ownership of the interactive Worker.
    # Require the approved Service to have its own SCM process, not svchost hosting peers.
    if ([string]$service.ServiceType -ne 'Own Process') {
        throw 'Approved Service must be an SCM own-process service'
    }
    if ([int64]$service.ProcessId -le 0) { throw 'Service has no running process ID' }
    $serviceProcess = Get-CimInstance Win32_Process -Filter ("ProcessId=" + [string]$service.ProcessId)
    if ($null -eq $serviceProcess -or [int]$serviceProcess.SessionId -ne 0) {
        throw 'Approved LocalSystem Service must execute in Session 0'
    }
    # The SCM configuration is not evidence of the image actually executing.
    # Reject a replaced process or inaccessible image metadata (fail closed).
    if ([string]::IsNullOrWhiteSpace([string]$serviceProcess.ExecutablePath) -or
        -not [string]::Equals(
            [System.IO.Path]::GetFullPath($binary),
            [System.IO.Path]::GetFullPath([string]$serviceProcess.ExecutablePath),
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Running Service image differs from signed SCM image'
    }
    if ($null -eq $serviceProcess.CreationDate) {
        throw 'Running Service creation time unavailable'
    }
    return ([string]$service.ProcessId + '|' + [string]$serviceProcess.CreationDate)
}

function Assert-NoReparsePath([string]$Path) {
    # Reject linked identity and executable inputs, including linked ancestors.
    # A provisioned identity must not be silently redirected after approval.
    $cursor = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Provisioned input path contains a reparse point'
        }
        $cursor = $cursor.Parent
    }
}

if ($TimeoutSeconds -lt 5 -or $TimeoutSeconds -gt 120) { throw 'TimeoutSeconds must be 5..120' }
if ([string]::IsNullOrWhiteSpace($Message)) { throw 'Message is required' }
foreach ($value in @($Connect, $ServerName, $Identity, $Message, $Receipt)) {
    if ($value -match '[`"\r\n]') { throw 'Unsafe command argument (quote, newline or backtick)' }
}
if (-not (Test-Path -LiteralPath $Identity -PathType Leaf)) { throw 'Provisioned Teacher identity missing' }
Assert-NoReparsePath $Identity
Assert-NoReparsePath $TeacherExe
# A receipt is evidence, not an arbitrary output path. Refuse junctions/symlinks
# and directories that could redirect creation or cleanup outside the lab.
$receiptParent = Split-Path -Parent ([System.IO.Path]::GetFullPath($Receipt))
if (-not (Test-Path -LiteralPath $receiptParent -PathType Container)) {
    throw 'Receipt parent directory must already exist'
}
$cursor = Get-Item -LiteralPath $receiptParent -Force
while ($null -ne $cursor) {
    if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Receipt path contains a reparse point'
    }
    $cursor = $cursor.Parent
}
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
    $receiptItem = Get-Item -LiteralPath $Receipt -Force
    if ($receiptItem.PSIsContainer -or
        ($receiptItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Receipt is not a regular file'
    }
    $lines = @(Get-Content -LiteralPath $Receipt)
    if ($lines.Count -ne 4 -or $lines[0] -ne 'classmesh_teacher_message_ack_v1' -or
        $lines[1] -notmatch '^control_session_id=[1-9][0-9]*$' -or
        $lines[2] -notmatch '^request_id=[1-9][0-9]*$' -or
        $lines[3] -ne 'worker_state=Completed') {
        throw 'Invalid completion receipt format'
    }
    $verifiedServicePid = Assert-ReadyService $ServiceName $TrustedSignerThumbprint
    if ($verifiedServicePid -cne $approvedServicePid) {
        throw 'Service process changed during ACK qualification; refusing evidence'
    }
    $qualificationPassed = $true
    Write-Output "ACK completed via approved Service: $Receipt"
} finally {
    if (-not $qualificationPassed -and (Test-Path -LiteralPath $Receipt -PathType Leaf)) {
        # Never follow or delete a redirected receipt during failure cleanup.
        $failedReceipt = Get-Item -LiteralPath $Receipt -Force -ErrorAction SilentlyContinue
        if ($null -ne $failedReceipt -and -not $failedReceipt.PSIsContainer -and
            ($failedReceipt.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
            Remove-Item -LiteralPath $Receipt -Force -ErrorAction SilentlyContinue
        }
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
