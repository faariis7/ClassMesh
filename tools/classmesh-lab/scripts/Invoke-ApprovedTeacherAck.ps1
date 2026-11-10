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
. (Join-Path $PSScriptRoot 'Assert-TeacherMessageInput.ps1')
. (Join-Path $PSScriptRoot 'Assert-TrustedTeacherPath.ps1')
. (Join-Path $PSScriptRoot 'Assert-AckReceipt.ps1')
. (Join-Path $PSScriptRoot 'Assert-ApprovedService.ps1')
. (Join-Path $PSScriptRoot 'Assert-NonElevatedTeacherSession.ps1')
Assert-NonElevatedTeacherSession

if ($TimeoutSeconds -lt 5 -or $TimeoutSeconds -gt 120) { throw 'TimeoutSeconds must be 5..120' }
Assert-TeacherMessageInput $Message
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
    $teacherStartUtc = [datetime]::UtcNow
    $process = Start-Process -FilePath $TeacherExe -ArgumentList ($arguments | ForEach-Object { '"' + $_ + '"' }) -PassThru -NoNewWindow
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        throw 'Teacher qualification timed out before Worker Completed'
    }
    if ($process.ExitCode -ne 0) { throw "Teacher qualification failed (exit $($process.ExitCode))" }
    if (-not (Test-Path -LiteralPath $Receipt -PathType Leaf)) {
        throw 'No correlated Completed receipt was produced'
    }
    Assert-AckReceipt $Receipt $teacherStartUtc
    $verifiedServicePid = Assert-ReadyService $ServiceName $TrustedSignerThumbprint
    if ($verifiedServicePid -cne $approvedServicePid) {
        throw 'Service process changed during ACK qualification; refusing evidence'
    }
    $qualificationPassed = $true
    Write-Output "ACK completed via approved Service: $Receipt"
} finally {
    # Stop the producer before removing failed evidence: otherwise a timed-out
    # Teacher can race cleanup and recreate the receipt after it was deleted.
    if ($null -ne $process) {
        try {
            $process.Refresh()
            if (-not $process.HasExited) {
                Stop-Process -Id $process.Id -Force -ErrorAction Stop
                if (-not $process.WaitForExit(5000)) {
                    throw 'Teacher did not terminate; failed evidence cannot be safely cleaned'
                }
            }
        } finally {
            $process.Dispose()
        }
    }
    if (-not $qualificationPassed -and (Test-Path -LiteralPath $Receipt -PathType Leaf)) {
        # Never follow or delete a redirected receipt during failure cleanup.
        $failedReceipt = Get-Item -LiteralPath $Receipt -Force -ErrorAction SilentlyContinue
        if ($null -ne $failedReceipt -and -not $failedReceipt.PSIsContainer -and
            ($failedReceipt.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
            Remove-Item -LiteralPath $Receipt -Force -ErrorAction SilentlyContinue
        }
    }
}
