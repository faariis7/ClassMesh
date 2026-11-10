#Requires -Version 5.1
# Validate bounded evidence emitted by the real enrolled Teacher CLI.
function Assert-AckReceipt([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Receipt is not a regular file'
    }
    # A compromised or malfunctioning producer must not force unbounded reads.
    if ($item.Length -gt 256 -or $item.Length -le 0) {
        throw 'Receipt size outside bounded ACK evidence'
    }
    $lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
    if ($lines.Count -ne 4 -or $lines[0] -cne 'classmesh_teacher_message_ack_v1' -or
        $lines[1] -cnotmatch '^control_session_id=[1-9][0-9]*$' -or
        $lines[2] -cnotmatch '^request_id=[1-9][0-9]*$' -or
        $lines[3] -cne 'worker_state=Completed') {
        throw 'Invalid completion receipt format'
    }
}
