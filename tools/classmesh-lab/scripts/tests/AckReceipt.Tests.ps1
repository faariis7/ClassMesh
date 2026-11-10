$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../Assert-AckReceipt.ps1')
$root = Join-Path ([IO.Path]::GetTempPath()) ('classmesh-ack-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$receipt = Join-Path $root 'ack.txt'
function MustReject([string]$value) {
    [IO.File]::WriteAllText($receipt, $value)
    $failed = $false
    try { Assert-AckReceipt $receipt } catch { $failed = $true }
    if (-not $failed) { throw 'Invalid ACK evidence accepted' }
}
try {
    $valid = "classmesh_teacher_message_ack_v1`ncontrol_session_id=12`nrequest_id=9`nworker_state=Completed`n"
    [IO.File]::WriteAllText($receipt, $valid)
    Assert-AckReceipt $receipt
    MustReject ($valid + ('X' * 300))
    MustReject ($valid -replace 'Completed','Accepted')
    MustReject ($valid -replace 'request_id=9','request_id=0')
    MustReject ($valid -replace 'request_id=9','request_id=9`nrequest_id=10')
    'PASS: real receipt verifier accepts Completed and rejects oversized, Accepted, zero ID, duplicate'
} finally { Remove-Item -LiteralPath $root -Recurse -Force }
