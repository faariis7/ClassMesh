$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../Assert-TeacherMessageInput.ps1')
function MustReject([string]$value) {
    $rejected = $false
    try { Assert-TeacherMessageInput $value } catch { $rejected = $true }
    if (-not $rejected) { throw 'Unsafe message was accepted' }
}
Assert-TeacherMessageInput ('a' * 4096)
MustReject ('a' * 4097)
Assert-TeacherMessageInput ([string]::Concat([char]0x00E9, ('a' * 4094)))
MustReject ([string]::Concat([char]0x00E9, ('a' * 4095)))
MustReject ([string]::Concat('a', [char]0, 'b'))
MustReject ([string]::Concat('a', [char]0xD800))
MustReject ''
'PASS: bounded UTF-8 Teacher message input'
