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

# Security regression: an executable under a junction must not inherit approval
# just because the final file is not itself a reparse point. The path checker
# must walk FileInfo.Directory then every directory ancestor to the root.
if ($env:OS -eq 'Windows_NT') {
    . (Join-Path $PSScriptRoot '../Assert-TrustedTeacherPath.ps1')
    $fixture = Join-Path $env:TEMP ('ClassMesh-AckPath-'+[Guid]::NewGuid().ToString('N'))
    $real = Join-Path $fixture 'real'
    $junction = Join-Path $fixture 'junction'
    try {
        New-Item -ItemType Directory -LiteralPath $real -Force | Out-Null
        $file = Join-Path $real 'teacher.exe'
        Set-Content -LiteralPath $file -Value 'disposable-test-bytes' -Encoding ASCII
        Assert-NoReparsePath $file  # ordinary owned file is allowed
        New-Item -ItemType Junction -Path $junction -Target $real -ErrorAction Stop | Out-Null
        $rejected = $false
        try { Assert-NoReparsePath (Join-Path $junction 'teacher.exe') }
        catch { $rejected = $true }
        if (-not $rejected) { throw 'FAIL: redirected ancestor accepted as signed Teacher executable' }
        'PASS: redirected executable ancestor rejected'
    } finally {
        if ([IO.Directory]::Exists($junction)) { [IO.Directory]::Delete($junction) }
        if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
    }
}
