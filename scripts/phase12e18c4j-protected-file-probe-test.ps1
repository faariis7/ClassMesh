[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$probe = Join-Path $PSScriptRoot 'phase12e18c4j-protected-file-probe.ps1'
if (-not (Test-Path -LiteralPath $probe -PathType Leaf)) {
    throw 'RED: missing Windows-native protected file probe implementation'
}
$output = @(& $probe -Mode All)
foreach ($expected in @(
    'PROTECTED_FILE_ALLOW',
    'USER_WRITABLE_FILE_DENIED',
    'USER_WRITABLE_DIRECTORY_DENIED',
    'WRONG_OWNER_DENIED',
    'LEAF_REPARSE_DENIED',
    'MISSING_FILE_DENIED',
    'CLEANUP_COMPLETE'
)) {
    if (-not ($output -contains $expected)) {
        throw "Missing expected native witness: $expected"
    }
}
if ($LASTEXITCODE -ne 0) {
    throw "Native protected file probe exit code $LASTEXITCODE"
}
'SECURITY_PROBE_PASS'
