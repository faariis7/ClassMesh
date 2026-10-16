[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows only' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Elevated admin required' }
$c4j = Join-Path $PSScriptRoot 'phase12e18c4j-protected-file-probe.ps1'
if (-not (Test-Path -LiteralPath $c4j -PathType Leaf)) { throw 'Missing prerequisite native predicate' }
$match = [regex]::Match([IO.File]::ReadAllText($c4j), "(?ms)^\`$nativeSource = @'\r?\n(.*?)\r?\n'@\r?$")
if (-not $match.Success) { throw 'Reviewed native predicate unavailable' }
Add-Type -TypeDefinition $match.Groups[1].Value -ErrorAction Stop
$id = [Guid]::NewGuid().ToString('N')
$folder = Join-Path $env:ProgramData ('classmesh-e18c4n-' + $id)
$primary = Join-Path $folder 'authorization.json'
$hardlink = Join-Path $folder 'alias.json'
try {
    New-Item -ItemType Directory -Path $folder | Out-Null
    & icacls.exe $folder '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'directory ACL fixture failed' }
    [IO.File]::WriteAllText($primary, '{"testOnly":true}')
    & icacls.exe $primary '/inheritance:r' '/grant:r' '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'file ACL fixture failed' }
    & fsutil.exe hardlink create $hardlink $primary | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'hardlink fixture creation failed' }
    $observed = [ClassMeshPolicyHandleAttestation]::Check($primary, $false)
    if ($observed -eq 'ALLOW') {
        throw 'RED: exact-handle owner/DACL predicate accepts multiply-linked policy inode; missing hardlink identity gate'
    }
    if ($observed -ne 'HARDLINK_DENIED') {
        throw "RED: expected explicit HARDLINK_DENIED, observed $observed"
    }
    'NATIVE_HARDLINK_ORIGIN_DENIED'
} finally {
    if (Test-Path -LiteralPath $folder) { Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction Stop }
}
