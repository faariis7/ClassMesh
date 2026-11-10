$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../Assert-LocalAbsolutePath.ps1')
Assert-LocalAbsolutePath 'C:\ClassMesh\service.exe'
function MustReject([string]$value) {
    $rejected=$false
    try { Assert-LocalAbsolutePath $value } catch { $rejected=$true }
    if (-not $rejected) { throw "FAIL: unsafe Windows file path accepted: $value" }
}
MustReject 'C:relative.exe'
MustReject '\rooted-no-volume.exe'
MustReject '\\server\share\service.exe'
MustReject '.\relative.exe'
MustReject 'service.exe'
MustReject 'C:\ClassMesh\service.exe:evil'
'PASS: protected SCM paths require local fully-qualified volumes under Windows PowerShell 5.1'
