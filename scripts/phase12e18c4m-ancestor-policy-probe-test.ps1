[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$probe = Join-Path $PSScriptRoot 'phase12e18c4m-ancestor-policy-probe.ps1'
if (-not (Test-Path -LiteralPath $probe -PathType Leaf)) {
    throw 'RED: missing Windows native ancestor policy origin security probe'
}
$report = @(& $probe -Mode All)
foreach ($required in @(
    'SCM_ANCESTOR_PROTECTED_ALLOW',
    'SCM_ANCESTOR_USERS_WRITABLE_DENIED',
    'SCM_ANCESTOR_REPARSE_DENIED',
    'SCM_ANCESTOR_CLEANUP_COMPLETE'
)) {
    if ($report -notcontains $required) { throw "Missing native security witness: $required" }
}
'SCM_ANCESTOR_POLICY_PROBE_PASS'
