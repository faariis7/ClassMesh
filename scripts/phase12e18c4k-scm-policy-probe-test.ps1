[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'phase12e18c4k-scm-policy-probe.ps1'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) {
    throw 'RED: missing native SCM LocalSystem policy-file attestation probe'
}
$report = @(& $script -Mode All)
foreach ($required in @(
    'SCM_LOCAL_SYSTEM_SESSION0',
    'SCM_PROTECTED_POLICY_ALLOW',
    'SCM_USER_WRITABLE_FILE_DENIED',
    'SCM_USER_WRITABLE_DIRECTORY_DENIED',
    'SCM_WRONG_OWNER_DENIED',
    'SCM_LEAF_REPARSE_DENIED',
    'SCM_MISSING_PRIMARY_DENIED',
    'SCM_CLEANUP_COMPLETE'
)) {
    if ($report -notcontains $required) { throw "SCM witness absent: $required" }
}
'SCM_POLICY_PROBE_PASS'
