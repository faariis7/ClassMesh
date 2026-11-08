# Nonmutating entry-point tests, never evidence of Windows SCM/IPC success.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$runner = Join-Path $PSScriptRoot '../mvp-service-scm-guarded.ps1'
$plan = & $runner -Mode Plan -QualifyWorkerIpc
if (($plan -join "`n") -notmatch 'WORKER_IPC_QUALIFICATION_PLAN_ONLY') { throw 'Missing Worker runtime qualification plan' }
try {
    & $runner -Mode Run -QualifyWorkerIpc
    throw 'Unapproved runtime qualification was allowed'
} catch {
    if ($_.Exception.Message -notmatch 'independent security review') { throw }
}
'PASS: qualification Plan is nonmutating; unapproved Run rejected'
