# Cross-platform nonmutating contract checks. Native positive SCM needs approved VM.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot '../mvp-service-scm-guarded.ps1'
$plan = & $script -Mode Plan
if ($plan -notmatch 'SCM_PLAN_ONLY') { throw 'Missing nonmutating plan marker' }
$cases = @(
    @{ Args = @('-Mode','Run'); Match = 'independent security review' },
    @{ Args = @('-Mode','Run','-SecurityReviewApproved','-DisposableVmApproved'); Match = 'native Windows required' }
)
foreach ($case in $cases) {
    if ($env:OS -eq 'Windows_NT' -and $case.Match -eq 'native Windows required') { continue }
    $output = & pwsh -NoProfile -File $script @($case.Args) 2>&1 | Out-String
    if ($output -notmatch [regex]::Escape($case.Match)) { throw "Expected fail-closed marker missing: $($case.Match)" }
}
'PASS: Plan nonmutating; unapproved invocation rejects; non-Windows invocation rejects'
