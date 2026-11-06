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

# Regression contract: reject all low-privilege mutation rights, not only the Write alias.
$source = Get-Content -LiteralPath $script -Raw
foreach ($right in @('WriteData','AppendData','Delete','DeleteSubdirectoriesAndFiles','ChangePermissions','TakeOwnership')) {
    if ($source -notmatch [regex]::Escape("::$right")) { throw "SCM ACL gate missing mutation right: $right" }
}
if ($source -notmatch 'Assert-ProtectedFile \$ServiceExe \$ExpectedServiceSha256') { throw 'Service executable integrity gate missing' }
'PASS: SCM ACL mutation-right regression contract'

# Both pinned executables must be checked again after startup verification and before SCM creation.
$verifyAt = $source.IndexOf('& $TrustedProvisionExe --verify-startup')
$createAt = $source.IndexOf('& sc.exe create $serviceName')
if ($verifyAt -lt 0 -or $createAt -le $verifyAt) { throw 'SCM verification/create sequence missing' }
$window = $source.Substring($verifyAt, $createAt - $verifyAt)
foreach ($check in @('Assert-ProtectedFile $ServiceExe $ExpectedServiceSha256', 'Assert-ProtectedFile $TrustedProvisionExe $ExpectedProvisionSha256')) {
    if (-not $window.Contains($check)) { throw "Post-verification pinned binary recheck missing: $check" }
}
'PASS: SCM post-verification integrity recheck contract (TOCTOU residual remains)'
