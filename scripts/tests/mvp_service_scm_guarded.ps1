# Cross-platform nonmutating contract checks. Native positive SCM needs approved VM.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot '../mvp-service-scm-guarded.ps1'
$plan = & $script -Mode Plan
if ($plan -notmatch 'SCM_PLAN_ONLY') { throw 'Missing nonmutating plan marker' }
# Windows Server and supported ARM64 test VMs may ship only Windows PowerShell
# 5.1. Use its native interpreter on Windows; pwsh remains the cross-platform
# interpreter. A missing optional PowerShell 7 must not block M2 fail-closed
# SCM rehearsals or encourage installing/changing VM policy.
if ($env:OS -eq 'Windows_NT') {
    $shell = (Get-Command powershell.exe -ErrorAction Stop).Source
    $hostFlags = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass')
} else {
    $shell = (Get-Command pwsh -ErrorAction Stop).Source
    $hostFlags = @('-NoProfile', '-NonInteractive')
}
$cases = @(
    @{ Args = @('-Mode','Run'); Match = 'independent security review' },
    @{ Args = @('-Mode','Run','-QualificationWindowSeconds','120'); Match = 'independent security review' },
    @{ Args = @('-Mode','Run','-SecurityReviewApproved','-DisposableVmApproved'); Match = 'native Windows required' }
)
foreach ($case in $cases) {
    if ($env:OS -eq 'Windows_NT' -and $case.Match -eq 'native Windows required') { continue }
    # Test the guard in an isolated child process. Negative `throw` output is
    # expected; PowerShell 5.1 surfaces redirected native stderr as an error
    # record under Stop, so preserve that message without suppressing the gate.
    try {
        $output = & $shell @hostFlags -File $script @($case.Args) 2>&1 | Out-String
    } catch {
        $output = $_ | Out-String
    }
    if ($output -notmatch [regex]::Escape($case.Match)) { throw "Expected fail-closed marker missing: $($case.Match): $output" }
}
'PASS: Plan nonmutating; unapproved invocation rejects; non-Windows invocation rejects'

# Regression contract: reject all low-privilege mutation rights, not only the Write alias.
$source = Get-Content -LiteralPath $script -Raw
foreach ($right in @('WriteData','AppendData','WriteAttributes','WriteExtendedAttributes','Delete','DeleteSubdirectoriesAndFiles','ChangePermissions','TakeOwnership')) {
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

# Unknown local/domain principals must never inherit executable mutation rights.
if ($source -notmatch [regex]::Escape('$sid -notin $trustedMutationSids')) {
    throw 'Unknown ACL principal fail-closed gate missing'
}
foreach ($trustedSid in @('S-1-5-18','S-1-5-32-544')) {
    if (-not $source.Contains($trustedSid)) { throw "Trusted principal missing: $trustedSid" }
}
if ($source -match [regex]::Escape('$sid -in $untrusted')) {
    throw 'Legacy low-privilege SID denylist must not control mutation decisions'
}
'PASS: SCM ACL allowlist rejects unknown mutation principals'

# Post-start evidence must bind the actual SCM process image to the pinned binary.
foreach ($needle in @('Get-CimInstance Win32_Process', 'ExecutablePath', 'running Service image path differs', 'Assert-ProtectedFile $process.ExecutablePath $ExpectedServiceSha256', 'IMAGE_PIN_VERIFIED')) {
    if (-not $source.Contains($needle)) { throw "Missing runtime image attestation: $needle" }
}
$startAt = $source.IndexOf('Start-Service -Name $serviceName')
$runtimeAt = $source.IndexOf('Get-CimInstance Win32_Process')
$successAt = $source.IndexOf('IMAGE_PIN_VERIFIED')
if ($startAt -lt 0 -or $runtimeAt -le $startAt -or $successAt -le $runtimeAt) {
    throw 'Running image attestation must follow SCM start and precede success'
}
'PASS: SCM runtime image path/hash fail-closed contract'

# Registered SCM configuration must be checked before the first service start.
$createAt = $source.IndexOf('& sc.exe create $serviceName')
$registeredAt = $source.IndexOf('$registered = Get-CimInstance Win32_Service')
$startAt = $source.IndexOf('Start-Service -Name $serviceName')
if ($registeredAt -le $createAt -or $startAt -le $registeredAt) {
    throw 'SCM registration verification must follow create and precede start'
}
$registrationWindow = $source.Substring($registeredAt, $startAt - $registeredAt)
foreach ($needle in @('StartName','StartMode','PathName.Trim()','SCM registered binary command mismatch','Assert-ProtectedFile $ServiceExe $ExpectedServiceSha256')) {
    if (-not $registrationWindow.Contains($needle)) { throw "SCM pre-start registration gate missing: $needle" }
}
'PASS: SCM pre-start registered image/account verification contract'

# Protected ancestry ownership must be checked by stable SID, not localized
# account display names. Failure to obtain a SID must fail closed.
foreach ($needle in @('GetOwner([Security.Principal.SecurityIdentifier])', 'owner SID unavailable', "'S-1-5-32-544','S-1-5-18'")) {
    if (-not $source.Contains($needle)) { throw "Owner SID validation missing: $needle" }
}
if ($source.Contains('if ($acl.Owner -notmatch')) {
    throw 'Localized ACL owner-name comparison must not control trust'
}
'PASS: SCM ancestry owner validation uses stable SIDs'

# The protected-file check must walk from FileInfo to its containing DirectoryInfo,
# then through every parent. FileInfo.Parent alone silently skips directory ACLs.
foreach ($needle in @('$cursor -is [IO.FileInfo]', '$cursor = $cursor.Directory', '$cursor = $cursor.Parent')) {
    if (-not $source.Contains($needle)) { throw "Executable ancestor traversal missing: $needle" }
}
if ($source.IndexOf('$cursor = $cursor.Directory') -gt $source.IndexOf('$cursor = $cursor.Parent')) {
    throw 'Executable file must transition to its directory before parent traversal'
}
'PASS: executable and directory ancestry are both checked'



# Readiness must be bounded, fail closed on early termination, and precede
# runtime image attestation. This is a static contract, not native SCM evidence.
$startAt = $source.IndexOf('Start-Service -Name $serviceName')
$deadlineAt = $source.IndexOf('$deadline = [DateTime]::UtcNow.AddSeconds(15)')
$processAt = $source.IndexOf('Get-CimInstance Win32_Process')
if ($startAt -lt 0 -or $deadlineAt -le $startAt -or $processAt -le $deadlineAt) {
    throw 'Bounded SCM readiness check must precede runtime image attestation'
}
foreach ($needle in @('Start-Sleep -Milliseconds 250', "State -in @('Stopped','StopPending','Paused')", 'SCM service exited or disappeared before readiness', '[DateTime]::UtcNow -lt $deadline')) {
    if (-not $source.Contains($needle)) { throw "SCM readiness fail-closed guard missing: $needle" }
}
'PASS: bounded SCM readiness and early-exit contract'

# Runtime identity must be proven from the actual PID token, not SCM StartName.
$processAt = $source.IndexOf('Get-CimInstance Win32_Process')
$ownerAt = $source.IndexOf('Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid')
$successAt = $source.IndexOf('SCM_LOCALSYSTEM_RUNNING_PID=')
if ($processAt -lt 0 -or $ownerAt -le $processAt -or $successAt -le $ownerAt) {
    throw 'Actual LocalSystem process SID attestation must precede runtime success'
}
foreach ($needle in @('$ownerResult.ReturnValue -ne 0', '$ownerResult.Sid -ne ''S-1-5-18''', 'running Service process token is not LocalSystem')) {
    if (-not $source.Contains($needle)) { throw "SCM process token attestation missing: $needle" }
}
'PASS: SCM actual process owner SID attestation contract'

# Cleanup must not stop/delete a service that no longer matches the registration
# created by this harness. Static ordering check only; native race needs VM proof.
$cleanupAt = $source.IndexOf('$cleanupRegistration = Get-CimInstance Win32_Service')
$stopAt = $source.IndexOf('Stop-Service -Name $serviceName')
$deleteAt = $source.IndexOf('& sc.exe delete $serviceName')
if ($cleanupAt -lt 0 -or $stopAt -le $cleanupAt -or $deleteAt -le $stopAt) {
    throw 'SCM cleanup ownership attestation must precede stop and delete'
}
$cleanupWindow = $source.Substring($cleanupAt, $stopAt - $cleanupAt)
foreach ($needle in @('StartName', 'StartMode', 'PathName.Trim()', '$expectedCommand', 'SCM cleanup ownership mismatch')) {
    if (-not $cleanupWindow.Contains($needle)) { throw "SCM cleanup ownership guard missing: $needle" }
}
$pinAt = $source.IndexOf('$expectedCommand = $bin')
$createAt = $source.IndexOf('& sc.exe create $serviceName')
if ($pinAt -lt 0 -or $pinAt -ge $createAt) { throw 'Cleanup identity must be pinned before SCM creation' }
'PASS: SCM cleanup refuses changed service registration before stop/delete'

# Runtime evidence must still describe the same running SCM PID after token
# and image checks; restart/PID changes invalidate earlier observations.
$ownerAt = $source.IndexOf('Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid')
$finalAt = $source.IndexOf('$finalService = Get-CimInstance Win32_Service')
$successAt = $source.IndexOf('SCM_LOCALSYSTEM_RUNNING_PID=')
if ($ownerAt -lt 0 -or $finalAt -le $ownerAt -or $successAt -le $finalAt) {
    throw 'Final SCM PID attestation must follow token proof and precede success'
}
$finalWindow = $source.Substring($finalAt, $successAt - $finalAt)
foreach ($needle in @('$finalService.State -ne ''Running''', '$finalService.ProcessId -ne $svc.ProcessId', 'SCM process or registration changed during runtime attestation')) {
    if (-not $finalWindow.Contains($needle)) { throw "Final SCM runtime binding missing: $needle" }
}
'PASS: SCM runtime evidence rebinds unchanged live PID before success'

# A successful sc.exe delete only requests removal; SCM may retain the
# registration until outstanding handles close. Do not claim cleanup early.
$deleteAt = $source.IndexOf('& sc.exe delete $serviceName')
$waitAt = $source.IndexOf('$deleteDeadline = [DateTime]::UtcNow.AddSeconds(15)')
$absentAt = $source.IndexOf('if ($null -ne $remaining)')
$removedAt = $source.IndexOf('SCM_DISPOSABLE_SERVICE_REMOVED')
if ($deleteAt -lt 0 -or $waitAt -le $deleteAt -or $absentAt -le $waitAt -or $removedAt -le $absentAt) {
    throw 'SCM deletion must be observed before reporting disposable cleanup'
}
foreach ($needle in @('Get-CimInstance Win32_Service -Filter', 'SCM service still registered after delete', '[DateTime]::UtcNow -lt $deleteDeadline')) {
    if (-not $source.Substring($waitAt, $removedAt - $waitAt).Contains($needle)) {
        throw "SCM deletion confirmation guard missing: $needle"
    }
}
'PASS: SCM deletion confirmation is bounded and fail-closed'

# The actual SCM-hosted PID must be isolated in Session 0, not the
# interactive Teacher/Worker Session 1. Static check, not VM proof.
$processAt = $source.IndexOf('Get-CimInstance Win32_Process')
$sessionAt = $source.IndexOf('$process.SessionId -ne 0')
$successAt = $source.IndexOf('SCM_LOCALSYSTEM_RUNNING_PID=')
if ($processAt -lt 0 -or $sessionAt -le $processAt -or $successAt -le $sessionAt) {
    throw 'SCM Session 0 attestation must follow process lookup and precede success'
}
if (-not $source.Contains('SCM Service process is not isolated in Session 0')) {
    throw 'Missing Session 0 fail-closed diagnostic'
}
'PASS: SCM process Session 0 isolation contract'

# The positive, separately approved LocalSystem SCM lifetime must retain a
# bounded window for a non-admin Teacher qualification *after* token/image
# proof and *before* the unchanged cleanup finally. It may not weaken approval.
$readyAt = $source.IndexOf('SCM_LOCALSYSTEM_RUNNING_PID=')
$holdAt = $source.IndexOf('Wait-ApprovedM2QualificationWindow @qualification')
$cleanupAt = $source.LastIndexOf('} finally {')
if ($readyAt -lt 0 -or $holdAt -le $readyAt -or $cleanupAt -le $holdAt) {
    throw 'Approved M2 qualification window not bounded between SCM proof and owned cleanup'
}
if (-not $source.Contains('QualificationWindowSeconds') -or
    -not $source.Contains('Assert-ProtectedFile $ServiceExe $ExpectedServiceSha256')) {
    throw 'Approved qualification window or source image re-verification missing'
}
'PASS: approved qualification hold follows live attestation and precedes owned cleanup'
