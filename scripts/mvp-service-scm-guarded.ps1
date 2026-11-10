# Disposable native SCM gate. Never provisions identity, CA, or ProgramData.
[CmdletBinding()]
param(
    [ValidateSet('Plan','Run')][string]$Mode = 'Plan',
    [string]$ServiceExe,
    [string]$TrustedProvisionExe,
    [string]$ExpectedServiceSha256,
    [string]$ExpectedProvisionSha256,
    [switch]$SecurityReviewApproved,
    [switch]$DisposableVmApproved,
    [ValidateRange(0,120)][int]$QualificationWindowSeconds = 0
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$serviceName = 'ClassMeshService'
if ($Mode -eq 'Plan') {
    'SCM_PLAN_ONLY: requires independently approved enrollment, protected install, elevated interactive admin, exact binary SHA256, successful --verify-startup, protected path/ACL, and exclusive disposable VM. No mutation.'
    return
}
if (-not $SecurityReviewApproved -or -not $DisposableVmApproved) {
    throw 'FAIL_CLOSED: independent security review and exclusive disposable VM approval required'
}
if ($env:OS -ne 'Windows_NT') { throw 'FAIL_CLOSED: native Windows required' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
    $identity.User.Value -eq 'S-1-5-18' -or [Diagnostics.Process]::GetCurrentProcess().SessionId -le 0) {
    throw 'FAIL_CLOSED: elevated interactive non-SYSTEM administrator required'
}
if ($ExpectedServiceSha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or
    $ExpectedProvisionSha256 -cnotmatch '^[a-fA-F0-9]{64}$') {
    throw 'FAIL_CLOSED: exact SHA256 pins required'
}
function Assert-ProtectedFile([string]$Path, [string]$ExpectedHash) {
    if (-not [IO.Path]::IsPathFullyQualified($Path)) { throw 'FAIL_CLOSED: absolute path required' }
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Extension -ne '.exe') { throw 'FAIL_CLOSED: executable file required' }
    if ((Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash -ne $ExpectedHash) {
        throw 'FAIL_CLOSED: executable SHA256 mismatch'
    }
    $cursor = $item
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'FAIL_CLOSED: reparse point in executable ancestry'
        }
        $acl = Get-Acl -LiteralPath $cursor.FullName
        # Owner display names are localized and may be renamed. Compare the
        # authoritative SID instead; translation failures must fail closed.
        try {
            $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        } catch {
            throw 'FAIL_CLOSED: executable ancestry owner SID unavailable'
        }
        if ($ownerSid -notin @('S-1-5-32-544','S-1-5-18')) {
            throw 'FAIL_CLOSED: executable ancestry owner is not SYSTEM/Administrators'
        }
        foreach ($rule in $acl.Access) {
            if ($rule.AccessControlType -ne 'Allow') { continue }
            $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            # Delete and ACL takeover are mutation capabilities even without Write.
            # Allow mutation only for trusted machine principals. A denylist misses
            # custom local groups, service accounts, and domain principals.
            $trustedMutationSids = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
            $mutation = [Security.AccessControl.FileSystemRights]::WriteData -bor
                [Security.AccessControl.FileSystemRights]::AppendData -bor
                [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
                [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
                [Security.AccessControl.FileSystemRights]::Delete -bor
                [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                [Security.AccessControl.FileSystemRights]::TakeOwnership
            if ($sid -notin $trustedMutationSids -and ($rule.FileSystemRights -band $mutation) -ne 0) {
                throw 'FAIL_CLOSED: low-privilege mutation permission in executable ancestry'
            }
        }
        # FileInfo does not expose DirectoryInfo.Parent as its own Parent; explicitly
        # ascend from the executable file to its containing directory, then to root.
        # Otherwise an unsafe writable ancestor can escape the ACL/reparse gate.
        if ($cursor -is [IO.FileInfo]) {
            $cursor = $cursor.Directory
        } else {
            $cursor = $cursor.Parent
        }
    }
}
if (-not $ServiceExe -or -not $TrustedProvisionExe) { throw 'FAIL_CLOSED: both executable paths required' }
Assert-ProtectedFile $ServiceExe $ExpectedServiceSha256
Assert-ProtectedFile $TrustedProvisionExe $ExpectedProvisionSha256
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw 'FAIL_CLOSED: ClassMeshService already exists; never replace or delete it'
}
# This is a readiness gate, not CA validation. CA/CSR/issuer review must precede this invocation.
& $TrustedProvisionExe --verify-startup
if ($LASTEXITCODE -ne 0) { throw 'FAIL_CLOSED: trusted startup verification failed' }
$created = $false
try {
    # Revalidate both pinned binaries after the external verifier returns; it may run for
    # an extended period. This narrows, but cannot eliminate, the SCM path TOCTOU window.
    Assert-ProtectedFile $ServiceExe $ExpectedServiceSha256
    Assert-ProtectedFile $TrustedProvisionExe $ExpectedProvisionSha256
    $bin = '"' + (Get-Item -LiteralPath $ServiceExe).FullName + '"'
    $expectedCommand = $bin
    $output = & sc.exe create $serviceName 'binPath=' $bin 'start=' 'demand' 'type=' 'own' 'obj=' 'LocalSystem' 2>&1
    if ($LASTEXITCODE -ne 0) { throw "SCM create failed: $($output -join ' | ')" }
    $created = $true
    # Bind the SCM configuration to the reviewed executable before the first start.
    # A successful sc.exe create alone does not establish the installed image path
    # or the LocalSystem account. Fail closed and let finally remove our service.
    $registered = Get-CimInstance Win32_Service -Filter "Name='ClassMeshService'"
    if ($null -eq $registered -or
        $registered.StartName -notin @('LocalSystem','NT AUTHORITY\\SYSTEM') -or
        $registered.StartMode -ne 'Manual') {
        throw 'FAIL_CLOSED: SCM registration account/start mode mismatch'
    }
    if (-not [string]::Equals($registered.PathName.Trim(), $expectedCommand, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'FAIL_CLOSED: SCM registered binary command mismatch'
    }
    Assert-ProtectedFile $ServiceExe $ExpectedServiceSha256
    Start-Service -Name $serviceName -ErrorAction Stop
    # SCM may report StartPending briefly after Start-Service returns. Bound the
    # wait and require a real Running process rather than treating a transition
    # state as either success or an immediate false failure.
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $svc = Get-CimInstance Win32_Service -Filter "Name='ClassMeshService'"
        if ($null -ne $svc -and $svc.State -eq 'Running' -and $svc.ProcessId -gt 0) { break }
        if ($null -eq $svc -or $svc.State -in @('Stopped','StopPending','Paused')) {
            throw 'FAIL_CLOSED: SCM service exited or disappeared before readiness'
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($null -eq $svc -or $svc.State -ne 'Running' -or $svc.StartName -notin @('LocalSystem','NT AUTHORITY\\SYSTEM') -or $svc.ProcessId -le 0) {
        throw 'FAIL_CLOSED: LocalSystem SCM runtime not verified'
    }
    # The SCM registration path is not proof of the image that actually started.
    # Query the running process and fail closed if its image is not the pinned,
    # protected executable. This is post-start evidence, not a TOCTOU cure.
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($svc.ProcessId)"
    if ($null -eq $process -or [string]::IsNullOrWhiteSpace($process.ExecutablePath)) {
        throw 'FAIL_CLOSED: running Service image path unavailable'
    }
    $expectedImage = (Get-Item -LiteralPath $ServiceExe).FullName
    if (-not [string]::Equals($process.ExecutablePath, $expectedImage, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'FAIL_CLOSED: running Service image path differs from pinned executable'
    }
    Assert-ProtectedFile $process.ExecutablePath $ExpectedServiceSha256
    # Windows services run in isolated Session 0; a Session 1 process is not
    # evidence of a genuine SCM-hosted service, even with a matching image.
    if ($process.SessionId -ne 0) {
        throw 'FAIL_CLOSED: SCM Service process is not isolated in Session 0'
    }
    # SCM StartName describes configuration, not the token of the running PID.
    # Verify the actual process owner SID via CIM before reporting LocalSystem.
    $ownerResult = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
    if ($null -eq $ownerResult -or $ownerResult.ReturnValue -ne 0 -or
        $ownerResult.Sid -ne 'S-1-5-18') {
        throw 'FAIL_CLOSED: running Service process token is not LocalSystem'
    }
    # Rebind the evidence to the same live SCM process after all CIM queries.
    # A stopped/restarted service or PID change invalidates earlier image/token
    # observations, even if each individual query appeared successful.
    $finalService = Get-CimInstance Win32_Service -Filter "Name='ClassMeshService'"
    if ($null -eq $finalService -or $finalService.State -ne 'Running' -or
        $finalService.ProcessId -ne $svc.ProcessId -or
        $finalService.StartName -notin @('LocalSystem','NT AUTHORITY\\SYSTEM') -or
        $finalService.StartMode -ne 'Manual' -or
        -not [string]::Equals($finalService.PathName.Trim(), $expectedCommand, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'FAIL_CLOSED: SCM process or registration changed during runtime attestation'
    }
    "SCM_LOCALSYSTEM_RUNNING_PID=$($svc.ProcessId); IMAGE_PIN_VERIFIED; WORKER_IPC_NOT_YET_PROVEN"
    if ($QualificationWindowSeconds -gt 0) {
        # The only authorized hold is *after* both independent approval gates,
        # exact signed image/ACL/Session0/token attestation, and SCM readiness.
        # The separate Teacher process must be run from a NON-elevated session:
        # invoking it here would inherit administrator privileges.
        . (Join-Path $PSScriptRoot 'Wait-ApprovedM2QualificationWindow.ps1')
        Wait-ApprovedM2QualificationWindow -ServiceName $serviceName             -ServicePid ([int]$svc.ProcessId)             -ExpectedImage $expectedImage             -ExpectedCreationDate ([string]$process.CreationDate)             -Seconds $QualificationWindowSeconds
        # A timed window is not Worker or Teacher completion evidence. Return
        # to the pre-existing bounded stop/delete `finally` without marking M2.
        Assert-ProtectedFile $ServiceExe $ExpectedServiceSha256
    }
} finally {
    if ($created) {
        # Never stop/delete a service whose SCM identity changed after our create.
        # A name match alone is insufficient to prove that cleanup owns the service.
        $cleanupRegistration = Get-CimInstance Win32_Service -Filter "Name='ClassMeshService'"
        if ($null -eq $cleanupRegistration -or
            $cleanupRegistration.StartName -notin @('LocalSystem','NT AUTHORITY\\SYSTEM') -or
            $cleanupRegistration.StartMode -ne 'Manual' -or
            -not [string]::Equals($cleanupRegistration.PathName.Trim(), $expectedCommand, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'FAIL_CLOSED: SCM cleanup ownership mismatch; do not stop or delete service; manual investigation required'
        }
        $live = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $live -and $live.Status -ne 'Stopped') {
            Stop-Service -Name $serviceName -ErrorAction Stop
            $live.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))
        }
        # Stop-Service is an external operation: SCM registration can be replaced
        # between our initial ownership check and deletion. Re-attest immediately
        # before the destructive delete; never delete a foreign replacement.
        $beforeDelete = Get-CimInstance Win32_Service -Filter "Name='ClassMeshService'"
        if ($null -eq $beforeDelete -or
            $beforeDelete.State -ne 'Stopped' -or
            $beforeDelete.StartName -notin @('LocalSystem','NT AUTHORITY\\SYSTEM') -or
            $beforeDelete.StartMode -ne 'Manual' -or
            -not [string]::Equals($beforeDelete.PathName.Trim(), $expectedCommand, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'FAIL_CLOSED: SCM registration changed before delete; manual investigation required'
        }
        & sc.exe delete $serviceName | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'SCM cleanup failed; manual investigation required' }
        # sc.exe delete may only mark a service for deletion while SCM handles
        # remain open. Never claim removal until its registration disappears.
        $deleteDeadline = [DateTime]::UtcNow.AddSeconds(15)
        do {
            $remaining = Get-CimInstance Win32_Service -Filter "Name='ClassMeshService'"
            if ($null -eq $remaining) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $deleteDeadline)
        if ($null -ne $remaining) {
            throw 'FAIL_CLOSED: SCM service still registered after delete; manual investigation required'
        }
        'SCM_DISPOSABLE_SERVICE_REMOVED; protected enrollment state intentionally retained'
    }
}
