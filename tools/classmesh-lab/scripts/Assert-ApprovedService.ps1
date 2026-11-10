#Requires -Version 5.1
# Authorized Service/SCM process attestation used by live M2 Teacher acceptance.
function Assert-ApprovedSignature([string]$Path, [string]$ExpectedThumbprint) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Missing signed executable: $Path" }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
        throw "Executable Authenticode signature is not valid: $Path"
    }
    $actual = ($signature.SignerCertificate.Thumbprint -replace '\s','').ToUpperInvariant()
    $expected = ($ExpectedThumbprint -replace '\s','').ToUpperInvariant()
    if ($expected.Length -ne 40 -or $actual -cne $expected) {
        throw "Executable signer does not match approved thumbprint"
    }
}

function Assert-ReadyService([string]$Name, [string]$ExpectedThumbprint) {
    $service = Get-CimInstance Win32_Service -Filter ("Name='" + $Name.Replace("'","''") + "'")
    if ($null -eq $service -or $service.State -ne 'Running' -or $service.StartName -ne 'LocalSystem') {
        throw "Approved LocalSystem Service must already be running"
    }
    $commandLine = [string]$service.PathName
    if ($commandLine -match '^\s*"([^"]+\.exe)"(?:\s|$)') {
        $binary = $Matches[1]
    } elseif ($commandLine -match '^\s*([^\s"]+\.exe)(?:\s|$)') {
        $binary = $Matches[1]
    } else {
        throw "Cannot safely identify installed Service executable"
    }
    # The SCM image is also provisioned input. A valid signature at a
    # symlink/junction target does not approve a redirectable service path.
    Assert-NoReparsePath $binary
    Assert-ApprovedSignature $binary $ExpectedThumbprint
    # A shared-process service cannot establish ownership of the interactive Worker.
    # Require the approved Service to have its own SCM process, not svchost hosting peers.
    if ([string]$service.ServiceType -ne 'Own Process') {
        throw 'Approved Service must be an SCM own-process service'
    }
    if ([int64]$service.ProcessId -le 0) { throw 'Service has no running process ID' }
    $serviceProcess = Get-CimInstance Win32_Process -Filter ("ProcessId=" + [string]$service.ProcessId)
    if ($null -eq $serviceProcess -or [int]$serviceProcess.SessionId -ne 0) {
        throw 'Approved LocalSystem Service must execute in Session 0'
    }
    # The SCM configuration is not evidence of the image actually executing.
    # Reject a replaced process or inaccessible image metadata (fail closed).
    if ([string]::IsNullOrWhiteSpace([string]$serviceProcess.ExecutablePath) -or
        -not [string]::Equals(
            [System.IO.Path]::GetFullPath($binary),
            [System.IO.Path]::GetFullPath([string]$serviceProcess.ExecutablePath),
            [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Running Service image differs from signed SCM image'
    }
    # SCM StartName is registration metadata, not proof of the Windows token
    # actually carried by the live process. Require authoritative GetOwnerSid
    # for this SAME bound PID (Session 0 / image / creation time), and reject
    # access-denied or malformed responses rather than trusting config alone.
    try {
        $owner = Invoke-CimMethod -InputObject $serviceProcess -MethodName GetOwnerSid -ErrorAction Stop
    } catch {
        throw 'Running Service process owner SID unavailable'
    }
    if ($null -eq $owner -or $owner.ReturnValue -ne 0 -or $owner.Sid -cne 'S-1-5-18') {
        throw 'Running Service process is not LocalSystem (S-1-5-18)'
    }
    if ($null -eq $serviceProcess.CreationDate) {
        throw 'Running Service creation time unavailable'
    }
    return ([string]$service.ProcessId + '|' + [string]$serviceProcess.CreationDate)
}
