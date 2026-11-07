[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$RepositoryRoot,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{40}$')][string]$ExpectedSha,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory
)
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Requires Windows and real CNG' }
$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run explicitly in an elevated test session' }
$RepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
if ($RepositoryRoot -match '[&|<>^%"\r\n]') { throw 'Repository path contains shell metacharacters' }
$source = (& git -C $RepositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -or $source -ne $ExpectedSha) { throw 'Source SHA mismatch' }
& git -C $RepositoryRoot diff --quiet
if ($LASTEXITCODE) { throw 'Tracked source changes present' }
$untracked = @(& git -C $RepositoryRoot ls-files --others --exclude-standard -- tools/classmesh-lab)
if ($LASTEXITCODE -or $untracked.Count) { throw 'Untracked tool source present' }
$temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$parent = [IO.Path]::GetFullPath((Split-Path -Parent $EvidenceDirectory)).TrimEnd('\')
if ($parent -ne $temp -or (Test-Path -LiteralPath $EvidenceDirectory)) { throw 'Evidence must be a new direct child of TEMP' }
$lease = [Threading.Mutex]::new($false, 'Global\ClassMesh-Lab-Exclusive')
$held = $false
$oldTarget = $env:CARGO_TARGET_DIR
try {
    $held = $lease.WaitOne(0)
    if (-not $held) { throw 'Another lab operation holds the VM lease' }
    $busy = @(Get-CimInstance Win32_Process | Where-Object {
        $_.ProcessId -ne $PID -and (
            $_.Name -match '^(cargo|rustc|classmesh.*|ctest|msbuild|cl)\.exe$' -or
            ($_.Name -match '^(powershell|pwsh)\.exe$' -and $_.CommandLine -match '(classmesh|phase[0-9]|cargo|rustc)' -and $_.CommandLine -notmatch 'Get-CimInstance Win32_Process')
        )
    })
    if ($busy.Count) { throw ('VM has active test/build processes: ' + (($busy | ForEach-Object { $_.Name + ':' + $_.ProcessId }) -join ',')) }
    if (@(Get-Service '*classmesh*' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running').Count) { throw 'ClassMesh service already running; coordinate VM use first' }
    New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
    function RootSnapshot {
        $values = @(Get-ChildItem Cert:\LocalMachine\Root,Cert:\CurrentUser\Root | ForEach-Object { $_.PSParentPath + ':' + $_.Thumbprint } | Sort-Object)
        $sha = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($values -join "`n"))))).Replace('-','').ToLowerInvariant() }
        finally { $sha.Dispose() }
    }
    $before = RootSnapshot
    $vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
    $vs = & $vswhere -latest -products '*' -property installationPath
    if (-not $vs -or -not (Test-Path ($vs+'\Common7\Tools\VsDevCmd.bat'))) { throw 'Existing Visual Studio C++ tools required' }
    $cargo = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    $env:CARGO_TARGET_DIR = Join-Path $RepositoryRoot 'target'
    $batch = Join-Path $EvidenceDirectory 'run.cmd'
    @('@echo off',('call "'+$vs+'\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul'),
      'if errorlevel 1 exit /b %errorlevel%',('"'+$cargo+'" +stable-x86_64-pc-windows-msvc test -p classmesh-lab --all-targets --offline -- --nocapture --test-threads=1'),
      'exit /b %errorlevel%') | Set-Content -LiteralPath $batch -Encoding ASCII
    Push-Location $RepositoryRoot
    try {
        # Redirect in cmd so PowerShell 5.1 does not turn compiler stderr into a terminating NativeCommandError.
        & cmd.exe /d /c ('"'+$batch+'" > "'+(Join-Path $EvidenceDirectory 'native.log')+'" 2>&1')
        $exitCode = $LASTEXITCODE
    } finally { Pop-Location }
    $after = RootSnapshot
    $hashes = @('classmesh-lab-ca','classmesh-enrollment-request','classmesh-enrollment-authority','classmesh-enrollment-install','classmesh-student-authorization-init') | ForEach-Object {
        $file = Join-Path $env:CARGO_TARGET_DIR ('debug\'+$_+'.exe')
        if (Test-Path $file) { [pscustomobject]@{path=$file;sha256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()} }
    }
    $evidence = [ordered]@{source_sha=$source;windows_host=$env:COMPUTERNAME;time_utc=[DateTime]::UtcNow.ToString('o');
        exit_code=$exitCode;root_store_before=$before;root_store_after=$after;root_store_unchanged=($before -eq $after);
        vm_busy_before=$false;executables=@($hashes);scope='TEMP staging and owned CNG test keys; no SCM or ClassMesh ProgramData installation'}
    $evidence | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'evidence.json') -Encoding UTF8
    Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'native.log')
    if ($exitCode -ne 0 -or $before -ne $after) { throw ('Native test or trust-store invariant failed; exit='+$exitCode) }
    'WINDOWS_LAB_ENROLLMENT=PASS; source='+$source
} finally {
    $env:CARGO_TARGET_DIR = $oldTarget
    if ($held) { $lease.ReleaseMutex() }
    $lease.Dispose()
}
