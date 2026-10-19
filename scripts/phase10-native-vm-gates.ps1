[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Help', 'Plan', 'Receiver', 'MachineKey')]
    [string]$Mode,

    [string]$RepoRoot = '',
    [string]$ClangBin = '',
    [string]$TargetDir = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

switch ($Mode) {
    'Help' {
@'
ClassMesh native Windows least-privilege verification (Phase 10)

Modes:
  Help        Read this help; no commands run
  Plan        Print both bounded cargo gates; no commands run
  Receiver    Must run as a standard NON-elevated Windows user
  MachineKey  Must run as an elevated Administrator (CNG machine keys only)

Examples:
  .\scripts\phase10-native-vm-gates.ps1 -Mode Receiver
  .\scripts\phase10-native-vm-gates.ps1 -Mode MachineKey
  .\scripts\phase10-native-vm-gates.ps1 -Mode Receiver -RepoRoot C:\src\ClassMesh -ClangBin C:\LLVM\bin -TargetDir C:\temp\cm-target

No automatic elevation, installation, credential changes or Windows policy
changes. Do not run the entire workspace as Administrator: Phase 12 protected
file, registry, SCM and enrollment tests have independent native gates.
VM verification is not physical two-host, GPU or classroom-scale qualification.
'@
        return
    }
    'Plan' {
        'NONADMIN: cargo fmt --all -- --check'
        'NONADMIN: cargo clippy -p classmesh-worker -p classmesh-control --all-targets -- -D warnings'
        'NONADMIN: cargo test -p classmesh-worker --lib'
        'NONADMIN: cargo test -p classmesh-control'
        'ADMIN-ONLY: cargo test -p classmesh-identity-win --lib'
        return
    }
}

if ($env:OS -ne 'Windows_NT') {
    throw 'Native Windows test mode requires Windows'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($Mode -eq 'MachineKey' -and -not $isAdmin) {
    throw 'MachineKey mode requires Administrator: CNG creates non-exportable machine-scoped keys'
}
if ($Mode -eq 'Receiver' -and $isAdmin) {
    throw 'Receiver mode requires standard non-elevated Windows session'
}

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Split-Path $PSScriptRoot -Parent
}
if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot 'Cargo.toml') -PathType Leaf)) {
    throw 'RepoRoot must point to a ClassMesh Cargo workspace; Cargo.toml not found'
}

if (-not [string]::IsNullOrWhiteSpace($ClangBin)) {
    if (-not (Test-Path -LiteralPath (Join-Path $ClangBin 'clang.exe') -PathType Leaf)) {
        throw 'ClangBin must contain a locally installed clang.exe; nothing will be downloaded'
    }
    $ClangBin = (Resolve-Path -LiteralPath $ClangBin).Path
    $env:PATH = "$ClangBin;$env:PATH"
    $hostTriple = & rustc --print host-tuple
    if ($LASTEXITCODE -ne 0) {
        throw 'rustc host detection failed'
    }
    if ($hostTriple -eq 'aarch64-pc-windows-msvc') {
        $env:CC_aarch64_pc_windows_msvc = Join-Path $ClangBin 'clang.exe'
    }
}

if (-not [string]::IsNullOrWhiteSpace($TargetDir)) {
    $env:CARGO_TARGET_DIR = [IO.Path]::GetFullPath($TargetDir)
}
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw 'Cargo is not available on PATH'
}
Set-Location -LiteralPath $RepoRoot
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'Git is required to record the exact tested repository HEAD'
}
$testedCommit = & git rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $testedCommit -notmatch '^[0-9a-f]{40}$') {
    throw 'Unable to identify exact tested Git commit'
}
Write-Output "TESTED_COMMIT $testedCommit"

# Windows PowerShell 5.1 can present compiler stderr as NativeCommandError.
# Check the actual process exit code rather than treating all stderr as failure.
$ErrorActionPreference = 'Continue'

function Invoke-CheckedCargo {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    Write-Output "BEGIN $Label"
    & cargo @Arguments
    $exit = $LASTEXITCODE
    if ($exit -ne 0) {
        throw "FAILED $Label (cargo exit $exit)"
    }
    Write-Output "PASS $Label"
}

if ($Mode -eq 'MachineKey') {
    Invoke-CheckedCargo -Label 'CNG non-exportable machine identity' -Arguments @(
        'test', '-p', 'classmesh-identity-win', '--lib'
    )
} else {
    Invoke-CheckedCargo -Label 'Workspace rustfmt' -Arguments @(
        'fmt', '--all', '--', '--check'
    )
    Invoke-CheckedCargo -Label 'Worker and Service warnings denied' -Arguments @(
        'clippy', '-p', 'classmesh-worker', '-p', 'classmesh-control',
        '--all-targets', '--', '-D', 'warnings'
    )
    Invoke-CheckedCargo -Label 'Windows Worker library tests' -Arguments @(
        'test', '-p', 'classmesh-worker', '--lib'
    )
    Invoke-CheckedCargo -Label 'Service telemetry/control library and integration tests' -Arguments @(
        'test', '-p', 'classmesh-control'
    )
}
Write-Output "PHASE10_NATIVE_$($Mode)_PASS"
