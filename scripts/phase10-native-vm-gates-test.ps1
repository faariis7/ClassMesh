[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$helper = Join-Path $PSScriptRoot 'phase10-native-vm-gates.ps1'
if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) {
    throw 'RED: Phase 10 native Windows least-privilege helper is missing'
}

$help = @(& $helper -Mode Help)
if (-not (@($help | Where-Object { $_ -match 'not physical two-host' }).Count -gt 0)) {
    throw 'Help must not misrepresent a VM as physical two-host qualification'
}

$plan = @(& $helper -Mode Plan)
foreach ($line in @(
    'NONADMIN: cargo fmt --all -- --check',
    'NONADMIN: cargo clippy -p classmesh-worker -p classmesh-control --all-targets -- -D warnings',
    'NONADMIN: cargo test -p classmesh-worker --lib',
    'NONADMIN: cargo test -p classmesh-control',
    'ADMIN-ONLY: cargo test -p classmesh-identity-win --lib'
)) {
    if ($plan -notcontains $line) {
        throw "Missing expected bounded test command: $line"
    }
}
if (@($plan | Where-Object { $_ -match 'cargo test --workspace|--all-features|Start-Process.*RunAs' }).Count -gt 0) {
    throw 'Plan must never attempt broad privileged workspace execution'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $blocked = $false
    try {
        & $helper -Mode MachineKey
    } catch {
        if ($_.Exception.Message -match 'requires Administrator') {
            $blocked = $true
        } else {
            throw
        }
    }
    if (-not $blocked) {
        throw 'Standard account must not enter machine-key CNG test suite'
    }
} else {
    $blocked = $false
    try {
        & $helper -Mode Receiver
    } catch {
        if ($_.Exception.Message -match 'requires standard non-elevated') {
            $blocked = $true
        } else {
            throw
        }
    }
    if (-not $blocked) {
        throw 'Elevated account must not execute receiver-only test suite'
    }
}
'PHASE10_NATIVE_VM_GATE_CONTRACT_PASS'