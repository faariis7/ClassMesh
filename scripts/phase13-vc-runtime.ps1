Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Parse-VcVersion {
    param([AllowEmptyString()][string]$Text)
    if ($Text -notmatch '^v?(14)\.(\d+)\.(\d+)(?:\.(\d+))?$') {
        throw "Invalid Visual C++ runtime/toolset version: $Text"
    }
    $revision = if ($Matches[4]) { $Matches[4] } else { '0' }
    [version]::Parse("$($Matches[1]).$($Matches[2]).$($Matches[3]).$revision")
}

function Assert-RuntimeSatisfiesToolset {
    param([version]$Minimum, [AllowNull()][version]$Installed)
    if ($null -eq $Installed) {
        throw "Microsoft Visual C++ x64 Redistributable is missing. Install the current Microsoft-signed x64 package: https://aka.ms/vc14/vc_redist.x64.exe"
    }
    if ($Installed -lt $Minimum) {
        throw "Microsoft Visual C++ x64 Redistributable $Installed is older than this bundle's MSVC toolset $Minimum. Update from https://aka.ms/vc14/vc_redist.x64.exe"
    }
}

function Get-BuildToolsetVersion {
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        throw 'Bundle indexing requires the Windows MSVC build host'
    }
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw 'vswhere.exe is missing' }
    $installation = (& $vswhere -latest -products '*' -property installationPath | Select-Object -First 1)
    if (-not $installation) { throw 'MSVC x64 build tools are missing' }
    $versionPath = Join-Path $installation 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt'
    if (-not (Test-Path -LiteralPath $versionPath -PathType Leaf)) { throw 'MSVC toolset version file is missing' }
    Parse-VcVersion ((Get-Content -LiteralPath $versionPath -Raw).Trim())
}

function Read-VcRuntimeRecord {
    param([Parameter(Mandatory = $true)][Microsoft.Win32.RegistryKey]$Key)
    $installed = $Key.GetValue('Installed', $null)
    if ($null -eq $installed) { return $null }
    if ($Key.GetValueKind('Installed') -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
        throw 'Visual C++ x64 Redistributable Installed registry value must be DWORD'
    }
    if ([int]$installed -ne 1) { return $null }
    if ($Key.GetValueKind('Version') -ne [Microsoft.Win32.RegistryValueKind]::String) {
        throw 'Visual C++ x64 Redistributable Version registry value must be REG_SZ'
    }
    Parse-VcVersion ([string]$Key.GetValue('Version', ''))
}

function Get-X64VcRuntimeVersion {
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        throw 'Visual C++ runtime preflight requires Windows'
    }
    Assert-X64CompatibleArchitecture ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)
    $versions = @()
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        try {
            $key = $root.OpenSubKey('SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64')
            if ($null -eq $key) { continue }
            try {
                $version = Read-VcRuntimeRecord $key
                if ($null -ne $version) { $versions += $version }
            } finally { $key.Close() }
        } finally { $root.Close() }
    }
    if ($versions.Count -eq 0) { return $null }
    if ($versions.Count -eq 2 -and $versions[0] -ne $versions[1]) {
        throw 'Conflicting Visual C++ x64 Redistributable registry versions'
    }
    $versions[0]
}

function Assert-X64CompatibleArchitecture {
    param([System.Runtime.InteropServices.Architecture]$Architecture)
    if ($Architecture -ne [System.Runtime.InteropServices.Architecture]::X64 -and
        $Architecture -ne [System.Runtime.InteropServices.Architecture]::Arm64) {
        throw "The Windows x64 bundle requires x64 Windows or Windows ARM64 with x64 emulation; found $Architecture"
    }
}

function Assert-BundleRuntime {
    param([Parameter(Mandatory = $true)]$Index)
    $minimum = Parse-VcVersion ([string]$Index.minimum_vc_runtime_version)
    $installed = Get-X64VcRuntimeVersion
    Assert-RuntimeSatisfiesToolset $minimum $installed
    Write-Host "vc_runtime_x64_version=$installed"
    Write-Host "minimum_vc_runtime_version=$minimum"
    Write-Host "os_architecture=$([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"
    $installed
}
