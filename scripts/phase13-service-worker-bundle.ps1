[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Help', 'IndexBundle', 'ValidateBundle', 'PreflightRuntime')]
    [string]$Mode,
    [string]$BundleDir = 'phase13-service-worker-bundle'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'phase13-vc-runtime.ps1')

$SchemaVersion = 2
$Target = 'windows-x64'
$IndexName = 'service-worker-bundle-index.json'
$Executables = @('classmesh-service.exe', 'classmesh-worker.exe')
$RequiredFiles = @($Executables) + @('phase13-service-worker-bundle.ps1', 'phase13-vc-runtime.ps1', 'PHASE13_SERVICE_WORKER_PREREQUISITES.md')

function Bundle-Path {
    param([Parameter(Mandatory = $true)][string]$Name)
    Join-Path $BundleDir $Name
}

function Assert-NonEmptyFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required bundle file is missing: $Path"
    }
    $item = Get-Item -LiteralPath $Path
    if ($item.Length -le 0) { throw "Required bundle file is empty: $Path" }
    $item
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$Path)
    $file = [System.IO.File]::OpenRead($Path)
    try {
        $reader = [System.IO.BinaryReader]::new($file)
        try {
            if ($file.Length -lt 70 -or $reader.ReadUInt16() -ne 0x5a4d) {
                throw "Invalid Windows PE executable: $Path"
            }
            $file.Position = 0x3c
            $offset = $reader.ReadUInt32()
            if ($offset -lt 64 -or [long]$offset + 6 -gt $file.Length) {
                throw "Invalid Windows PE header offset: $Path"
            }
            $file.Position = $offset
            if ($reader.ReadUInt32() -ne 0x00004550) {
                throw "Invalid Windows PE signature: $Path"
            }
            $reader.ReadUInt16()
        } finally { $reader.Dispose() }
    } finally { $file.Dispose() }
}

function Assert-X64Pe {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ((Get-PeMachine -Path $Path) -ne 0x8664) {
        throw "Service/Worker bundle requires a Windows x64 PE executable: $Path"
    }
}

function File-Evidence {
    param([string]$Path, [string]$RelativePath)
    $item = Assert-NonEmptyFile -Path $Path
    [ordered]@{
        path = $RelativePath
        bytes = [int64]$item.Length
        sha256 = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}

function Read-RuntimePrerequisites {
    param([Parameter(Mandatory = $true)]$Index)
    $items = @($Index.runtime_prerequisites)
    if ($items.Count -ne $Executables.Count) {
        throw 'Service/Worker runtime prerequisite count mismatch'
    }
    foreach ($name in $Executables) {
        $matches = @($items | Where-Object { [string]$_.path -ceq $name })
        if ($matches.Count -ne 1) {
            throw "Service/Worker runtime prerequisite missing or duplicated: $name"
        }
        [pscustomobject]@{
            path = $name
            minimum = Parse-VcVersion ([string]$matches[0].minimum_vc_runtime_version)
        }
    }
}

function Validate-Bundle {
    $path = Bundle-Path -Name $IndexName
    Assert-NonEmptyFile -Path $path | Out-Null
    $index = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ([int]$index.schema_version -ne $SchemaVersion -or [string]$index.target -ne $Target) {
        throw 'Unsupported Service/Worker bundle schema or target'
    }
    $prerequisites = @(Read-RuntimePrerequisites -Index $index)
    $files = @($index.files)
    if ($files.Count -ne $RequiredFiles.Count) { throw 'Service/Worker bundle file count mismatch' }
    foreach ($name in $RequiredFiles) {
        $matches = @($files | Where-Object { [string]$_.path -ceq $name })
        if ($matches.Count -ne 1) { throw "Service/Worker bundle index missing or duplicates: $name" }
        $full = Bundle-Path -Name $name
        $item = Assert-NonEmptyFile -Path $full
        if ($item.Length -ne [int64]$matches[0].bytes -or
            (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash -ine [string]$matches[0].sha256) {
            throw "Service/Worker bundle size or SHA-256 mismatch: $name"
        }
    }
    foreach ($name in $Executables) { Assert-X64Pe -Path (Bundle-Path -Name $name) }
    Write-Host 'bundle_valid=true'
    foreach ($item in $prerequisites) {
        Write-Host "minimum_vc_runtime_version[$($item.path)]=$($item.minimum)"
    }
    $index
}

switch ($Mode) {
    'Help' {
        Write-Host 'ClassMesh Service/Worker bundle: IndexBundle, ValidateBundle, PreflightRuntime. No installation or Service action.'
    }
    'IndexBundle' {
        if (-not (Test-Path -LiteralPath $BundleDir -PathType Container)) {
            throw "Bundle directory is missing: $BundleDir"
        }
        foreach ($name in $Executables) { Assert-X64Pe -Path (Bundle-Path -Name $name) }
        $files = @()
        foreach ($name in $RequiredFiles) {
            $files += File-Evidence -Path (Bundle-Path -Name $name) -RelativePath $name
        }
        $toolsetVersion = (Get-BuildToolsetVersion).ToString()
        [ordered]@{
            schema_version = $SchemaVersion
            target = $Target
            runtime_prerequisites = @($Executables | ForEach-Object {
                [ordered]@{ path = $_; minimum_vc_runtime_version = $toolsetVersion }
            })
            files = $files
            note = 'Integrity and runtime prerequisite diagnostic only. No installation or security authority.'
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Bundle-Path -Name $IndexName) -Encoding utf8
        Write-Host "bundle_index=$(Bundle-Path -Name $IndexName)"
    }
    'ValidateBundle' { $null = Validate-Bundle }
    'PreflightRuntime' {
        $index = Validate-Bundle
        $installed = Get-X64VcRuntimeVersion
        foreach ($item in @(Read-RuntimePrerequisites -Index $index)) {
            Assert-RuntimeSatisfiesToolset $item.minimum $installed
        }
        Write-Host "vc_runtime_x64_version=$installed"
        Write-Host 'runtime_preflight_passed=true'
    }
}
