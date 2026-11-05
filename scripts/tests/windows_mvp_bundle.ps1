$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path (Join-Path $PSScriptRoot '..') 'windows-mvp-common.ps1')

$script:Passed = 0
$script:Failed = 0
function Check([string]$Name, [scriptblock]$Body) {
    try { & $Body; $script:Passed++; Write-Host "PASS $Name" }
    catch { $script:Failed++; Write-Host "FAIL $Name : $($_.Exception.Message)" }
}
function Assert-True($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}
function Reject([scriptblock]$Body, [string]$MessagePattern) {
    $errorSeen = $null
    try { & $Body | Out-Null } catch { $errorSeen = $_.Exception.Message }
    if ($null -eq $errorSeen) { throw "Invalid input was accepted: $MessagePattern" }
    if ($errorSeen -notmatch $MessagePattern) { throw "Wrong rejection: $errorSeen; expected $MessagePattern" }
}
function Context {
    [pscustomobject]@{
        source_revision = ('a' * 40); ci_run_id = '12345'; ci_run_attempt = '1'
        ci_repository = 'faariis7/ClassMesh'; ci_job = 'windows'
    }
}
function Write-Json($Value, [string]$Path) {
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding utf8
}
function New-Fixture([string]$Root) {
    $null = New-Item -ItemType Directory -Path $Root
    foreach ($name in @(Get-MvpRequiredFiles)) {
        $source = Join-Path (Join-Path $PSScriptRoot '..') $name
        if ($name -in @(Get-MvpExecutables)) {
            $pe = [byte[]]::new(128)
            $pe[0] = 0x4d; $pe[1] = 0x5a; $pe[0x3c] = 64
            $pe[64] = 0x50; $pe[65] = 0x45; $pe[68] = 0x64; $pe[69] = 0x86
            [IO.File]::WriteAllBytes((Join-Path $Root $name), $pe)
        } elseif (Test-Path -LiteralPath $source -PathType Leaf) {
            Copy-Item -LiteralPath $source -Destination (Join-Path $Root $name)
        } else { Set-Content -LiteralPath (Join-Path $Root $name) -Value 'fixture' }
    }
    Write-Json ([ordered]@{schema_version=1; service_name='ClassMeshService'; teacher_startup_seconds=2}) (Join-Path $Root 'mvp-launcher-config.json')
    $teacherNames = @('classmesh-teacher-ui.exe', 'phase11f4-teacher-ui-smoke.ps1', 'phase13-vc-runtime.ps1', 'PHASE11_TEACHER_UI_SMOKE.md', 'PHASE11_TEACHER_UI_SMOKE_RESULTS.md')
    $serviceNames = @('classmesh-service.exe', 'classmesh-worker.exe', 'phase13-service-worker-bundle.ps1', 'phase13-vc-runtime.ps1', 'PHASE13_SERVICE_WORKER_PREREQUISITES.md')
    function Records($Names) {
        @($Names | ForEach-Object {
            $p = Join-Path $Root $_
            [pscustomobject]@{path=$_; bytes=(Get-Item -LiteralPath $p).Length; sha256=(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
        })
    }
    Write-Json ([ordered]@{schema_version=3;target='windows-x64';ui_scope_only=$true;visual_accessibility_reviewed=$null;minimum_vc_runtime_version='14.44.35207.0';files=@(Records $teacherNames)}) (Join-Path $Root 'teacher-ui-bundle-index.json')
    Write-Json ([ordered]@{schema_version=2;target='windows-x64';runtime_prerequisites=@(@{path='classmesh-service.exe';minimum_vc_runtime_version='14.44.35207.0'},@{path='classmesh-worker.exe';minimum_vc_runtime_version='14.44.35207.0'});files=@(Records $serviceNames)}) (Join-Path $Root 'service-worker-bundle-index.json')
    $files = @(Records (@(Get-MvpRequiredFiles) + @('teacher-ui-bundle-index.json','service-worker-bundle-index.json')))
    $components = @(@(Get-MvpExecutables) | ForEach-Object {
        $r = $files | Where-Object path -CEQ $_
        $v = Context
        $v | Add-Member path $_; $v | Add-Member bytes $r.bytes; $v | Add-Member sha256 $r.sha256
        $v
    })
    $index = Context
    $index | Add-Member schema_version 1; $index | Add-Member target 'windows-x64'
    $index | Add-Member production_qualified $false; $index | Add-Member files $files
    $index | Add-Member components $components
    Write-Json $index (Join-Path $Root 'mvp-bundle-index.json')
    $index
}

$suiteRoot = Join-Path ([IO.Path]::GetTempPath()) ('ClassMesh-MVP-unit-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $suiteRoot
try {
    Check 'valid identical CI context is accepted' { Assert-MvpBuildContext (Context) (Context) }
    foreach ($field in @('source_revision','ci_run_id','ci_run_attempt','ci_repository','ci_job')) {
        Check "mismatching $field is rejected" {
            $actual = Context
            $actual.$field = if ($field -eq 'source_revision') { 'b' * 40 } else { 'different' }
            Reject { Assert-MvpBuildContext $actual (Context) } 'provenance|context'
        }
    }
    Check 'a complete bundle passes existing component validators' {
        $root = Join-Path $suiteRoot 'valid'; $null = New-Fixture $root
        $result = Test-MvpBundle $root (Context)
        Assert-True ($result.source_revision -ceq ('a' * 40)) 'valid revision was lost'
        Assert-True (@($result.components).Count -eq 3) 'all three components must be indexed'
    }
    foreach ($case in @('modified-exe','old-worker','other-run','missing-component','extra-file','missing-file','traversal','duplicate-record','missing-hash','production-claim','bad-pe')) {
        Check "bundle rejects $case" {
            $root = Join-Path $suiteRoot $case; $index = New-Fixture $root
            $pattern = 'mismatch|provenance|context|file|component|production|PE'
            switch ($case) {
                'modified-exe' { [IO.File]::AppendAllText((Join-Path $root 'classmesh-worker.exe'),'altered') }
                'old-worker' { $index.components[2].source_revision = 'b' * 40 }
                'other-run' { $index.components[1].ci_run_id = '67890' }
                'missing-component' { $index.components = @($index.components[0..1]) }
                'extra-file' { Set-Content (Join-Path $root 'unexpected.exe') 'unindexed' }
                'missing-file' { Remove-Item (Join-Path $root 'classmesh-service.exe') }
                'traversal' { $index.files[0].path = '../classmesh-teacher-ui.exe' }
                'duplicate-record' { $index.files[1] = $index.files[0] }
                'missing-hash' { $index.files[0].sha256 = '' }
                'production-claim' { $index.production_qualified = $true }
                'bad-pe' {
                    $p = Join-Path $root 'classmesh-teacher-ui.exe'; [IO.File]::WriteAllBytes($p, [byte[]]::new(128))
                    $r = $index.files | Where-Object path -CEQ 'classmesh-teacher-ui.exe'
                    $r.sha256 = (Get-FileHash $p -Algorithm SHA256).Hash.ToLowerInvariant()
                    $index.components[0].sha256 = $r.sha256
                }
            }
            Write-Json $index (Join-Path $root 'mvp-bundle-index.json')
            Reject { Test-MvpBundle $root (Context) } $pattern
        }
    }
    Check 'leases retain all validated bundle files' {
        $root = Join-Path $suiteRoot 'leased'; $null = New-Fixture $root
        $handles = @(Open-MvpBundleLease $root)
        try {
            Assert-True ($handles.Count -eq 18) 'a bundle file was not leased'
            if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
                Reject { [IO.File]::WriteAllText((Join-Path $root 'classmesh-worker.exe'),'changed') } 'being used|access|process|sharing'
            }
        } finally { foreach ($h in $handles) { $h.Dispose() } }
    }
    Check 'report directory cannot adopt previous evidence' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ('ClassMesh-MVP-' + [guid]::NewGuid().ToString('N'))
        try {
            $created = New-MvpReportDirectory $path
            Set-Content (Join-Path $created 'sentinel') 'keep'
            Reject { New-MvpReportDirectory $path } 'exists'
            Assert-True ((Get-Content (Join-Path $created 'sentinel')) -eq 'keep') 'old evidence was overwritten'
        } finally { if (Test-Path $path) { Remove-Item -LiteralPath $path -Recurse -Force } }
    }
    Check 'report directory rejects arbitrary non-TEMP path' {
        Reject { New-MvpReportDirectory (Join-Path $suiteRoot 'not-direct-temp') } 'TEMP'
    }
    Check 'recording requires real GitHub Actions context' {
        $previous = $env:GITHUB_ACTIONS
        try { $env:GITHUB_ACTIONS = 'false'; Reject { Get-MvpCiContext (Join-Path $PSScriptRoot '../..') } 'GitHub Actions' }
        finally { $env:GITHUB_ACTIONS = $previous }
    }
    foreach ($case in @('valid','wrong-revision')) {
        Check "launcher produces a fresh JSON result for $case" {
            $root = Join-Path $suiteRoot ('cli-' + $case); $null = New-Fixture $root
            $report = Join-Path ([IO.Path]::GetTempPath()) ('ClassMesh-MVP-' + [guid]::NewGuid().ToString('N'))
            try {
                $sha = if ($case -eq 'valid') { 'a' * 40 } else { 'b' * 40 }
                $program = (Get-Process -Id $PID).Path
                & $program -NoProfile -File (Join-Path $root 'windows-mvp-launch.ps1') -Mode Validate -BundleDir $root -ExpectedSourceRevision $sha -ExpectedCiRunId 12345 -ReportDir $report
                $code = $LASTEXITCODE
                $result = Get-Content -LiteralPath (Join-Path $report 'mvp-report.json') -Raw | ConvertFrom-Json
                if ($case -eq 'valid') { Assert-True ($code -eq 0 -and $result.bundle.status -eq 'PASSED') 'valid CLI bundle failed' }
                else { Assert-True ($code -eq 1 -and $result.bundle.status -eq 'FAILED') 'CLI accepted mismatching version' }
                Assert-True ($result.integrated_test_passed -eq $false) 'integrated readiness was invented'
            } finally { if (Test-Path $report) { Remove-Item -LiteralPath $report -Recurse -Force } }
        }
    }
} finally { Remove-Item -LiteralPath $suiteRoot -Recurse -Force }
Write-Host "windows_mvp_bundle_tests: passed=$script:Passed failed=$script:Failed"
if ($script:Failed -ne 0) { exit 1 }
exit 0
