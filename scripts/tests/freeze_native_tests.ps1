$ErrorActionPreference = 'Stop'
$freeze = Join-Path (Join-Path $PSScriptRoot '..') 'freeze-native-tests.ps1'
$root = Join-Path ([IO.Path]::GetTempPath()) ('classmesh-freeze-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $root
function Assert-Rejected([scriptblock]$Action, [string]$Pattern) {
    $message = $null
    try { & $Action } catch { $message = $_.Exception.Message }
    if ($null -eq $message -or $message -notmatch $Pattern) { throw "Expected $Pattern, got: $message" }
}
function Artifact([string]$Path) {
    @{ reason='compiler-artifact'; target=@{name='classmesh_win32'; kind=@('lib')};
       profile=@{test=$true}; features=@('default'); executable=$Path }
}
function cargo {
    if (($args -join ' ') -cne 'test -p classmesh-win32 --lib --no-run --message-format=json') {
        throw "Unexpected Cargo invocation: $args"
    }
    foreach ($record in $global:NativeFreezeRecords) {
        if ($record -is [string]) { $record } else { $record | ConvertTo-Json -Depth 8 -Compress }
    }
    $global:LASTEXITCODE = $global:NativeFreezeExit
}
try {
    foreach ($layout in @('debug/deps', 'custom target/debug/build/classmesh-win32/hash/out')) {
        $dir = Join-Path $root $layout
        $null = New-Item -ItemType Directory -Path $dir -Force
        $exe = Join-Path $dir 'classmesh_win32-hash.exe'
        Set-Content -LiteralPath $exe -Value 'exact default-feature image'
        $global:NativeFreezeExit = 0
        $global:NativeFreezeRecords = @((Artifact $exe), @{reason='build-finished'; success=$true})
        $bundle = Join-Path $root ('bundle-' + [guid]::NewGuid().ToString('N'))
        & $freeze -BundleDir $bundle
        $copy = Join-Path $bundle 'classmesh-win32-native-tests.exe'
        if ((Get-FileHash $copy).Hash -ne (Get-FileHash $exe).Hash) { throw 'Wrong executable copied' }
    }
    $bundle = Join-Path $root 'rejected'
    $invoke = { & $freeze -BundleDir $bundle }
    $done = @{reason='build-finished'; success=$true}
    $global:NativeFreezeRecords = @((Artifact $exe), $done)
    $global:NativeFreezeExit = 101
    Assert-Rejected $invoke 'Cargo.*101'
    $global:NativeFreezeExit = 0
    $global:NativeFreezeRecords = @($done)
    Assert-Rejected $invoke 'exactly one'
    $global:NativeFreezeRecords = @((Artifact $exe), (Artifact $exe), $done)
    Assert-Rejected $invoke 'exactly one'
    foreach ($field in @('features', 'profile', 'target', 'kind', 'executable')) {
        $bad = Artifact $exe
        switch ($field) {
            features { $bad.features = @('experimental-trusted-policy') }
            profile { $bad.profile.test = $false }
            target { $bad.target.name = 'another_crate' }
            kind { $bad.target.kind = @('bin') }
            executable { $bad.executable = $null }
        }
        $global:NativeFreezeRecords = @($bad, $done)
        Assert-Rejected $invoke 'exactly one'
    }
    $global:NativeFreezeRecords = @((Artifact (Join-Path $root 'missing.exe')), $done)
    Assert-Rejected $invoke 'does not exist'
    $global:NativeFreezeRecords = @((Artifact $exe), @{reason='build-finished'; success=$false})
    Assert-Rejected $invoke 'successful build-finished'
    $global:NativeFreezeRecords = @((Artifact $exe))
    Assert-Rejected $invoke 'successful build-finished'
    $global:NativeFreezeRecords = @('not valid JSON')
    Assert-Rejected $invoke 'JSON'
    if (Test-Path -LiteralPath $bundle) { throw 'Rejected build produced a bundle' }
    Write-Host 'freeze_native_tests=pass'
} finally {
    Remove-Item -LiteralPath $root -Recurse -Force
    Remove-Variable NativeFreezeRecords, NativeFreezeExit -Scope Global -ErrorAction SilentlyContinue
}
