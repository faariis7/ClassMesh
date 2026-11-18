param([string]$BundleDir = 'phase10-native-telemetry-bundle')
$ErrorActionPreference = 'Stop'

# Ask Cargo for the default-feature library test image. Its output layout is
# not a stable API (and CARGO_TARGET_DIR may override the workspace target).
# Workspace tests must already have passed; this does not replace running them.
$lines = @(cargo test -p classmesh-win32 --lib --no-run --message-format=json)
if ($LASTEXITCODE -ne 0) { throw "Cargo native test build failed: $LASTEXITCODE" }
$messages = @($lines | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop })
$finished = @($messages | Where-Object { $_.reason -eq 'build-finished' })
if ($finished.Count -ne 1 -or $finished[0].success -ne $true) {
    throw 'Cargo did not report a successful build-finished message'
}
$bins = @($messages | Where-Object {
    $_.reason -eq 'compiler-artifact' -and
    $_.target.name -ceq 'classmesh_win32' -and
    @($_.target.kind) -contains 'lib' -and
    $_.profile.test -eq $true -and
    @($_.features | Where-Object { $_ -cne 'default' }).Count -eq 0 -and
    $null -ne $_.executable
})
if ($bins.Count -ne 1) {
    throw "Expected exactly one default-feature native test executable, found $($bins.Count)"
}
$exe = $bins[0].executable
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw "Cargo test executable does not exist: $exe"
}
$null = New-Item -ItemType Directory -Path $BundleDir -Force
Copy-Item -LiteralPath $exe -Destination (Join-Path $BundleDir 'classmesh-win32-native-tests.exe')
Write-Host "Frozen Cargo native test executable: $exe"
