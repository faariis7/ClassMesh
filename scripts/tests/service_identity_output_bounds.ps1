Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../service-identity-output.ps1')
$exact = [ClassMeshIdentityBoundedOutput]::Read([IO.StringReader]::new('12345678'),8).GetAwaiter().GetResult()
if ($exact -ne '12345678') { throw 'Exact-limit output was not retained' }
$refused = $false
try { $null = [ClassMeshIdentityBoundedOutput]::Read([IO.StringReader]::new('123456789'),8).GetAwaiter().GetResult() }
catch { $refused = $_.Exception.ToString().Contains('identity output exceeded limit') }
if (-not $refused) { throw 'IDENTITY_OUTPUT_BOUND: over-limit reader accepted' }
Write-Host 'PASS streaming output exact limit and overflow rejection (unit evidence only)'
