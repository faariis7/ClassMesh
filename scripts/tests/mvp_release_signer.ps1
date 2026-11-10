# Windows-native nonmutating regression of release-signature binding.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot '../mvp-service-scm-guarded.ps1'
$script = Get-Content -LiteralPath $source -Raw
if ($script -notmatch 'TrustedSignerThumbprint' -or
    $script -notmatch 'Assert-ApprovedReleaseSigner') {
    throw 'FAIL: protected SCM installer accepts only SHA256, not an approved Authenticode signer'
}
$helper = Join-Path $PSScriptRoot '../Assert-ApprovedReleaseSigner.ps1'
if (-not (Test-Path -LiteralPath $helper -PathType Leaf)) {
    throw 'FAIL: real signed release identity verifier is not present'
}
. $helper
$approved = 'A' * 40
$script:reportStatus = 'Valid'
$script:reportSigner = $approved
function Get-AuthenticodeSignature {
    param([string]$LiteralPath)
    return [pscustomobject]@{
        Status=$script:reportStatus
        SignerCertificate=[pscustomobject]@{Thumbprint=$script:reportSigner}
    }
}
function MustReject([string]$why) {
    $failed=$false
    try { Assert-ApprovedReleaseSigner 'C:\ClassMesh\service.exe' $approved }
    catch { $failed=$true }
    if (-not $failed) { throw "FAIL: unsigned/untrusted release image approved: $why" }
}
Assert-ApprovedReleaseSigner 'C:\ClassMesh\service.exe' $approved
$script:reportStatus = 'NotSigned'; MustReject 'unsigned binary'
$script:reportStatus = 'HashMismatch'; MustReject 'signature hash mismatch'
$script:reportStatus = 'UnknownError'; MustReject 'untrusted signature'
$script:reportStatus = 'Valid'; $script:reportSigner = 'B' * 40
MustReject 'different signer'
$script:reportSigner = $approved
foreach ($bad in @('', 'not-a-thumbprint', ('A' * 39),('A' * 41))) {
    $failed=$false
    try { Assert-ApprovedReleaseSigner 'C:\ClassMesh\service.exe' $bad }
    catch { $failed=$true }
    if (-not $failed) { throw 'FAIL: malformed signer pin accepted' }
}
'PASS: signed release identity is checked and bound to approved thumbprint before protected SCM'
