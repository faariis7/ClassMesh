#Requires -Version 5.1
# Require the independently approved release code-signing identity in addition
# to the exact SHA-256 file pin. This does not issue or approve certificates.
function Assert-ApprovedReleaseSigner([string]$Path, [string]$ExpectedThumbprint) {
    if ($ExpectedThumbprint -cnotmatch '^[a-fA-F0-9]{40}$') {
        throw 'FAIL_CLOSED: explicitly approved 40-hex Authenticode signer thumbprint required'
    }
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    } catch {
        throw 'FAIL_CLOSED: signed release executable identity cannot be verified'
    }
    if ($null -eq $signature -or [string]$signature.Status -cne 'Valid' -or
        $null -eq $signature.SignerCertificate) {
        throw 'FAIL_CLOSED: Authenticode release signature is missing or invalid'
    }
    $actual = [string]$signature.SignerCertificate.Thumbprint
    if ($actual -cnotmatch '^[a-fA-F0-9]{40}$' -or
        -not [string]::Equals($actual, $ExpectedThumbprint,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'FAIL_CLOSED: Authenticode signer differs from approved release identity'
    }
}
