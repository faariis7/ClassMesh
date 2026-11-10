#Requires -Version 5.1
# Windows PowerShell 5.1 uses .NET Framework and lacks
# [IO.Path]::IsPathFullyQualified. Accept only local volume-qualified paths;
# never permit drive-relative, cwd-relative, root-relative or UNC executable
# paths into the protected SCM installer or live M2 attestation.
function Assert-LocalAbsolutePath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -cnotmatch '^[A-Za-z]:\\') {
        throw 'FAIL_CLOSED: local fully-qualified Windows path required'
    }
    if ($Path.Substring(2).Contains(':')) {
        throw 'FAIL_CLOSED: alternate-stream or malformed Windows path'
    }
    $canonical = [IO.Path]::GetFullPath($Path)
    if ($canonical -cnotmatch '^[A-Za-z]:\\') {
        throw 'FAIL_CLOSED: canonical Windows path not on local volume'
    }
}
