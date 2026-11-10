#Requires -Version 5.1
# Keep path authority checks separate so native Windows tests exercise them.
function Assert-NoReparsePath([string]$Path) {
    # Reject linked identity and executable inputs, including linked ancestors.
    # A provisioned identity must not be silently redirected after approval.
    $cursor = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Provisioned input path contains a reparse point'
        }
        # FileInfo does NOT expose Parent in Windows PowerShell 5.1. Ascend
        # from the file to its *lexical* containing DirectoryInfo, and then
        # check every directory/volume ancestor. Otherwise a signed executable
        # located beneath an attacker-redirectable junction may be accepted.
        if ($cursor -is [System.IO.FileInfo]) {
            $cursor = $cursor.Directory
        } else {
            $cursor = $cursor.Parent
        }
    }
}
