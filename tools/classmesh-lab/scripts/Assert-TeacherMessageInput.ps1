#Requires -Version 5.1
# Reject invalid UTF-16 and oversized UTF-8 before launching the authenticated CLI.
function Assert-TeacherMessageInput([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { throw 'Teacher message is required' }
    if ($Text.IndexOf([char]0) -ge 0) { throw 'Teacher message contains NUL' }
    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
    try { $bytes = $strictUtf8.GetByteCount($Text) }
    catch { throw 'Teacher message contains invalid Unicode' }
    if ($bytes -gt 4096) { throw 'Teacher message exceeds 4096 UTF-8 bytes' }
}
