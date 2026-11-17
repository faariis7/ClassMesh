# Runs the existing synthetic ClassMesh lab endpoint and optionally observes one Windows NIC.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Teacher', 'Student')][string]$Role,
    [Parameter(Mandatory)][string]$Lab,
    [Parameter(Mandatory)][ipaddress]$InterfaceIp,
    [Parameter(Mandatory)][ipaddress]$TeacherIp,
    [Parameter(Mandatory)][ValidateRange(1, 4294967295)][uint32]$Stream,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [ipaddress]$Group = '239.255.23.94',
    [ValidateRange(1, 65535)][int]$Port = 50494,
    [ValidateRange(1, 240)][int]$Frames = 120,
    [ValidateRange(1, 16384)][int]$FrameBytes = 8192,
    [ValidateRange(1, 60)][int]$Seconds = 25,
    [ValidateRange(1, 65535)][int]$ComponentId,
    [string]$Tshark = "$env:ProgramFiles\Wireshark\tshark.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$teacher = $Role -eq 'Teacher'
$endpoint = if ($teacher) { 'sender' } else { 'receiver' }
$side = if ($teacher) { 'outbound' } else { 'inbound' }
$direction = if ($teacher) { 'Outbound' } else { 'Inbound' }
$hasCapture = $PSBoundParameters.ContainsKey('ComponentId')
foreach ($address in @($InterfaceIp, $TeacherIp)) {
    $firstByte = $address.GetAddressBytes()[0]
    if ($address.AddressFamily -ne 'InterNetwork' -or $firstByte -in 0, 127 -or $firstByte -ge 224) {
        throw 'InterfaceIp and TeacherIp must be explicit unicast IPv4 addresses.'
    }
}
if ($Group.AddressFamily -ne 'InterNetwork' -or $Group.GetAddressBytes()[0] -ne 239) {
    throw 'Group must be an administratively scoped IPv4 multicast address.'
}
if ($teacher -and !$InterfaceIp.Equals($TeacherIp)) { throw 'TeacherIp must match InterfaceIp on Teacher.' }
$labPath = (Get-Item -LiteralPath $Lab).FullName
if ($hasCapture) {
    $tsharkPath = (Get-Command $Tshark -CommandType Application).Source
    $pktmonPath = (Get-Command pktmon.exe -CommandType Application).Source
}
# Creating the directory without -Force rejects reuse and gives this process ownership of its files.
$runPath = (New-Item -Path $OutputDirectory -ItemType Directory).FullName
$filter = "ClassMeshDelivery$PID"
$ownsFilter = $false
$ownsCapture = $false
$lock = $null
$locked = $false
$locationPushed = $false
$process = $null
$complete = $false
$etl = Join-Path $runPath 'PktMon.etl'
$pcap = Join-Path $runPath 'nic.pcapng'

function Invoke-Pktmon {
    $output = & $pktmonPath @args
    if ($LASTEXITCODE -ne 0) { throw "Pktmon command '$($args[0])' failed (exit $LASTEXITCODE)." }
    $output
}

try {
    if ($hasCapture) {
        $lock = [Threading.Mutex]::new($false, 'Global\ClassMeshMulticastDelivery')
        try { $locked = $lock.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
        if (!$locked) { throw 'A ClassMesh NIC capture is already managed on this host.' }
        $status = (Invoke-Pktmon status) -join [Environment]::NewLine
        $filters = (Invoke-Pktmon filter list) -join [Environment]::NewLine
        if ($status.Trim() -ne 'Packet Monitor is not running.' -or $filters -notmatch '(?m)^\s*None\s*$') {
            throw 'Pktmon must be idle with no filters. Check status and filters in an elevated English-language shell.'
        }

        $inventory = (Invoke-Pktmon list --json) -join [Environment]::NewLine | ConvertFrom-Json
        $localIndex = @(Get-NetIPAddress -AddressFamily IPv4 -IPAddress "$InterfaceIp" |
            Select-Object -ExpandProperty InterfaceIndex)
        $nic = @($inventory | ForEach-Object { $_.Components } |
            Where-Object { $_.Id -eq $ComponentId -and $_.Type -eq 'Miniport' })
        $nicIndex = @($nic | ForEach-Object { $_.Properties } |
            Where-Object Name -eq 'ifIndex' | Select-Object -ExpandProperty Value)
        if ($nicIndex.Count -ne 1 -or $localIndex.Count -ne 1 -or $nicIndex[0] -ne $localIndex[0]) {
            throw 'Pktmon component must be the NIC that owns InterfaceIp. Check pktmon list and Get-NetIPAddress.'
        }
        Invoke-Pktmon filter add $filter -i "$TeacherIp" "$Group" -p $Port -t UDP | Out-Null
        $ownsFilter = $true
        # Pktmon memory mode writes PktMon.etl in the stop command's working directory.
        Push-Location -LiteralPath $runPath
        $locationPushed = $true
        $captureArgs = @('start', '--capture', '--comp', $ComponentId, '--type', 'all', '--flags', '0x013',
            '--pkt-size', 80, '--file-size', 64, '--log-mode', 'memory')
        Invoke-Pktmon @captureArgs | Out-Null
        $ownsCapture = $true
    }

    if ($teacher) {
        $labArgs = @('send', "$InterfaceIp", "$Group", $Port, $Stream, $Frames, $FrameBytes)
        $deadline = [Math]::Ceiling($Frames / 30) + 10
    } else {
        $labArgs = @('receive', "$InterfaceIp", "$TeacherIp", "$Group", $Port, $Stream, $Seconds)
        $deadline = $Seconds + 10
    }
    $trace = Join-Path $runPath "$endpoint.tsv"
    $log = Join-Path $runPath "$endpoint.stderr"
    $processArgs = @{
        FilePath = $labPath; ArgumentList = $labArgs; PassThru = $true; NoNewWindow = $true
        WorkingDirectory = $runPath; RedirectStandardOutput = $trace; RedirectStandardError = $log
    }
    $process = Start-Process @processArgs
    # Windows PowerShell can lose ExitCode after a fast child exits without an open handle.
    $null = $process.Handle
    $elapsed = [Diagnostics.Stopwatch]::StartNew()
    $ready = $false
    while (!$process.WaitForExit(100)) {
        if (!$teacher -and !$ready -and (Select-String -LiteralPath $log -Pattern '^receiver_ready ' -Quiet)) {
            Write-Host 'receiver_ready. Start Teacher now.'
            $ready = $true
        }
        if ($elapsed.Elapsed.TotalSeconds -ge $deadline) { throw "$Role lab exceeded its process deadline." }
    }
    if ($process.ExitCode -ne 0) { throw "$Role lab failed (exit $($process.ExitCode)). See $log." }

    if ($hasCapture) {
        $counters = (Invoke-Pktmon counters --type flow --zero --json) -join [Environment]::NewLine | ConvertFrom-Json
        $flow = @($counters | ForEach-Object { $_.Components } | Where-Object Id -eq $ComponentId |
            ForEach-Object { $_.Counters } | Where-Object { $_.Name -eq 'Upper' -and $_.Type -eq 'Flows' })
        if ($flow.Count -ne 1 -or $null -eq $flow[0].$direction.Packets) {
            throw 'Selected NIC flow counter is unavailable. Use the application trace without NIC attribution.'
        }
        $count = $flow[0].$direction.Packets
        Invoke-Pktmon stop | Out-Null
        $ownsCapture = $false
        Invoke-Pktmon etl2pcap $etl --out $pcap --component-id $ComponentId | Out-Null
        $streamBytes = $Stream.ToString('x8') -replace '(..)(?!$)', '$1:'
        $display = "ip.src == $TeacherIp && ip.dst == $Group && udp.dstport == $Port" +
            " && udp.payload[0:6] == 43:4d:56:31:00:04 && udp.payload[8:4] == $streamBytes"
        $fieldsArgs = @('-n', '-r', $pcap, '-c', 32769, '-Y', $display, '-T', 'fields', '-E', 'occurrence=f',
            '-e', 'frame.time_epoch', '-e', 'ip.src', '-e', 'udp.srcport', '-e', 'ip.dst', '-e', 'udp.dstport',
            '-e', 'udp.payload')
        $capturePath = Join-Path $runPath "$side.tsv"
        & $tsharkPath @fieldsArgs | ForEach-Object {
            $fields = $_ -split [char]9, 6
            if ($fields.Count -ne 6) { throw 'TShark output does not contain six fields.' }
            $prefix = $fields[5].Replace(':', '')
            if ($prefix.Length -lt 52) { throw 'NIC capture prefix is too short for correlation.' }
            $fields[5] = $prefix.Substring(0, 52)
            $fields -join [char]9
        } | Set-Content -LiteralPath $capturePath -Encoding ascii
        if ($LASTEXITCODE -ne 0) { throw "TShark failed (exit $LASTEXITCODE)." }
        if (!(Test-Path -LiteralPath $capturePath)) {
            New-Item -Path $capturePath -ItemType File | Out-Null
        }
        Set-Content -LiteralPath (Join-Path $runPath "$side.count") -Value $count -Encoding ascii
    }
    $complete = $true
} finally {
    try {
        if ($null -ne $process -and !$process.HasExited) {
            $process.Kill()
            $null = $process.WaitForExit(3000)
        }
    } finally {
        try {
            if ($ownsCapture) { Invoke-Pktmon stop | Out-Null }
        } finally {
            try {
                # Pktmon only supports remove-all. Check that nobody added another filter.
                if ($ownsFilter) {
                    $filters = @(Invoke-Pktmon filter list | Where-Object { $_ -match '^\s*\d+\s+\S' })
                    if ($filters.Count -eq 1 -and $filters[0] -match "^\s*\d+\s+$filter\s") {
                        Invoke-Pktmon filter remove | Out-Null
                    } else {
                        Write-Warning "Pktmon filters changed during the run. Inspect the $filter filter manually."
                    }
                }
            } finally {
                foreach ($path in @($etl, $pcap)) {
                    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
                }
                if (!$complete) {
                    foreach ($extension in @('tsv', 'count')) {
                        $path = Join-Path $runPath "$side.$extension"
                        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
                    }
                }
                if ($locationPushed) { Pop-Location }
                if ($locked) { $lock.ReleaseMutex() }
                if ($null -ne $lock) { $lock.Dispose() }
            }
        }
    }
}
Write-Host "$Role evidence saved to $runPath"
