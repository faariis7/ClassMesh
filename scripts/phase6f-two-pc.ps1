[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Help", "Healthy", "Degraded", "MediaDrop", "DisconnectCleanup")]
    [string]$Mode,

    [string]$BinDir = ".",
    [string]$Connect = "",
    [string]$ServerName = "",
    [string]$Identity = "",
    [string]$UdpListen = "0.0.0.0:57020",
    [int]$Seconds = 30,
    [int]$DropMediaAfter = 10,
    [int]$HoldKeyVk = 65,
    [string]$ResultsDir = "phase6f-results"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Require-Value {
    param(
        [string]$Name,
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "$Name is required for mode $Mode"
    }
}

function Invoke-Qualification {
    param(
        [string[]]$Arguments,
        [string]$LogPrefix
    )

    $exePath = Join-Path $BinDir "classmesh-interactive-qualification.exe"
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        throw "Qualification executable not found: $exePath"
    }
    if (-not (Test-Path -LiteralPath $Identity -PathType Leaf)) {
        throw "Teacher machine identity not found: $Identity"
    }

    New-Item -ItemType Directory -Path $ResultsDir -Force | Out-Null
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $logPath = Join-Path $ResultsDir "$LogPrefix-$stamp.log"

    Write-Host "Running: $exePath $($Arguments -join ' ')"
    Write-Host "Log: $logPath"

    & $exePath @Arguments 2>&1 | Tee-Object -FilePath $logPath
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "classmesh-interactive-qualification.exe exited with code $exitCode. See $logPath"
    }

    Write-Host "Qualification command completed. Log saved to $logPath"
    Write-Host "Physical observations must still be recorded in PHASE6F_TWO_PC_RESULTS.md."
}

function Base-Arguments {
    Require-Value -Name "-Connect <student-ip:port>" -Value $Connect
    Require-Value -Name "-ServerName <student-certificate-dns-name>" -Value $ServerName
    Require-Value -Name "-Identity <teacher-machine-identity.json>" -Value $Identity

    if ($Seconds -le 0) {
        throw "-Seconds must be greater than zero"
    }

    return @(
        "--connect", $Connect,
        "--server-name", $ServerName,
        "--identity", $Identity,
        "--udp-listen", $UdpListen,
        "--seconds", "$Seconds"
    )
}

function Show-Help {
    @"
ClassMesh Phase 6F two-PC physical qualification runner

Prerequisites:
  - Student Service + interactive Worker are running with production-style state.
  - Teacher has an enrolled machine-identity.json backed by a non-exportable CNG key.
  - Student authorization contains that Teacher with ViewInteractive + ControlInput.
  - Use the classmesh-phase6f-qualification-windows-x64 artifact.

Examples:
  .\phase6f-two-pc.ps1 -Mode Healthy -BinDir . -Connect 192.168.1.20:44991 -ServerName student.classmesh.local -Identity C:\ClassMesh\teacher\machine-identity.json

  .\phase6f-two-pc.ps1 -Mode Degraded -BinDir . -Connect 192.168.1.20:44991 -ServerName student.classmesh.local -Identity C:\ClassMesh\teacher\machine-identity.json

  .\phase6f-two-pc.ps1 -Mode MediaDrop -BinDir . -Connect 192.168.1.20:44991 -ServerName student.classmesh.local -Identity C:\ClassMesh\teacher\machine-identity.json -DropMediaAfter 10

  .\phase6f-two-pc.ps1 -Mode DisconnectCleanup -BinDir . -Connect 192.168.1.20:44991 -ServerName student.classmesh.local -Identity C:\ClassMesh\teacher\machine-identity.json -Seconds 10 -HoldKeyVk 65

Logs are written under -ResultsDir (default: .\phase6f-results).
This helper does not mark Phase 6F PASS. Lock/unlock, Worker restart, secure desktop,
visible input behavior and other physical observations still require human evidence.
"@ | Write-Host
}

switch ($Mode) {
    "Help" {
        Show-Help
    }

    "Healthy" {
        $arguments = Base-Arguments
        $arguments += "--input-pulse"
        Invoke-Qualification -Arguments $arguments -LogPrefix "healthy"
    }

    "Degraded" {
        $arguments = Base-Arguments
        $arguments += @("--input-pulse", "--degraded-feedback")
        Invoke-Qualification -Arguments $arguments -LogPrefix "degraded"
    }

    "MediaDrop" {
        if ($DropMediaAfter -le 0 -or $DropMediaAfter -ge $Seconds) {
            throw "-DropMediaAfter must be greater than zero and less than -Seconds"
        }
        $arguments = Base-Arguments
        $arguments += @("--input-pulse", "--drop-media-after", "$DropMediaAfter")
        Invoke-Qualification -Arguments $arguments -LogPrefix "media-drop"
    }

    "DisconnectCleanup" {
        if ($HoldKeyVk -lt 1 -or $HoldKeyVk -gt 65535) {
            throw "-HoldKeyVk must be in 1..65535"
        }
        $arguments = Base-Arguments
        $arguments += @("--hold-key-vk", "$HoldKeyVk")
        Invoke-Qualification -Arguments $arguments -LogPrefix "disconnect-cleanup"
    }
}
