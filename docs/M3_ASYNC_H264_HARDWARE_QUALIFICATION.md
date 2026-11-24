## Physical Windows x64 qualification sequence

1. Use two physical Windows 11 x64 PCs on the target wired VLAN. Record OS
   build, NIC/interface, vendor GPU/driver and display topology on both
   hosts. Validate the exact x64 candidate with the
   [Windows package guide](WINDOWS_MVP_QUICKSTART.md). The authenticated
   product test also requires the [approved M2 setup](WINDOWS_RUNTIME_PLAN.md).
2. Run the inventory below on each GPU, then the separate async lab decode
   and present cases. Record adapter LUID and transform CLSID, negotiated
   format, frame output and HRESULTs. Keep async decoding qualification-only.
3. In the authenticated product session, present a moving lab-only source.
   Run Unicast and Multicast independently. Record the matching start
   request/terminal result, capture/encode and receive/decode/present
   counters, replay denial, key-epoch rotation, and changing nonblank Student
   output. Repeat with controlled packet loss and observe bounded queues,
   NACK/keyframe recovery and fresh decodable output.
4. Run the [two-host multicast diagnostic](../tools/classmesh-lab/docs/MULTICAST_DELIVERY_DIAGNOSTIC.md)
   on the chosen adapters and comparison path. Preserve the per-direction
   NIC capture/counter and Worker delivery correlation. The signed product
   run supplies authentication and playback evidence beyond that diagnostic.
5. Stop and restart the same test scenario, switch display modes,
   minimize/restore, interrupt the network, and exercise a controlled vendor
   device-loss/reset case. Record whether old frames, keys and processes
   retired, whether fresh output resumed, and the failure stage for any
   unsupported path. Retain per-stage logs, exit codes, source and executable
   hashes, and queue/resource measurements. Treat unmeasured paths as open.
6. Close only test-owned UI and Worker sessions, stop the approved disposable
   Service, retire keys and capture ownership, and remove only run-owned
   fixtures under the [Windows runtime cleanup procedure](WINDOWS_RUNTIME_PLAN.md).
   Use approved signed rollback with the protected policy epoch intact if an
   installed qualification step requires reverting.

## Unified RC gate — 2026-11-18

Use the exact unified Draft candidate and its locked graph (`cargo build --locked`).
The commands below qualify the separate async lab only. Production Student still
uses synchronous H.264; do not enable async from a VM or fixture result. The media
owner must also record the authenticated production Student path through Stop,
restart, recovery, device loss, minimize/restore and changing nonblank output on
physical Windows x64. Pair the hardware/driver inventory with source/executable
SHA-256, per-stage logs, HRESULTs, frame counters and cleanup; record unmeasured
stages explicitly. This task has no physical GPU acceptance result.

# M3 async H.264 hardware qualification

Use an authorized physical Windows 11 x64 PC with an installed vendor graphics driver. Sign in at the local desktop in a regular user session. Keep the qualification window visible during the presentation run. The lab uses the default hardware D3D11 video adapter, so confirm its identity before interpreting the result. Record the GPU and driver separately for every machine tested. If the adapter or driver changes, repeat qualification.

## Build the exact revision

Download `classmesh-async-h264-qualification-windows-x64` from the Windows Build job for the intended PR head. Record the GitHub Actions run ID and the bundle's `source-revision.txt`. To build from source instead, use the Visual Studio C++ build tools with a Windows SDK and the repository's Rust toolchain. Run in the checkout at the chosen commit.

```powershell
git rev-parse HEAD
rustup target add x86_64-pc-windows-msvc
cargo build --locked --release --target x86_64-pc-windows-msvc -p classmesh-lab --bin classmesh-async-h264-qualify
$exe = (Resolve-Path '.\target\x86_64-pc-windows-msvc\release\classmesh-async-h264-qualify.exe').Path
# With the downloaded bundle, instead set $exe to the bundled executable's full path.
```

## Prepare the real recording

Record an approved 6-second or longer clip with movement and visible contrast, such as a camera pointed at a moving object against a contrasting background. Use a local file you can share with the qualification reviewer if needed. The two segments exercise an in-place resolution switch. FFmpeg creates complete Annex B access units with AUDs, repeated SPS/PPS, an initial IDR, 30 fps, 8-bit 4:2:0 progressive video and no B-frames. The fixtures use fresh test timestamps derived from that cadence.

```powershell
$recording = (Resolve-Path '.\motion-recording.mp4').Path
$evidence = Join-Path (Get-Location) ('async-h264-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $evidence -ErrorAction Stop | Out-Null
$first = Join-Path $evidence '640x480.h264'
$second = Join-Path $evidence '1280x720.h264'
$encoding = @('-map', '0:v:0', '-an', '-frames:v', '60', '-c:v', 'libx264',
    '-profile:v', 'high', '-pix_fmt', 'yuv420p', '-bf', '0', '-g', '30',
    '-x264-params', 'aud=1:repeat-headers=1:scenecut=0', '-f', 'h264')
ffmpeg -v error -ss 0 -i $recording -vf 'fps=30,scale=640:480:force_original_aspect_ratio=decrease:force_divisible_by=2,pad=640:480:(ow-iw)/2:(oh-ih)/2' @encoding $first
if ($LASTEXITCODE -ne 0) { throw 'First fixture encode failed' }
ffmpeg -v error -ss 3 -i $recording -vf 'fps=30,scale=1280:720:force_original_aspect_ratio=decrease:force_divisible_by=2,pad=1280:720:(ow-iw)/2:(oh-ih)/2' @encoding $second
if ($LASTEXITCODE -ne 0) { throw 'Second fixture encode failed' }
```

## Run and capture evidence

This wrapper captures the JSON, the completed-stage log and the exit code. The outer deadline also covers synchronous vendor calls that could hang. Run the commands in order. Run the decode-only command even when presenting on the machine is unavailable.

```powershell
function Invoke-H264Lab {
    param([string] $Name, [string] $CommandLine)

    $jsonPath = Join-Path $evidence "$Name.json"
    $stagePath = Join-Path $evidence "$Name.stages.log"
    $start = [System.Diagnostics.ProcessStartInfo]::new($exe, $CommandLine)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $start.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $process = [System.Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $timedOut = -not $process.WaitForExit(120000)
        if ($timedOut) {
            try { $process.Kill() } catch { if (-not $process.HasExited) { throw } }
            $null = $process.WaitForExit(5000)
        }
        $progress = if ($stderr.Wait(5000)) { $stderr.Result } else { '' }
        Set-Content -LiteralPath $stagePath -Value $progress -Encoding UTF8
        $report = $null
        if (-not $timedOut -and $stdout.Wait(5000)) {
            try { $report = $stdout.Result | ConvertFrom-Json -ErrorAction Stop } catch {}
        }
        if ($null -eq $report) {
            $stage = if ($timedOut) { 'process_watchdog' } else { 'process_terminated_without_report' }
            $lastStage = ($progress.Trim() -split '\r?\n')[-1]
            $report = [ordered]@{
                status = 'failed'
                physical_qualification = $null
                failure = @{ stage = $stage; last_completed_stage = $lastStage }
            }
        }
        $exitCode = if ($timedOut) { 124 } else { $process.ExitCode }
        Set-Content -LiteralPath (Join-Path $evidence "$Name.exit.txt") $exitCode
        $report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
        $report
    } finally {
        $process.Dispose()
    }
}

Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, SystemType |
    ConvertTo-Json | Set-Content (Join-Path $evidence 'system.json')
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, OSArchitecture, BuildNumber |
    ConvertTo-Json | Set-Content (Join-Path $evidence 'windows.json')
Get-CimInstance Win32_VideoController | Select-Object Name, PNPDeviceID, DriverVersion |
    ConvertTo-Json | Set-Content (Join-Path $evidence 'video-driver.json')
Get-FileHash -Algorithm SHA256 -LiteralPath $exe, $first, $second |
    Select-Object Hash, @{ Name = 'File'; Expression = { Split-Path $_.Path -Leaf } } |
    ConvertTo-Json | Set-Content (Join-Path $evidence 'sha256.json')

Invoke-H264Lab inventory '--inventory'
$arguments = '"{0}" "{1}"' -f $first, $second
Invoke-H264Lab inspect "--inspect $arguments"
Invoke-H264Lab decode "--run $arguments"
Invoke-H264Lab present "--run $arguments --present"
```

## Acceptance

Retain the evidence files, source revision, executable SHA-256, fixture hashes and recording provenance. Confirm that the run took place on the physical machine and that the adapter, PCI IDs and DXCore driver version match the local driver inventory. Sign off against the selected GPU, driver version and transform CLSID together. `physical_qualification` is deliberately `null` in tool output. The executable measures the native path while the reviewer confirms the environment and fixture provenance.

- **Inventory** records globally enumerable H.264 transforms and separately records hardware transforms scoped to the selected adapter LUID. The attributes and interfaces come from live activation. A selected transform additionally has to unlock asynchronous mode, use the multithread-protected D3D11 device manager, negotiate NV12 and supply its own DXGI output.
- **Decode** exits 0 with `hardware_checks_passed`, both DXVA size configurations, an interrupted generation that accepted input before Stop, and a fresh generation that rejects an interframe until an IDR arrives. It must produce one output for every submitted timestamp in order and one actual `DrainComplete` following the native output events. Every sample must pass NV12 format, D3D11 device identity, geometry and array-slice checks. The second size must appear after a successful native NV12 stream-change negotiation in that same generation. Both generations must retire successfully.
- **Presentation** repeats decode with the existing `FlipPresenter`. A pass requires visible DXGI Presents, video-processor rebuilds across the size change and at least two distinct nonblank samples from the rendered BGRA back buffer per size. `presentation = "passed"` is render-path evidence. Record a brief local visual observation of the window for display evidence.
- **Failure** exits 1 with `failure.stage`, `failure.detail` and an HRESULT when the failing operation supplies one. Preserve the report even if no suitable async hardware registration, usable NV12 capability or presentation path exists on that adapter. Record unsupported presentation separately from a successful decode-only run.
- **Hosted, virtual and fixture checks** can verify compilation, native Windows API regressions or input handling. Physical hardware acceptance stays pending until the physical run and its evidence are available. The Student Worker continues to use its synchronous selection policy.

References for the [asynchronous MFT event contract](https://learn.microsoft.com/en-us/windows/win32/medfound/asynchronous-mfts), [adapter-scoped enumeration](https://learn.microsoft.com/en-us/windows/win32/api/mfapi/nf-mfapi-mftenum2) and [DXCore driver property](https://learn.microsoft.com/en-us/windows/win32/api/dxcore_interface/ne-dxcore_interface-dxcoreadapterproperty).
