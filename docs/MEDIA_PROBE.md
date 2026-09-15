# ClassMesh Windows Media Probe

`classmesh-media-probe.exe` is the first hardware validation tool for the teacher-presentation hot path:

```text
Desktop Duplication BGRA texture
        ↓ GPU only
D3D11 Video Processor
        ↓
NV12 surface from a bounded pool
        ↓
Media Foundation hardware H.264 encoder
        ↓
encoded H.264 access units
```

The probe is intentionally separate from the normal Service-driven Worker. A driver or hardware-encoder problem therefore cannot affect the classroom service while the media path is still being qualified.

## Getting the probe

The Windows CI job builds the release binary and uploads the artifact:

```text
classmesh-media-probe-windows-x64
```

The executable inside the artifact is:

```text
classmesh-media-probe.exe
```

Run the probe from the signed-in interactive Windows desktop that will act as the teacher machine. Do not run this first hardware test from Session 0 or as a Windows service.

## First validation run

Open PowerShell in the directory containing the executable and run:

```powershell
.\classmesh-media-probe.exe --seconds 15 --output .\classmesh-probe.h264
```

The output file is optional. To test only capture/conversion/encoding and print metrics:

```powershell
.\classmesh-media-probe.exe --seconds 15
```

During the run, play a moving 1080p video or move windows continuously so the capture path is not measuring a mostly static desktop.

## Expected console output

A successful run should report:

- the selected DXGI display and adapter identity;
- the selected Media Foundation hardware H.264 encoder;
- source texture geometry and the bounded presentation geometry;
- periodic counts for captured, submitted and encoded frames;
- keyframe count;
- rate-drop count when capture is faster than the 30 fps presentation target;
- pool-drop count;
- number of NV12 surfaces currently in flight;
- total encoded bytes.

The first performance gate is not a fixed benchmark score. It is:

1. no CPU bitmap/readback path;
2. encoded frames continue to advance for the entire run;
3. the bounded NV12 pool does not grow;
4. no permanent DXGI fallback is introduced;
5. no process disconnect or unbounded latency queue appears.

A healthy 60 Hz desktop may show `rate_drop` increasing because the presentation encoder is deliberately paced at 30 fps. That is expected and preferable to queueing old frames.

`pool_drop` should normally remain low or zero. A steadily increasing `pool_drop` means the encoder is not returning surfaces quickly enough and requires investigation before classroom fan-out work continues.

## Resolution behavior

The probe never upscales and caps the initial presentation rendition at 1920×1080 while preserving aspect ratio and forcing even NV12 dimensions. Examples:

| Capture texture | Presentation target |
| --- | --- |
| 2560×1440 | 1920×1080 |
| 1920×1200 | 1728×1080 |
| 1366×768 | 1366×768 |

The source dimensions come from the actual Desktop Duplication texture rather than only from desktop coordinates so rotated-display resource geometry can be handled correctly.

## What to collect if the probe fails

Save the complete console output and collect the GPU/driver identity with:

```powershell
Get-CimInstance Win32_VideoController |
    Select-Object Name, DriverVersion, AdapterCompatibility, VideoProcessor
```

Also note:

- Windows version/build;
- whether the machine has Intel, NVIDIA, AMD, or hybrid graphics;
- monitor resolution and refresh rate;
- whether HDR is enabled;
- whether the failure occurred immediately or after frames had already encoded.

Do not work around an encoder/capture failure by silently switching the teacher presentation path to JPEG over TCP. The failure should remain observable so ClassMesh can select or repair a real-time video path deliberately.

## Follow-up validation

After the 15-second run is stable, repeat with:

```powershell
.\classmesh-media-probe.exe --seconds 300
```

while playing continuous motion. The five-minute run is the next soak gate before the presentation pipeline is enabled inside the normal Worker lifecycle.

Later qualification expands to Intel Quick Sync, NVIDIA, AMD, multi-monitor, rotation, HDR, lock/unlock, sleep/resume and display-topology changes.
