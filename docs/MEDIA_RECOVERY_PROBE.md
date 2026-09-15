# ClassMesh Media Recovery Probe

`classmesh-media-recovery-probe.exe` validates the Windows GPU media lifecycle without requiring a real driver crash.

It is intentionally a deterministic reconstruction test, not a synthetic `DXGI_ERROR_DEVICE_REMOVED` generator. The probe keeps one interactive student presentation HWND alive and repeatedly:

1. creates a fresh D3D11 video device;
2. enumerates and activates a D3D11-aware Media Foundation H.264 decoder;
3. releases the old flip-model presenter/swap chain;
4. creates a new presenter on the same HWND and new device;
5. replaces the decoder/device generation;
6. pumps the existing window between cycles.

This catches resource-lifetime problems that hosted compile-only CI cannot detect, especially the requirement that the old flip-model swap chain be released before creating another swap chain for the same HWND.

## CI artifact

The Windows CI job publishes:

```text
classmesh-media-recovery-probe-windows-x64
```

containing:

```text
classmesh-media-recovery-probe.exe
```

## Basic run

Run from an interactive signed-in Windows session:

```powershell
.\classmesh-media-recovery-probe.exe --cycles 10 --pause-ms 250
```

For a longer lifecycle soak:

```powershell
.\classmesh-media-recovery-probe.exe --cycles 100 --pause-ms 100
```

Keep the presentation window open. During the probe you may also resize, maximize, minimize, and restore it to combine HWND lifecycle pressure with repeated GPU media reconstruction.

## Pass criteria

A useful first pass requires:

- every requested recovery cycle completes;
- the same presentation HWND survives all cycles;
- every replacement decoder is D3D11-aware and successfully activated;
- every replacement flip-model swap chain is created successfully;
- no process crash or hang;
- no monotonically increasing recovery latency;
- no teacher/control reconnect is involved because this probe isolates the student media lifecycle.

The executable reports per-cycle recovery time plus total and longest recovery duration.

## What this does not prove

A green recovery probe does **not** prove that a real GPU/driver reset is handled correctly. Real `DXGI_ERROR_DEVICE_REMOVED`, `DXGI_ERROR_DEVICE_RESET`, hybrid-GPU changes, sleep/resume, RDP/VDI transitions, and vendor-driver behavior still require physical Windows qualification.

The next end-to-end gate is the normal two-machine stream:

```text
Teacher DXGI capture -> GPU conversion -> H.264 encode -> UDP -> student H.264 decode -> D3D11 presentation
```

with a recovery request injected while encoded media is flowing, followed by a fresh keyframe and resumed presentation.
