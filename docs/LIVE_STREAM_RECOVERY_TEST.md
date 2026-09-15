# Live-Stream GPU Recovery Test

ClassMesh can now exercise the student GPU media reconstruction path **while real H.264 media is flowing**.

This is stronger than `classmesh-media-recovery-probe.exe`: the standalone recovery probe validates repeated D3D11/MF resource reconstruction, while this test validates reconstruction inside the normal UDP receive -> H.264 decode -> D3D11 presentation diagnostic.

## Student

Start the receiver with rendering and schedule one deterministic recovery after a known number of decoder-eligible frames:

```powershell
.\classmesh-media-receiver.exe `
  --listen 0.0.0.0:57000 `
  --seconds 120 `
  --render `
  --recover-after-frames 90
```

The counter begins once the receiver reaches a usable H.264 keyframe, so the test does not waste its scheduled recovery while the decoder is still waiting for initial synchronization.

At the configured frame the receiver deliberately runs the same D3D11 + Media Foundation reconstruction path used after a real device-loss error. This is a controlled lifecycle test; it does not manufacture a fake DXGI HRESULT or crash the driver.

## Teacher

Send the normal encoded presentation stream:

```powershell
.\classmesh-media-probe.exe --seconds 120 --udp-to STUDENT_IP:57000
```

Keep motion on the teacher desktop so visual recovery is obvious.

## Expected sequence

For a non-keyframe recovery point:

```text
Streaming
  -> scheduled GPU media recovery
  -> create fresh D3D11 device + MF decoder
  -> release old student flip chain
  -> bind new presenter to the same HWND
  -> WaitingForKeyframe
  -> next IDR
  -> decode resumes
  -> presentation resumes
```

If the scheduled frame itself is a keyframe, ClassMesh may reuse that access unit immediately after rebuilding instead of waiting for another IDR.

## Telemetry

Periodic and final receiver diagnostics include:

- `gpu_recoveries`
- `forced_gpu_recoveries`
- `last_gpu_recovery_ms`
- `longest_gpu_recovery_ms`
- `decode_waiting_frames`
- `decoded_gpu_frames`
- `presented_frames`
- `present_errors`
- network loss/reorder/stale-frame counters

## Pass criteria

The first live-stream recovery gate passes when:

1. `forced_gpu_recoveries=1`;
2. `gpu_recoveries` increases without terminating the receiver;
3. the existing presentation window survives;
4. the receiver waits for a keyframe when required rather than decoding stale inter frames;
5. `decoded_gpu_frames` and `presented_frames` continue increasing after recovery;
6. no TCP/JPEG fallback appears;
7. no teacher reconnect is required;
8. recovery latency remains bounded and the media queue does not grow.

Run the same test at several recovery points, for example 30, 90, 300, and 900 frames. Then repeat while resizing/minimizing the student presentation window.

## Remaining physical qualification

This deterministic test validates the recovery control flow and object lifetime while media is active. It still does not replace real Intel/NVIDIA/AMD tests for `DXGI_ERROR_DEVICE_REMOVED`, `DXGI_ERROR_DEVICE_RESET`, sleep/resume, hybrid GPU changes, or driver resets.
