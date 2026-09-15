# ClassMesh Implementation Status

Last updated: 2026-09-15

This file distinguishes **implemented code**, **hosted-CI validation**, **real-hardware validation still required**, and **future product work**. Architecture documents must not be read as claims that every planned feature is already production-ready.

## Current baseline

Main now includes the merged live presentation-media work through PR #14 (`65e0db1633792fe620a2cf20832a293b11abce00`). PR #14 passed both hosted CI jobs before merge:

- **Portable Rust / Ubuntu** — rustfmt, Clippy with warnings denied, full workspace tests, and `classmesh-lab` pass.
- **Windows Build** — full workspace Clippy and tests pass on `windows-latest`.

Hosted Windows runners prove that the Win32/D3D11/Media Foundation code compiles and its deterministic tests pass. They do **not** prove that Desktop Duplication, D3D11 Video Processor, or a hardware encoder works correctly on a real interactive GPU/driver combination.

PR #15 adds a release-mode Windows `classmesh-media-probe.exe` workflow artifact and the real-hardware runbook so that the next validation gate can be executed without first wiring presentation encoding into the normal classroom Worker lifecycle.

## Implemented in the repository

### Core runtime policy

- Separate control/media state concepts.
- Bounded `LatestQueue<T>` with stale-media eviction/drop accounting.
- Recovery controller with bounded exponential backoff.
- Baseline network adaptation policy with separate monitoring/presentation profiles.
- Stateful quality/transport hysteresis to prevent protocol and bitrate flapping.
- Receiver cohort grouping so one weak client does not force a class-wide downgrade.
- Rolling capture/encode/queue/decode/render latency metrics and media counters.

### Media protocol/network primitives

- Fixed, validated v0.1 media datagram header.
- 1200-byte media payload budget.
- Frame packetization with sequence wrapping.
- Reassembly tolerant of packet reordering.
- Missing-packet reporting suitable for NACK.
- Sequence-gap/reordering tracking.
- Time/count-bounded retransmission cache.
- Bounded active receiver-frame window.
- NACK deadline, stale-frame drop and keyframe-recovery events.
- UDP datagram encoder/decoder and socket wrapper.
- IPv4 multicast join/leave primitives.
- Keyframe request coalescing/rate limiting.
- Frame pacing that never bursts old frames to catch up.
- Encode-once distributor model using one shared encoded allocation and independent bounded sink queues.
- Optional bounded rendition-planning model so simulcast is not created for every isolated weak receiver.

### Windows Service / interactive Worker boundary

Merged PRs #6 and #7 implement the first real Windows runtime boundary:

- Service launches a Worker into the selected interactive Windows session with `WTSQueryUserToken` + `CreateProcessAsUserW`.
- Worker validates its Windows session identity.
- Fast-user-switch replaces the active Worker instead of moving capture into Session 0.
- Unexpected Worker exit and launch failure use bounded restart policy.
- Local duplex Named Pipe transport is implemented.
- Remote Named Pipe clients are disabled.
- Service validates the exact launched Worker PID and Windows session before trusting IPC.
- Typed/versioned WorkerHello, ServiceReady, SuspendMedia, ResumeMedia and Shutdown messages are implemented.
- Lock/unlock and stop lifecycle control is connected to the Worker.

Production hardening still includes a per-user SID pipe DACL, production environment/profile setup, installer/service registration and LocalSystem soak testing.

### Real DXGI Desktop Duplication capture

Merged PRs #8 and #9 implement real GPU-native capture:

- DXGI adapter/output enumeration.
- Stable display identity using adapter LUID + output index.
- D3D11 device creation on the selected adapter.
- `IDXGIOutputDuplication` creation and `AcquireNextFrame`.
- GPU-native `ID3D11Texture2D` frame ownership without CPU readback.
- RAII `ReleaseFrame` behavior.
- explicit mapping for timeout, access-lost, device-reset and device-removed failures.
- replace/recreate recovery rather than permanent sticky fallback.
- the capture loop runs inside the interactive Worker and responds to Service suspend/resume/shutdown control.

Real runtime validation is still required for Intel/NVIDIA/AMD drivers, rotation, multi-monitor, HDR, secure desktop, lock/unlock, sleep/resume and display-topology changes.

### GPU processing and Media Foundation H.264

Merged PRs #10–#14 establish the first complete code path from live DXGI frame to encoded H.264 bytes:

- COM + Media Foundation RAII platform lifetime.
- hardware H.264 MFT enumeration and activation.
- shared D3D11 device through `IMFDXGIDeviceManager`.
- NV12 input / H.264 output media type configuration.
- GPU texture wrapping through `MFCreateDXGISurfaceBuffer`.
- D3D11 Video Processor BGRA → NV12 conversion/scaling with no CPU `Bitmap`, staging readback, or System.Drawing hot path.
- caller-owned NV12 output textures.
- bounded preallocated NV12 `SurfacePool`.
- asynchronous MFT input/output flow driven by `METransformNeedInput` / `METransformHaveOutput`.
- pending-surface ownership retained until encoded output or explicit flush/drain proves a surface is safe to recycle.
- encoded access units paired back to ClassMesh frame id/timestamp metadata.
- clean-point + Annex-B IDR keyframe detection.
- `SharedEncodedFrame` output suitable for one-allocation fan-out.
- live `PresentationPipeline` that polls/recycles completed outputs, paces capture to 30 fps and drops stale work instead of growing latency.
- actual capture texture geometry is used for source sizing, and output is capped at 1920×1080 without upscaling while preserving aspect ratio and even NV12 dimensions.
- Desktop Duplication frames are released immediately after GPU conversion, before waiting on encoder input.
- standalone `classmesh-media-probe` exercises the full path without enabling it in the normal production Worker yet.

**Important:** the complete code path is implemented and CI-clean, but real GPU/driver execution is the next gate. Until `classmesh-media-probe` succeeds on interactive Windows hardware, do not describe 1080p30 hardware presentation as validated.

### Security/discovery/tooling

- Control-plane Protobuf schema.
- Service/Worker IPC Protobuf schema.
- Enrollment/authorization/replay-window policy primitives.
- LAN discovery protocol and expiry/rate-limit primitives.
- `classmesh-lab` synthetic packet-loss/adaptation utility.
- Portable + Windows GitHub Actions validation.
- architecture, roadmap, security, protocol and runtime validation documents.
- media-probe hardware validation runbook.

## Not implemented or not validated yet

### Immediate hardware validation gate

Run `classmesh-media-probe` on a signed-in teacher Windows desktop while continuous motion is visible. The first gate is a 15-second run; after that succeeds, run a five-minute soak. See `docs/MEDIA_PROBE.md`.

Required observations:

- hardware encoder selected successfully;
- encoded frame count continues advancing;
- no CPU bitmap/readback path appears;
- bounded NV12 pool remains bounded;
- pool drops stay low/zero under a healthy local GPU;
- no hang, disconnect, or growing latency queue.

Repeat later on representative Intel Quick Sync, NVIDIA and AMD devices.

### Encoder/runtime hardening

Still required before the presentation pipeline is production-enabled:

- bounded timeout/watchdog around asynchronous Media Foundation event waits so a broken driver cannot hang the Worker indefinitely;
- measured `ICodecAPI` low-latency/rate-control/GOP/keyframe controls rather than assuming vendor behavior;
- first-run encoder benchmark and capability cache wired to real adapter/driver/CLSID data;
- deliberate multi-GPU encoder selection instead of assuming the first enumerated hardware MFT is optimal;
- recovery/rebuild after encoder/device loss;
- long-running resource/leak/driver soak tests.

### Receiver decode/render

Missing:

- Media Foundation/D3D11 hardware H.264 decoder;
- GPU presentation/swap-chain rendering;
- real jitter timing using receive clocks;
- end-to-end glass-to-glass latency instrumentation.

### Classroom fan-out runtime

Protocol primitives exist, but the live encoded output is not yet connected to production network fan-out. Still required:

- live `SharedEncodedFrame` → packetizer → UDP unicast path for the first two-machine stream;
- live multicast sender for teacher presentation;
- per-client fallback selection (multicast → UDP unicast → later fallback options);
- NACK/keyframe recovery connected to the real encoder;
- receiver quality telemetry feeding adaptation policy;
- classroom-scale 2/5/10/20+ device tests on wired LAN and Wi-Fi.

### Control/security transport

Still missing or incomplete:

- QUIC/TLS control runtime;
- persistent enrollment and certificate/key storage;
- transport-connected authorization engine;
- encrypted multicast media session keys, replay protection and rotation;
- production per-user SID ACL on the local Named Pipe.

### Installer/update/product surface

Still required:

- installer/service registration and firewall setup;
- signed update manifest/package flow and rollback;
- polished Console/Agent UI integration;
- diagnostics export and support bundle.

## Next implementation sequence

1. Build/publish PR #15 media-probe artifact.
2. Run the 15-second and five-minute live Windows GPU/H.264 probe.
3. Fix any adapter/driver/MFT compatibility issue revealed by the probe before hiding it behind fallback logic.
4. Add bounded Media Foundation wait timeouts, measured codec controls and encoder capability selection.
5. Implement hardware H.264 decode + GPU render on a second Windows machine.
6. Prove one-to-one 1080p30 motion streaming over UDP with end-to-end latency metrics.
7. Connect shared encoded output to multicast plus per-client unicast fallback.
8. Run wired/Wi-Fi classroom scale and loss/jitter/reorder tests.
9. Only after the media engine is proven, expand product UI and installer/update polish.
