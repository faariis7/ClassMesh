# ClassMesh Implementation Status

Last updated: 2026-09-15

This file distinguishes **implemented code**, **hosted-CI validation**, **real-hardware validation still required**, and **future product work**. Architecture documents must not be read as claims that every planned feature is already production-ready.

## Current baseline

`main` now includes Phase 4 implementation work through PR #29 (`553fca31d4adcb8723e64711dfec2e9e36cdcdb8`). The current hosted CI baseline covers:

- **Portable Rust / Ubuntu** — rustfmt, Clippy with warnings denied, full workspace tests, and `classmesh-lab`.
- **Windows Build** — workspace Clippy/tests plus release builds for the media probe, media receiver, media recovery probe, deterministic network impairment proxy, and UDP/QUIC Datagram transport benchmark.

Hosted Windows runners prove that the Win32/D3D11/Media Foundation code compiles and deterministic tests pass. They do **not** prove that Desktop Duplication, hardware H.264 encode/decode, D3D11 presentation, or two-machine latency behaves correctly on real interactive GPU/driver combinations.

The immediate gate is now physical two-PC Phase 4 qualification using `docs/PHASE4_TWO_PC_QUALIFICATION.md` and `scripts/phase4-two-pc.ps1`.

## Implemented in the repository

### Core runtime policy

- Separate control/media state concepts.
- Bounded `LatestQueue<T>` with stale-media eviction/drop accounting.
- Recovery controller with bounded exponential backoff.
- Baseline network adaptation policy with separate monitoring/presentation profiles.
- Stateful quality/transport hysteresis to prevent protocol and bitrate flapping.
- Receiver cohort grouping so one weak client does not force a class-wide downgrade.
- Rolling capture/encode/queue/decode/render latency metric primitives and media counters.

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

- DXGI adapter/output enumeration.
- Stable display identity using adapter LUID + output index.
- D3D11 device creation on the selected adapter.
- `IDXGIOutputDuplication` creation and `AcquireNextFrame`.
- GPU-native `ID3D11Texture2D` frame ownership without CPU readback.
- RAII `ReleaseFrame` behavior.
- Explicit mapping for timeout, access-lost, device-reset and device-removed failures.
- Replace/recreate recovery rather than permanent sticky fallback.
- Capture loop runs inside the interactive Worker and responds to Service suspend/resume/shutdown control.

Real runtime validation is still required across representative Intel/NVIDIA/AMD drivers, rotation, multi-monitor, HDR, secure desktop, lock/unlock, sleep/resume and display-topology changes.

### GPU processing and hardware H.264 encode

- COM + Media Foundation RAII platform lifetime.
- Hardware H.264 MFT enumeration and activation.
- Shared D3D11 device through `IMFDXGIDeviceManager`.
- NV12 input / H.264 output media type configuration.
- GPU texture wrapping through `MFCreateDXGISurfaceBuffer`.
- D3D11 Video Processor BGRA → NV12 conversion/scaling without a CPU bitmap hot path.
- Caller-owned NV12 output textures.
- Bounded preallocated NV12 `SurfacePool`.
- Asynchronous MFT input/output flow driven by Media Foundation events.
- Pending-surface ownership retained until encoded output or explicit flush/drain proves reuse is safe.
- Encoded access units paired to ClassMesh frame id/timestamp metadata.
- Clean-point + Annex-B IDR keyframe detection.
- `SharedEncodedFrame` output suitable for one-allocation fan-out.
- Live `PresentationPipeline` paced to 30 fps with stale-work drops instead of latency growth.
- Output capped at 1920×1080 without upscaling while preserving aspect ratio and even NV12 dimensions.
- Desktop Duplication frames released immediately after GPU conversion.
- Standalone `classmesh-media-probe.exe` exercises capture → process → hardware encode → UDP packetization.

### Hardware H.264 decode and D3D11 presentation

The Phase 4 receiver path is implemented and CI-clean:

- `classmesh-media-receiver.exe` receives/reassembles ClassMesh UDP media frames.
- Media Foundation/D3D11 hardware H.264 decoding is available with `--decode` / `--render`.
- `--render` enables the D3D11 flip-model presentation window.
- Receiver feedback reports missing/stale media recovery signals to the Teacher sender.
- Receiver telemetry includes decoded GPU frames, presented frames, decode/present errors, stale drops, NACK/keyframe requests, and recovery timing.
- `--recover-after-frames` deliberately rebuilds GPU media resources for recovery qualification.
- The Teacher media probe consumes receiver feedback, retransmits cached packets when useful, and coalesces/rate-limits keyframe requests.

**Important:** this is implemented code, not yet a claim that real two-PC 1080p30 hardware presentation has passed the Phase 4 exit criteria.

### Phase 4 impairment and transport qualification tooling

- Deterministic media loss/jitter/reorder engine with reproducible seeds.
- Bounded one-way media impairment proxy with queue/drop/reorder statistics.
- Baseline, 1%, 3%, 5%, and 30-minute impairment procedures.
- Synthetic `classmesh-transport-benchmark` with equivalent UDP and QUIC Datagram modes.
- Configurable packets-per-second and application payload size.
- Application acknowledgement RTT without requiring synchronized PC clocks.
- Bounded latency sample window with lifetime min/avg/max and recent p50/p95/p99.
- QUIC path statistics including RTT, congestion window, loss, congestion events and MTU.
- Explicit copied DER trust for the benchmark self-signed certificate; this is not production enrollment identity.
- Windows CI publishes the transport benchmark executable.
- `scripts/phase4-two-pc.ps1` standardizes the physical commands and captures logs.
- `docs/PHASE4_TWO_PC_RESULTS.md` is the persistent physical-result record and remains pending until real hardware is tested.

### Security/discovery/tooling

- Control-plane Protobuf schema.
- Service/Worker IPC Protobuf schema.
- Enrollment/authorization/replay-window policy primitives.
- LAN discovery protocol and expiry/rate-limit primitives.
- Portable + Windows GitHub Actions validation.
- Architecture, roadmap, security, protocol and runtime validation documents.

## Not implemented or not validated yet

### Immediate Phase 4 physical validation gate

Run the two-PC sequence in `docs/PHASE4_TWO_PC_QUALIFICATION.md` on two signed-in Windows machines.

Required observations before Issue #3 can close:

- Teacher hardware capture/encode stays live under continuous motion.
- Student hardware decode + D3D11 render stays live at the target 1080p30 workload.
- Healthy wired-LAN end-to-end latency is measured; the Phase 4 engineering target is `<100 ms`.
- No steadily growing display delay during a 30-minute run.
- 1%, 3%, and 5% deterministic loss/jitter/reorder degrade and recover the video path without dropping the device/control session.
- UDP and QUIC Datagram synthetic benchmark results are recorded before selecting the unicast default.

If current telemetry cannot substantiate the end-to-end latency target, that missing instrumentation remains a Phase 4 blocker; do not infer a pass from visual smoothness alone.

### Encoder/runtime hardening

Still required before the presentation pipeline is production-enabled broadly:

- Bounded timeout/watchdog around asynchronous Media Foundation event waits so a broken driver cannot hang the Worker indefinitely.
- Measured `ICodecAPI` low-latency/rate-control/GOP/keyframe controls rather than assuming vendor behavior.
- First-run encoder benchmark and capability cache wired to real adapter/driver/CLSID data.
- Deliberate multi-GPU encoder selection instead of assuming the first enumerated hardware MFT is optimal.
- Recovery/rebuild after encoder/device loss across representative drivers.
- Long-running resource/leak/driver soak tests.

### End-to-end observability gaps

The receiver/sender expose useful counters, but Phase 4 still needs hardware evidence for the complete latency budget:

- capture timing;
- GPU process timing;
- encode timing;
- sender queue age;
- network RTT/loss/jitter;
- receiver reassembly/jitter delay;
- decode timing;
- render/presentation timing;
- an end-to-end value that can demonstrate the `<100 ms` target without synchronized-PC ambiguity.

### Classroom fan-out runtime

The first two-machine UDP media path exists, but production classroom fan-out is intentionally later. Still required:

- production integration of shared encoded output into the normal Teacher/Worker lifecycle;
- multicast sender and authenticated group-media protection;
- per-client fallback selection;
- receiver telemetry wired into the production adaptation/controller path;
- classroom-scale 2/5/10/20+ device tests on wired LAN and Wi-Fi.

### Control/security transport — Phase 5

Still missing or incomplete:

- QUIC/TLS control runtime;
- persistent enrollment and certificate/key storage;
- transport-connected authorization engine;
- heartbeat/capability/session negotiation over the real control transport;
- encrypted multicast media session keys, replay protection and rotation;
- production per-user SID ACL on the local Named Pipe.

The QUIC Datagram benchmark from Phase 4 does not replace this Phase 5 identity/control-plane work.

### Installer/update/product surface

Still required:

- installer/service registration and firewall setup;
- signed update manifest/package flow and rollback;
- polished Console/Agent UI integration;
- diagnostics export and support bundle.

## Next implementation sequence

1. Merge the Phase 4 two-PC qualification runner/runbook after CI is green.
2. Run healthy UDP and QUIC Datagram synthetic benchmarks on two Windows PCs and record the results.
3. Run the live hardware encode → UDP → hardware decode/render baseline.
4. Run deterministic 1%, 3%, and 5% loss/jitter/reorder recovery tests.
5. Run the 30-minute 3% impairment soak and record queue/resource/latency behavior.
6. If the `<100 ms` gate cannot be measured directly, implement the missing end-to-end latency instrumentation and repeat the baseline.
7. Update `docs/PHASE4_TWO_PC_RESULTS.md`, choose the measured Phase 4 unicast default, and close Issue #3 only when every acceptance item is evidenced.
8. Begin Phase 5: reliable QUIC/TLS control plane, device/teacher identity, enrollment, authorization, heartbeat and capability/session negotiation.
