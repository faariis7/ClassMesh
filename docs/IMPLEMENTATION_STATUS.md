# ClassMesh Implementation Status

Last updated: 2026-09-18

This file distinguishes **implemented code**, **hosted-CI validation**, **real-hardware validation still required**, and **future product work**. Architecture documents must not be read as claims that every planned feature is already production-ready.

## Current baseline

`main` includes Phase 4 implementation and qualification tooling through PR #31 plus the Phase 5A control-session foundation from PR #33 (merge `86e3a09b0e36ec38e29210dacd50b8c7f806e3e4`).

Phase 4 physical acceptance remains pending. Issue #3 must remain open until two physical Windows PCs pass the documented qualification.

Phase 5 is tracked in Issue #32. Phase 5B implementation is complete in PR #34 and Linux + Windows CI run #227 passed. The PR is still not merged, so `main` must not yet be described as containing the QUIC/TLS runtime.

The hosted CI baseline covers:

- **Portable Rust / Ubuntu** — rustfmt, Clippy with warnings denied, full workspace tests, and `classmesh-lab`.
- **Windows Build** — workspace Clippy/tests plus release builds for the media probe, media receiver, media recovery probe, deterministic network impairment proxy, and UDP/QUIC Datagram transport benchmark.

Hosted Windows runners prove that the Win32/D3D11/Media Foundation code compiles and deterministic tests pass. They do **not** prove that Desktop Duplication, hardware H.264 encode/decode, D3D11 presentation, or two-machine latency behaves correctly on real interactive GPU/driver combinations.

The immediate Phase 4 gate remains physical two-PC qualification using `docs/PHASE4_TWO_PC_QUALIFICATION.md` and `scripts/phase4-two-pc.ps1`.

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

### Phase 5A control-session foundation

Merged in PR #33:

- Control-plane Protobuf is compiled into Rust types during the build using a vendored `protoc`.
- Reliable `ControlEnvelope` carries session ID, sequence, protocol version, request ID and typed payload.
- `Hello` / `HelloAck` schema supports explicit protocol negotiation, role, credential fingerprint and shared capabilities.
- Protocol major mismatch is explicit; compatible peers select the lower minor version.
- Shared capability intersection is deterministic.
- Heartbeat tracking has Online / Suspect / Offline transitions.
- Duplicate/non-increasing heartbeat sequences and wrong control-session IDs are rejected.
- Media health is independent from control liveness.
- Initial heartbeat defaults are 2s interval / 6s suspect / 10s offline.
- Stable identity is documented independently from credential fingerprints.
- Administrative QUIC 0-RTT is excluded from the initial security model.

### AI-assisted engineering/design quality tooling

Repository-level quality instructions are now defined under `.agents/skills/`:

- `classmesh-engineering` — roadmap/security/evidence gates plus the engineering workflow.
- `classmesh-design` — Windows desktop UI/UX, accessibility, DPI, runtime and live-grid constraints.
- `frontend-design-review` — Microsoft-derived independent UI critique layer.

`docs/AI_QUALITY_STACK.md` records the maintained external layers (Superpowers, UI/UX Pro Max and Codex Security), their source/update policy, and the rule that external skills are reviewed like third-party dependencies.

These instructions improve agent consistency; they do not replace tests, security review, CI, runtime inspection or human product decisions.

## Ready to merge

### Phase 5B reliable QUIC/TLS control runtime

PR #34 has completed implementation and passed Linux + Windows CI run #227.

Implemented on the PR branch:

- reliable bidirectional QUIC control streams using Quinn/rustls;
- ALPN `classmesh-control/1`;
- explicit rustls `ring` CryptoProvider with TLS 1.3 only;
- application 0-RTT disabled;
- 4-byte big-endian length-prefixed Protobuf framing;
- 256 KiB maximum message size enforced before allocation;
- connect/I/O/idle/keepalive timeouts;
- bounded reconnect policy;
- Hello/HelloAck and heartbeat over the real transport;
- loopback TLS/ALPN → QUIC → framing → hello → heartbeat coverage;
- corrected test lifetime so the server endpoint/connection remain alive through the final control frame.

This section remains distinct from implemented-on-`main` until PR #34 merges.

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

- Bounded timeout/watchdog around asynchronous Media Foundation event waits.
- Measured `ICodecAPI` low-latency/rate-control/GOP/keyframe controls.
- First-run encoder benchmark and capability cache wired to real adapter/driver/CLSID data.
- Deliberate multi-GPU encoder selection.
- Recovery/rebuild after encoder/device loss across representative drivers.
- Long-running resource/leak/driver soak tests.

### Classroom fan-out runtime

Still required:

- production integration of shared encoded output into the normal Teacher/Worker lifecycle;
- multicast sender and authenticated group-media protection;
- per-client fallback selection;
- receiver telemetry wired into the production adaptation/controller path;
- classroom-scale 2/5/10/20+ device tests on wired LAN and Wi-Fi.

### Control/security transport — later Phase 5

Still missing or incomplete:

- persistent enrollment and protected certificate/key storage;
- post-enrollment mTLS identity;
- revocation/key rotation;
- transport-connected authorization engine;
- replay/duplicate enforcement connected to privileged commands;
- capability/session negotiation completed over authenticated transport;
- encrypted multicast media session keys, replay protection and rotation;
- production per-user SID ACL on the local Named Pipe.

### Installer/update/product surface

Still required:

- installer/service registration and firewall setup;
- signed update manifest/package flow and rollback;
- polished Console/Agent UI integration;
- diagnostics export and support bundle.

## Next implementation sequence

1. Keep Issue #3 open and run Phase 4 physical qualification when two Windows PCs are available.
2. Merge PR #34 Phase 5B after validating its integration with current `main`, then update Issue #32.
3. Begin Phase 5C persistent identity/enrollment/mTLS with Windows-protected credential storage behind a testable abstraction.
4. Add dependency/advisory/license and fuzzing gates when they become useful to the active phase rather than as unused tooling.
5. Start product UI work under `classmesh-design` and runtime/visual verification once the Console/Agent surface becomes an active implementation track.
