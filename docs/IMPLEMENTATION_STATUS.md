# ClassMesh Implementation Status

Last updated: 2026-09-15

This file distinguishes **implemented code**, **testable abstractions**, **hardware/platform work still missing**, and **active integration work**. It exists so architecture documents are not mistaken for completed product features.

## CI status

The repository is now public and GitHub-hosted runners are executing normally again.

Main branch baseline `a98bd6af4800dda734616f60cc6a5b164c138856` is verified green on both CI jobs:

- **Portable Rust / Ubuntu** — `cargo fmt`, Clippy with warnings denied, full workspace tests, and `classmesh-lab` all pass.
- **Windows Build** — full workspace Clippy and tests pass on `windows-latest`.

CI also uses concurrency cancellation so superseded runs do not create a large queue of obsolete jobs.

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
- Reassembly that tolerates packet reordering.
- Missing-packet reporting suitable for NACK.
- Sequence-gap/reordering tracking.
- Time/count-bounded retransmission cache.
- Bounded active receiver-frame window.
- NACK deadline, stale-frame drop and keyframe-recovery events.
- UDP datagram encoder/decoder and socket wrapper.
- IPv4 multicast join/leave primitives.
- Keyframe request coalescing/rate limiting.
- Frame pacing that never bursts old frames to catch up.
- Encode-once distributor model with independent slow-receiver queues.

### Windows architecture primitives

- Service/User-Session Worker lifecycle state machine.
- Logon/logoff/lock/unlock/console/remote-session events.
- Fast-user-switch worker replacement.
- Worker-crash restart policy without restarting machine service.
- Bounded local IPC framing and incremental parser.
- IPC authentication handshake state model.
- Capture backend/factory abstraction.
- Replaceable/recoverable capture controller.
- Secure-desktop/protected-content suspension concept.
- Display descriptor/identity model.
- Initial Windows SCM service executable and session-change event loop.

Active draft PR #6 adds the first real `WTSQueryUserToken` + `CreateProcessAsUserW` Service → interactive-session Worker path behind an isolated Win32 FFI crate.

### Codec capability primitives

- H.264-first codec model.
- Measured encoder capability classes instead of trusting vendor labels.
- p50/p95 benchmark summarization.
- GPU-native/low-latency/reset/bitrate/keyframe capability fields.
- Capability-cache key model including adapter/driver/encoder/profile.
- Media Foundation low-latency intent model.

### Security/discovery/tooling

- Control-plane Protobuf schema.
- Service/Worker IPC Protobuf schema.
- Enrollment/authorization/replay-window policy primitives.
- LAN discovery protocol and expiry/rate-limit primitives.
- `classmesh-lab` synthetic packet-loss/adaptation utility.
- Portable + Windows GitHub Actions validation.
- Architecture, roadmap, security, protocol and runtime validation documents.

## Not implemented yet

The following are the main hardware/platform milestones and must not be described as working features yet.

### Windows Service integration

Still required after PR #6:

- production user environment/profile setup for the Worker;
- authenticated Named Pipe endpoint with Windows ACL + peer process/session validation;
- IPC-driven suspend/resume/stop instead of prototype process termination/logging;
- bounded Worker restart backoff wired to the real process manager;
- installer/service registration and recovery configuration;
- LocalSystem login/lock/unlock/logoff/fast-user-switch soak validation.

### DXGI/WGC capture backend

Missing:

- actual adapter/output enumeration against Win32/DXGI;
- D3D11 device/context creation;
- `DuplicateOutput`/`DuplicateOutput1` backend;
- GPU texture ownership handoff;
- Windows error-code mapping into `CaptureFailure`;
- display-topology notifications/re-enumeration;
- Windows.Graphics.Capture alternate backend.

The lifecycle/recovery layer already exists so the platform implementation plugs into a tested replaceable backend instead of embedding policy inside raw COM calls.

### GPU processing and H.264 Media Foundation

Missing:

- D3D11 BGRA -> NV12 conversion/scaling;
- D3D11-aware Media Foundation MFT plumbing;
- `MFTEnumEx` hardware enumeration;
- `MF_LOW_LATENCY` / `CODECAPI_AVLowLatencyMode` application and capability reporting;
- asynchronous MFT input/output loop;
- local H.264 validation sink;
- first-run real hardware benchmark implementation.

### Receiver decode/render

Missing:

- Media Foundation/D3D11 hardware H.264 decoder;
- GPU presentation/swap-chain rendering;
- real jitter timing using receive clocks;
- end-to-end latency instrumentation.

### Control/security transport

Missing:

- QUIC/TLS runtime;
- Protobuf generated Rust types/build tooling;
- persistent enrollment and certificate/key storage;
- transport-connected authorization engine;
- media group encryption;
- key rotation/revocation.

### SFU/WebRTC

Not selected as mandatory infrastructure. LiveKit/WebRTC remains an empirical Wi-Fi/cross-subnet candidate. No SFU integration is implemented yet.

## Next implementation sequence

1. Finish and CI-validate PR #6 Service → User-Session Worker launch path.
2. Add authenticated Named Pipe lifecycle control and real Worker restart backoff.
3. Validate Service/Worker behavior under LocalSystem and the Windows session transition matrix.
4. Implement real DXGI GPU texture capture behind `CaptureBackend`.
5. Run display/runtime recovery tests before adding encoder complexity.
6. Implement D3D11 GPU processing + Media Foundation H.264 hardware encode/benchmark.
7. Implement hardware decode/render and prove one-to-one 1080p30 motion streaming.
8. Only then scale to multicast and Wi-Fi/SFU fan-out tests.
