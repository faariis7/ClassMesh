# ClassMesh Implementation Status

Last updated: 2026-09-15

This file distinguishes **implemented code**, **testable abstractions**, **hardware/platform work still missing**, and **external validation blockers**. It exists so architecture documents are not mistaken for completed product features.

## Implemented in the repository

### Core runtime policy

- Separate control/media state concepts.
- Bounded `LatestQueue<T>` with stale-media eviction/drop accounting.
- Recovery controller with bounded exponential backoff.
- Baseline network adaptation policy with separate monitoring/presentation profiles.
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

### Windows architecture primitives

- Service/User-Session Worker lifecycle state machine.
- Logon/logoff/lock/unlock/console/remote-session events.
- Fast-user-switch worker replacement.
- Worker-crash restart without restarting machine service.
- Bounded local IPC framing and incremental parser.
- IPC authentication handshake state model.
- Capture backend/factory abstraction.
- Replaceable/recoverable capture controller.
- Secure-desktop/protected-content suspension concept.
- Display descriptor/identity model.

### Codec capability primitives

- H.264-first codec model.
- Measured encoder capability classes instead of trusting vendor labels.
- p50/p95 benchmark summarization.
- GPU-native/low-latency/reset/bitrate/keyframe capability fields.
- Capability-cache key model including adapter/driver/encoder/profile.
- Media Foundation low-latency intent model.

### Schemas and developer tooling

- Control-plane Protobuf schema.
- Service/Worker IPC Protobuf schema.
- `classmesh-lab` synthetic packet-loss/adaptation utility.
- Windows CI workflow configuration.
- Architecture, roadmap, security, protocol and runtime validation documents.

## Not implemented yet

The following are the main hardware/platform milestones and must not be described as working features yet.

### Windows Service integration

Missing:

- actual SCM service executable/registration;
- WTS event subscription;
- `WTSQueryUserToken`/equivalent session token resolution;
- safe `CreateProcessAsUser` Worker launch;
- Named Pipe endpoint + Windows ACL/process validation;
- service recovery configuration.

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
- enrollment and certificate/key storage;
- authorization engine;
- media group encryption;
- key rotation/revocation.

### SFU/WebRTC

Not selected as mandatory infrastructure. LiveKit/WebRTC remains an empirical Wi-Fi/cross-subnet candidate. No SFU integration is implemented yet.

## Current validation blocker

GitHub Actions workflow jobs are currently terminating before any workflow steps execute (`runner_id` is reported as `0` and the job contains no executed steps). Therefore the repository cannot currently claim CI-verified compilation/test success for the newest commits.

Until GitHub Actions runners execute normally, new code should be treated as **implementation in progress pending compiler/Clippy/test validation**. Once a runner is available, the first task is:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p classmesh-lab
```

Any failures discovered there take priority over adding new platform features.

## Next implementation sequence

1. Restore/obtain an executable Windows CI or local Windows Rust build loop.
2. Compile/fix the current pure-Rust workspace until formatting, Clippy and tests are green.
3. Implement the actual Service → User-Session Worker launcher and Named Pipe security boundary.
4. Implement real DXGI GPU texture capture behind `CaptureBackend`.
5. Run the runtime/display recovery matrix before adding encoder complexity.
6. Implement D3D11 GPU processing + Media Foundation H.264 hardware encode/benchmark.
7. Implement hardware decode/render and prove one-to-one 1080p30 motion streaming.
8. Only then scale to multicast and Wi-Fi/SFU fan-out tests.
