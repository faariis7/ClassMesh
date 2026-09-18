# ClassMesh

ClassMesh is a Windows-first classroom streaming, monitoring, and remote-management platform designed for low latency, high device density, and graceful operation on both wired and Wi-Fi networks.

> Status: **engine prototyping**. The first goal is not UI polish; it is proving a recoverable GPU-native 1080p30 streaming pipeline between two Windows machines, then scaling it to a classroom.

## Product goals

- Teacher-to-class presentation with smooth video playback and no growing delay.
- Student monitoring grid that scales without sending full-resolution streams for every device.
- One-to-one remote viewing/control with low input latency.
- Strong recovery behavior: capture, codec, or video transport failures must not mark a device offline if the control session is healthy.
- Hardware-accelerated capture/encode/decode/render on Windows.
- Secure device enrollment, authenticated control, and encrypted video.
- Adaptive behavior across Ethernet, Wi-Fi, multicast-capable and multicast-hostile networks.

## Architecture baseline

ClassMesh deliberately separates three workloads:

1. **Monitoring** — low-rate, low-resolution thumbnails optimized for many students.
2. **Interactive remote control** — responsive unicast stream plus independent input/control.
3. **Teacher presentation** — one hardware encode per rendition distributed to many receivers, preferring multicast on suitable managed wired LANs.

Initial platform direction:

- **Core / video / networking:** Rust
- **Windows process model:** Session 0 service + per-user interactive Worker
- **Windows graphics:** D3D11 + DXGI Desktop Duplication, with Windows Graphics Capture as a secondary backend
- **Codec:** H.264 first; hardware Media Foundation path preferred and benchmarked at runtime
- **Control plane:** QUIC/TLS 1.3 + Protocol Buffers
- **Video plane:** low-latency datagrams; multicast for suitable wired presentation; unicast/SFU candidates for Wi-Fi
- **Windows UI:** separate native UI layer; final framework decision is deferred until engine gates are stable

See [Architecture](docs/ARCHITECTURE.md), [Roadmap](docs/ROADMAP.md), [Living Work Plan](docs/WORK_PLAN.md), [Protocol](docs/PROTOCOL.md), [Testing](docs/TESTING.md), [Security](docs/SECURITY.md), and the [current implementation status](docs/IMPLEMENTATION_STATUS.md).

## Non-negotiable engineering rules

- Never capture the interactive desktop directly from Session 0.
- No `Bitmap`/JPEG round-trip in the teacher-presentation hot path.
- Capture and decoded frames stay GPU-side whenever practical.
- Bounded queues only. **Latest frame wins**; stale frames are dropped rather than accumulated.
- Video health and device/control health are separate state machines.
- A slow receiver must never stall the class.
- One classroom presentation is encoded once for the main rendition, not once per student.
- No global protocol switch based only on student count; topology and measured health drive per-client/cohort decisions.
- Hardware encoders are measured, not trusted because of their name/vendor label.
- Recovery is a first-class feature, not an afterthought.

## First proof target

Before building the full classroom UI, ClassMesh must demonstrate:

- 1920×1080 at 30 FPS;
- hardware H.264 encode and decode when supported;
- <100 ms engineering target end-to-end latency on a healthy LAN;
- no latency growth over a 30-minute stream;
- smooth playback while the teacher plays high-motion video;
- automatic capture/codec recovery without terminating the control session;
- bounded queues and explainable p50/p95 stage latency metrics.

## Current repository layout

```text
ClassMesh/
├─ crates/
│  ├─ classmesh-core/             # queues, recovery, adaptation, metrics
│  ├─ classmesh-protocol/         # versioning + generated control schema + native media header
│  ├─ classmesh-control/          # control negotiation, heartbeat and liveness state
│  ├─ classmesh-network/          # packetization, UDP, loss/NACK/reassembly
│  ├─ classmesh-video/            # codec policy, pacing, keyframe coordination
│  ├─ classmesh-capture-win/      # capture lifecycle/backend abstraction
│  ├─ classmesh-codec-win/        # encoder benchmark/capability policy
│  ├─ classmesh-security/         # enrollment/authorization/replay policy
│  └─ classmesh-windows-runtime/  # Session Worker supervision + local IPC
├─ proto/
│  ├─ classmesh_control.proto
│  └─ classmesh_ipc.proto
├─ docs/
│  ├─ ARCHITECTURE.md
│  ├─ ROADMAP.md
│  ├─ PROTOCOL.md
│  ├─ TESTING.md
│  ├─ SECURITY.md
│  ├─ WINDOWS_RUNTIME_PLAN.md
│  ├─ IMPLEMENTATION_STATUS.md
│  └─ decisions/
├─ tools/
│  └─ classmesh-lab/              # synthetic loss/adaptation developer lab
└─ .github/workflows/ci.yml
```

## Local validation commands

Once a Windows Rust build environment is available:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p classmesh-lab
```

The current GitHub Actions runner problem is tracked separately; do not interpret a job that never starts steps as a source/test failure.

## References

The architecture is informed by public designs and APIs from Microsoft Desktop Duplication / Windows Graphics Capture, Sunshine/Moonlight, RustDesk, Veyon, WebRTC/RTP, QUIC and classroom deployment research. ClassMesh is not a fork of those projects. Third-party media components, when used, stay behind replaceable ClassMesh backends.
