# ClassMesh

ClassMesh is a Windows-first classroom streaming, monitoring, and remote-management platform designed for low latency, high device density, and graceful operation on both wired and Wi-Fi networks.

> Status: **Architecture / prototyping**. The first goal is not UI polish; it is proving a stable 1080p30 GPU-native streaming pipeline between two Windows machines, then scaling it to a classroom.

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

1. **Monitoring** — low-rate, low-resolution thumbnails, optimized for many students.
2. **Interactive remote control** — responsive unicast stream plus independent input/control.
3. **Teacher presentation** — one hardware encode distributed to many receivers, preferring multicast on suitable managed LANs.

Initial platform direction:

- **Core / video / networking:** Rust
- **Windows graphics:** D3D11 + DXGI Desktop Duplication, with Windows Graphics Capture as a secondary backend
- **Codec:** H.264 first; hardware Media Foundation path preferred
- **Control plane:** QUIC/TLS 1.3
- **Video plane:** low-latency UDP/RTP-style transport; multicast for classroom presentation where appropriate
- **Windows UI:** separate native UI layer; final framework decision is intentionally deferred until the engine prototype is stable
- **Wire messages:** Protocol Buffers for control messages

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

## Non-negotiable engineering rules

- No `Bitmap`/JPEG round-trip in the teacher-presentation hot path.
- Capture and decoded frames stay GPU-side whenever practical.
- Bounded queues only. **Latest frame wins**; stale frames are dropped rather than accumulated.
- Video health and device/control health are separate state machines.
- A slow receiver must never stall the class.
- One classroom presentation is encoded once for the main stream, not once per student.
- No hard-coded protocol switch based only on student count; topology and measured network health drive the decision.
- Recovery is a first-class feature, not an afterthought.

## First proof target

Before building the full classroom UI, ClassMesh must demonstrate:

- 1920×1080 at 30 FPS
- hardware H.264 encode and decode when supported
- <100 ms target end-to-end latency on a healthy LAN
- no latency growth over a 30-minute stream
- smooth playback while the teacher plays motion video
- automatic capture/codec recovery without terminating the control session

## Planned repository layout

```text
ClassMesh/
├─ crates/
│  ├─ classmesh-core/
│  ├─ classmesh-protocol/
│  ├─ classmesh-network/
│  ├─ classmesh-video/
│  ├─ classmesh-capture-win/
│  ├─ classmesh-codec-win/
│  ├─ classmesh-agent/
│  └─ classmesh-service/
├─ apps/
│  ├─ teacher/
│  └─ student/
├─ proto/
├─ docs/
│  ├─ ARCHITECTURE.md
│  ├─ ROADMAP.md
│  ├─ SECURITY.md
│  └─ decisions/
└─ tools/
```

## References

The architecture is informed by public designs and APIs from Microsoft Desktop Duplication / Windows Graphics Capture, Sunshine/Moonlight, RustDesk, Veyon, WebRTC/RTP, and QUIC. ClassMesh is not a fork of those projects.
