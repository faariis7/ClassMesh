# ClassMesh Architecture Baseline v0.1

## 1. Mission

ClassMesh is a Windows-first classroom streaming and remote-management system. It must remain responsive and recoverable while supporting three fundamentally different media workloads: monitoring many student screens, interactively controlling one student, and broadcasting the teacher screen to an entire class.

The architecture is optimized first for a managed LAN but must degrade gracefully on Wi-Fi and on networks where multicast is unavailable.

## 2. Architectural principles

1. **Separate control and media planes.** Commands, identity, heartbeat and file transfer never depend on video delivery.
2. **GPU-native media path.** Avoid CPU readback and image-object conversion in the presentation hot path.
3. **Encode once, distribute many.** Main teacher presentation must not create one encoder per student.
4. **Latest frame wins.** Bounded queues drop stale media rather than accumulate latency.
5. **Per-client failure isolation.** One weak receiver cannot stall the classroom.
6. **Measured adaptation.** Protocol and quality decisions use topology/capability probes and runtime metrics, not a fixed student-count threshold.
7. **Recovery by design.** Capture, device, decoder and network state machines explicitly support restart and rejoin.
8. **Windows-first before cross-platform.** Cross-platform receivers are a future extension, not an MVP constraint.

## 3. Process model

### Student device

```text
Windows Service (non-interactive)
  - identity / enrollment
  - discovery
  - update orchestration
  - control-session supervision
  - policy
        |
        | authenticated local IPC
        v
Interactive Agent (user session)
  - capture / decode / render
  - input application
  - presentation receiver
  - monitoring producer
```

The split is intentional. Desktop capture must occur in the interactive user session rather than relying on Session 0. This also prevents capture lifecycle issues from terminating the service.

### Teacher device

```text
Teacher UI
   |
   v
ClassMesh Core
   |-- classroom/session model
   |-- device state
   |-- control plane
   |-- monitoring coordinator
   `-- presentation coordinator
             |
             v
        Video Engine
```

## 4. Media workloads

### 4.1 Monitoring grid

Goal: show many students cheaply.

- Typical target: 2-5 FPS per student.
- Resolution selected for tile size, not desktop native resolution.
- Dirty/change awareness can reduce unnecessary work.
- JPEG/WebP-like still-image techniques may be acceptable here because latency and motion quality requirements differ from presentation.
- When the teacher focuses one device, switch that device to the interactive pipeline.

### 4.2 Interactive remote control

Goal: low input-to-display latency for one selected student.

- H.264 hardware path.
- UDP/QUIC-datagram or WebRTC-style unicast media.
- Independent reliable input/control channel.
- Adaptive bitrate/resolution/FPS.
- Video degradation must not affect command delivery.

### 4.3 Teacher presentation

Goal: teacher can play motion video and present to the whole class without N-times encoding or growing latency.

```text
DXGI/WGC capture
     |
     v
D3D11 GPU texture
     |
     v
GPU scaling / color conversion (BGRA -> NV12)
     |
     v
ONE hardware H.264 encoder
     |
     v
Encoded frame distributor
     |
     +--> encrypted UDP multicast (preferred on suitable managed LAN)
     |
     +--> UDP/QUIC datagram unicast for outliers
     |
     `--> reliable low-rate emergency fallback
```

A receiver that cannot use multicast leaves the multicast cohort and receives a separate lower-rate unicast stream if needed. It does not force the whole class to downgrade.

## 5. Windows capture

### Primary backend: DXGI Desktop Duplication

Reasons:

- frames are delivered in GPU memory;
- desktop dirty/move metadata is available;
- designed for desktop collaboration/remote-access use cases;
- full-display capture works without a CPU bitmap path.

### Secondary backend: Windows.Graphics.Capture

Use as an alternate capture backend where it provides better lifecycle behavior or window-level capture. Keep it behind the same capture abstraction.

### Capture abstraction

```rust
pub trait CaptureBackend {
    fn start(&mut self, target: CaptureTarget) -> Result<()>;
    fn acquire(&mut self) -> Result<CapturedGpuFrame>;
    fn recover(&mut self, reason: CaptureFailure) -> Result<()>;
}
```

### Recovery events

Treat the following as recoverable state transitions when possible:

- access lost;
- display mode/size change;
- device removed/reset;
- lock/unlock or user-session transition;
- monitor hot-plug.

The capture component releases stale duplication/device resources, recreates the pipeline, and resumes without tearing down the control session.

## 6. GPU processing

Presentation hot path must avoid:

```text
GPU -> CPU staging -> Bitmap -> scale -> encoder
```

Preferred path:

```text
D3D11 texture -> GPU video processor -> NV12 texture -> hardware encoder
```

CPU readback is acceptable only for diagnostics, screenshots, compatibility fallback or low-rate monitoring paths.

## 7. Codec strategy

### v1 codec: H.264/AVC

Why first:

- broad Windows hardware decode support;
- mature hardware encoders across Intel/NVIDIA/AMD systems;
- low-latency modes are widely available;
- simpler compatibility target than HEVC/AV1.

Initial target profile:

- 1080p30 presentation;
- low-latency mode;
- B-frames disabled initially;
- GOP / IDR cadence around 1-2 seconds, dynamically requestable;
- 3-5 Mbps nominal classroom stream, adaptive within configured bounds.

### Encoder backend

Prefer Windows Media Foundation / Direct3D-aware hardware transforms for the Windows-first baseline. Keep the interface abstract so other implementations can be added later.

```rust
pub trait VideoEncoder {
    fn configure(&mut self, cfg: EncoderConfig) -> Result<()>;
    fn encode(&mut self, frame: GpuVideoFrame) -> Result<Option<EncodedFrame>>;
    fn request_keyframe(&mut self);
    fn reconfigure(&mut self, cfg: EncoderConfig) -> Result<()>;
}
```

Future codecs: HEVC, AV1.

## 8. Queueing and frame pacing

No unbounded channel is allowed in the media pipeline.

Suggested starting limits:

- capture -> process: 2 frames;
- process -> encode: 2 frames;
- encoded frame distribution: 2-3 frames per stream;
- per-client retransmission cache: time-bounded, not an unlimited queue.

When a producer outruns a consumer, discard stale media. Never preserve old video at the cost of increasing live latency.

## 9. Control plane

Baseline: QUIC with TLS 1.3.

Uses separate logical streams for:

- authentication/enrollment;
- heartbeat/status;
- classroom commands;
- input events;
- file transfer;
- stream negotiation/feedback.

QUIC is chosen because reliable logical streams do not head-of-line block each other at the application level and encryption is built in.

Protocol messages use Protobuf and carry explicit protocol versions/capabilities.

## 10. Video transport

There is no single transport for every topology.

### Mode A: managed-LAN presentation

- RTP-style packetization of H.264 NAL units.
- UDP multicast when multicast capability tests succeed and network policy allows it.
- encrypted payload using a per-session group key distributed over the authenticated control plane.
- sequence, frame, packet index and timestamp metadata.

### Mode B: unicast real-time

For Wi-Fi, outlier receivers and interactive control:

- UDP / QUIC datagrams initially;
- feedback for packet loss, RTT, jitter and decoder health;
- NACK/keyframe recovery;
- WebRTC is an optional later transport backend where its congestion control/NAT traversal benefits justify the integration cost.

### Mode C: restrictive fallback

Use a reliable ClassMesh transport at reduced FPS/bitrate. Do **not** make HLS or WebSocket/MJPEG the native desktop baseline; HLS adds avoidable latency and WebSocket is mainly useful for a future browser client.

## 11. Why WebRTC is not the only baseline transport

WebRTC is valuable for Wi-Fi, cross-subnet and future cross-platform/browser scenarios because it provides mature congestion control, SRTP, NACK/FEC mechanisms and NAT traversal. However:

- native libwebrtc integration is large and operationally complex;
- it does not solve LAN multicast teacher-to-class distribution;
- a local classroom should not require an SFU to work.

Therefore ClassMesh keeps a transport abstraction and can add WebRTC without coupling the core engine to it.

## 12. Why no mandatory LiveKit/SRS/SFU

An SFU can be useful for remote campuses, internet-connected classrooms or browser receivers, but making one mandatory would add a central service and potential bottleneck to a product whose primary scenario is a local classroom. It remains an optional future deployment mode.

## 13. Network adaptation

Inputs:

- wired vs wireless interface;
- multicast probe result;
- RTT;
- packet loss;
- jitter;
- receiver decode FPS;
- receiver dropped frames;
- queue delay;
- estimated throughput.

Outputs:

- bitrate;
- resolution;
- FPS;
- transport membership;
- keyframe/recovery decisions.

Do not switch the whole class because one client crosses an arbitrary 5% packet-loss threshold. Adapt per receiver and preserve a healthy multicast cohort where possible.

## 14. Keyframe coordination

Multiple receivers may request recovery simultaneously. Requests are coalesced by a keyframe coordinator so a class of receivers produces one IDR request, rate-limited by a minimum interval.

## 15. Loss recovery

Progressive implementation:

1. sequence/frame tracking;
2. drop incomplete stale frames;
3. NACK while a frame remains inside the recovery deadline;
4. coalesced IDR request when recovery is no longer useful;
5. optional FEC for Wi-Fi multicast/unicast after measurement demonstrates value.

## 16. Rendering

Receiver path:

```text
packets -> reassembly/jitter -> hardware H.264 decode -> D3D11 texture -> GPU presentation
```

Avoid converting every decoded frame into WPF/WinUI bitmaps.

## 17. Discovery

Support multiple discovery sources behind one abstraction:

- mDNS/Zeroconf for zero-config LANs;
- ClassMesh UDP discovery where mDNS is filtered;
- static/admin-managed directory;
- future Active Directory/LDAP integration.

Discovery packets contain identity/capability metadata only; no secrets.

## 18. Observability

Every media session records structured metrics:

- capture FPS and capture latency;
- GPU process latency;
- encode FPS/latency and hardware backend;
- bitrate;
- queue depth/drop count;
- packet loss/reordering;
- RTT/jitter;
- decoder FPS/latency;
- render latency;
- stream recovery events.

Debugging must answer *where* latency was introduced rather than merely report that video is slow.

## 19. Initial performance targets

- presentation: 1920x1080 @ 30 FPS;
- healthy LAN end-to-end latency target: <100 ms;
- no monotonically growing latency during a 30-minute run;
- hardware encode/decode when supported;
- main multicast teacher outbound target: under ~8 Mbps for the encoded video stream;
- one weak client does not interrupt healthy clients.

These are engineering targets, not guaranteed product specifications, and will be adjusted from measured hardware results.

## 20. Deferred items

Not MVP requirements:

- macOS/Linux agents;
- browser receiver;
- cloud relay/SFU;
- HEVC/AV1;
- audio;
- recording;
- simulcast/SVC;
- central enterprise directory.
