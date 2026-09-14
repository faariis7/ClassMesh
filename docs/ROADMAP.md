# ClassMesh Implementation Roadmap

This roadmap favors measurement and stable primitives before UI breadth.

## Phase 0 — Architecture and repository foundation

Deliverables:

- architecture baseline;
- security model;
- protocol/versioning rules;
- performance targets;
- Rust workspace and CI skeleton;
- structured logging/metrics conventions.

Exit criteria:

- key design decisions documented as ADRs;
- no unresolved question blocks the first capture/encode prototype.

## Phase 1 — Local GPU capture proof

Build a Windows command-line prototype that:

1. creates a D3D11 device;
2. captures a selected display with DXGI Desktop Duplication;
3. keeps the frame GPU-side;
4. measures capture FPS and acquisition latency;
5. survives display resize / access-loss by rebuilding the capture backend.

Add Windows.Graphics.Capture only after the primary DXGI path is measurable.

Exit criteria:

- 1080p60 capture capability on suitable hardware without CPU bitmap conversion;
- explicit recovery test for access lost / display change;
- 30-minute capture soak test.

## Phase 2 — GPU processing + H.264 hardware encode

Implement:

- GPU BGRA -> NV12 conversion/scaling;
- Media Foundation H.264 encoder discovery;
- hardware encoder preference and capability reporting;
- low-latency encoder configuration;
- encoded-frame timestamps and keyframe metadata;
- local `.h264` or diagnostic sink for validation only.

Exit criteria:

- 1080p30 encode with stable frame pacing;
- hardware backend identified in logs;
- no CPU pixel-copy hot path;
- motion-video source remains smooth locally.

## Phase 3 — One-to-one live video prototype

Build TeacherSender and StudentReceiver CLI programs.

Implement:

- packet framing;
- UDP/QUIC-datagram unicast transport;
- bounded queues;
- frame reassembly;
- hardware H.264 decode;
- GPU rendering;
- stream metrics.

Exit criteria:

- 1080p30 teacher motion video on second Windows PC;
- <100 ms target latency on healthy wired LAN;
- no growing delay over 30 minutes;
- packet loss causes frame degradation/recovery, not process failure.

## Phase 4 — Reliable control plane

Implement QUIC/TLS control sessions with Protobuf messages for:

- enrollment/session negotiation;
- heartbeat;
- capabilities;
- video configuration;
- network feedback;
- input events.

Model control and media health independently.

Exit criteria:

- media can be restarted while control session remains alive;
- reconnect resumes without reinstall/pairing;
- protocol version/capability negotiation covered by tests.

## Phase 5 — Remote control

Implement:

- mouse/keyboard input channel;
- focus-mode stream quality adaptation;
- clipboard protocol skeleton;
- input release/cleanup on disconnect.

Exit criteria:

- interactive control remains responsive while media is degraded;
- stuck-key/stuck-button cleanup verified.

## Phase 6 — Classroom teacher presentation

Implement multicast-capable presentation mode:

- one encoder for main class stream;
- RTP-style H.264 packetization;
- multicast capability probe;
- IGMP-friendly multicast join/leave;
- encrypted group payload;
- per-client feedback over control plane;
- outlier fallback to unicast;
- coordinated/rate-limited keyframe requests.

Scale tests:

- 2 receivers;
- 5 receivers;
- 10 receivers;
- 20+ receivers where hardware/network lab allows.

Exit criteria:

- sender does not N-times encode the main stream;
- multicast class stream has near-constant sender media bandwidth as receiver count grows;
- one bad receiver does not interrupt others.

## Phase 7 — Monitoring grid

Build a separate monitoring pipeline:

- low resolution;
- 2-5 FPS default;
- thumbnail-size aware scaling;
- change/dirty-region awareness;
- priority scheduling so dozens of thumbnails do not starve control traffic.

Exit criteria:

- target classroom grid remains responsive at expected device counts;
- opening one student promotes that device to the interactive pipeline without disrupting grid monitoring.

## Phase 8 — Adaptive networking

Implement network estimator and policy engine.

Metrics:

- RTT;
- loss;
- jitter;
- throughput estimate;
- decoder/render delay;
- queue depth;
- wired/wireless topology;
- multicast viability.

Actions:

- bitrate changes;
- FPS changes;
- resolution changes;
- multicast cohort membership;
- recovery/keyframe policy.

Add WebRTC as an optional transport backend only if test results justify it for Wi-Fi/cross-subnet scenarios.

Exit criteria:

- simulated congestion results in graceful quality reduction rather than disconnect;
- recovery returns quality upward with hysteresis, avoiding protocol flapping.

## Phase 9 — Student service and enrollment

Implement production process split:

- ClassMesh Windows Service;
- interactive user-session Agent;
- authenticated local IPC;
- device identity/certificates;
- discovery;
- enrollment;
- policy storage.

Exit criteria:

- reboot/autostart works;
- logon/logoff/lock/unlock transitions are handled;
- capture is never attempted blindly from Session 0.

## Phase 10 — Teacher UI and classroom UX

Only now build the production UI:

- classroom/device list;
- monitoring grid;
- focus/remote control view;
- teacher presentation start/stop;
- stream health indicators;
- per-device troubleshooting information;
- explicit protocol/quality override for diagnostics.

The UI must consume engine APIs; it must not own media pipeline logic.

## Phase 11 — Administrative features

Add incrementally:

- lock/unlock policy actions;
- message;
- open URL/app;
- shutdown/restart;
- file transfer;
- clipboard;
- classroom configuration;
- role/permission policy.

## Phase 12 — Installer, update and recovery

Implement:

- Windows installer;
- service installation;
- firewall rules;
- signed update metadata;
- staged updates;
- rollback;
- compatibility checks.

## Phase 13 — Hardening and 1.0 gate

Required test matrix:

- Intel / NVIDIA / AMD where available;
- wired and Wi-Fi;
- multicast enabled/disabled;
- 1/5/10/20+ receivers;
- 1%, 3%, 5% synthetic loss;
- jitter and reordering;
- bandwidth throttling;
- lock/unlock/logoff;
- monitor hot-plug;
- resolution/DPI changes;
- sleep/wake;
- encoder/decoder reset;
- long soak tests.

1.0 is gated by measured stability, not feature count.
