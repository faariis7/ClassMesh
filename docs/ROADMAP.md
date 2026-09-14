# ClassMesh Implementation Roadmap

This roadmap favors measured, recoverable primitives before UI breadth. It is deliberately Windows-first and treats Session 0 isolation, GPU lifecycle, transport backpressure and observability as architecture—not cleanup work.

## Phase 0 — Architecture and repository foundation

Deliverables:

- architecture/security baselines and ADRs;
- protocol/versioning rules;
- performance targets;
- Rust workspace and CI skeleton;
- structured metrics conventions;
- bounded queue/recovery/adaptation primitives;
- initial media packet framing and Protobuf schemas.

Exit criteria:

- key decisions are documented;
- core policy/state-machine logic is unit-testable without Windows hardware;
- no unresolved architecture question blocks the Windows runtime prototype.

## Phase 1 — Windows runtime and Session Worker foundation

Build the process model before relying on capture:

1. ClassMesh Windows Service lifecycle skeleton;
2. WTS session tracking;
3. launch a per-user Worker using the active interactive session;
4. authenticated, ACL-restricted local IPC;
5. logon/logoff/lock/unlock/fast-user-switch state machine;
6. worker crash/restart supervision with bounded backoff.

The service must never blindly attempt interactive desktop capture from Session 0.

Exit criteria:

- cold boot before login leaves the service healthy;
- interactive login launches exactly the intended worker;
- lock/unlock suspends/resumes media state without marking the device offline;
- fast user switching replaces the worker cleanly;
- a worker crash does not require restarting the machine service.

## Phase 2 — Local GPU capture proof

Build a Windows command-line Worker prototype that:

1. creates a D3D11 device on the correct adapter;
2. enumerates a stable display descriptor;
3. captures the selected display with DXGI Desktop Duplication;
4. keeps the frame GPU-side;
5. measures capture FPS and acquisition latency;
6. rebuilds stale resources after access-loss, device reset, display topology/size/rotation change and monitor hot-plug;
7. handles secure-desktop/session transitions as suspension/recovery rather than permanent failure.

Windows.Graphics.Capture is an alternate backend behind the same abstraction, not a reason to duplicate the pipeline.

Exit criteria:

- 1080p60 capture capability on suitable hardware without CPU bitmap conversion;
- explicit recovery tests for access lost and display change;
- lock/unlock and monitor-topology recovery;
- 30-minute capture soak test with bounded memory/queue growth.

## Phase 3 — GPU processing + H.264 hardware encode

Implement:

- GPU BGRA -> NV12 conversion/scaling;
- Media Foundation H.264 encoder enumeration;
- hardware/async capability inspection;
- low-latency Media Foundation and codec controls where supported;
- first-run bounded encoder benchmark rather than trusting the hardware label;
- capability cache keyed by adapter/driver/encoder/profile;
- encoded-frame timestamps/keyframe metadata;
- local diagnostic H.264 sink.

Exit criteria:

- measured 1080p30 presentation capability on supported hardware;
- p50/p95 encode latency is recorded;
- backend and fallback reason are visible in diagnostics;
- no CPU pixel-copy hot path in normal presentation;
- encoder reset/reconfigure does not kill the Worker.

## Phase 4 — One-to-one live video prototype

Build TeacherSender and StudentReceiver CLI programs.

Implement:

- ClassMesh media datagram framing;
- UDP unicast baseline and QUIC Datagram comparison;
- strictly bounded sender/receiver queues;
- packet sequence/loss/reordering tracking;
- bounded retransmit cache;
- frame reassembly and small jitter/recovery window;
- NACK while a frame is still useful;
- stale incomplete-frame drop + coalesced keyframe recovery;
- hardware H.264 decode and GPU render;
- end-to-end stream metrics.

Exit criteria:

- 1080p30 teacher motion video on a second Windows PC;
- <100 ms engineering target on a healthy wired LAN;
- no growing delay over a 30-minute run;
- 1–5% injected loss degrades/recover video without dropping the control/device session.

## Phase 5 — Reliable control plane, identity and enrollment

Implement QUIC/TLS control sessions with Protobuf messages for:

- enrollment and asymmetric device/teacher identity;
- mutual authentication/authorization;
- heartbeat/status;
- protocol/capability negotiation;
- stream negotiation and feedback;
- input events;
- keyframe/NACK coordination;
- session-worker diagnostics.

Model control and media health independently.

Exit criteria:

- media can restart while control stays authenticated;
- reconnect resumes without reinstalling/re-pairing;
- protocol incompatibilities fail explicitly;
- authorization is checked per privileged command;
- key rotation/revocation paths are defined before production enrollment.

## Phase 6 — Interactive remote control

Implement:

- low-latency mouse/keyboard path;
- input release/cleanup on disconnect;
- focused stream quality adaptation;
- clipboard protocol skeleton;
- secure-desktop behavior and explicit diagnostics.

Exit criteria:

- control remains responsive while video is degraded;
- stuck-key/stuck-button cleanup is verified;
- media transport failure does not imply device offline.

## Phase 7 — Wired classroom teacher presentation

Implement the scale-efficient managed-LAN path:

- one main H.264 encoder/rendition for the classroom;
- RTP-style ClassMesh packetization;
- multicast capability probe;
- multicast join/leave and IGMP-friendly behavior;
- established authenticated media protection for group traffic;
- per-client feedback over the control plane;
- outlier fallback to unicast;
- coordinated/rate-limited keyframe requests.

Scale tests: 2, 5, 10, 20+ receivers where lab hardware allows.

Exit criteria:

- sender does not N-times encode the main stream;
- teacher outbound media bitrate remains roughly constant as healthy multicast receiver count grows;
- one weak receiver never stalls healthy receivers.

## Phase 8 — Wi-Fi fan-out benchmark and optional local SFU

Conventional IP multicast is not the default Wi-Fi path.

Compare empirically:

1. direct real-time unicast from the teacher using one encoded rendition;
2. QUIC/WebRTC-style per-student transport;
3. optional self-hosted local SFU/relay (LiveKit is a candidate, not a mandatory dependency);
4. optional simulcast/renditions only if measurements justify the encoder/GPU cost.

Collect:

- teacher uplink bitrate;
- AP airtime/load where measurable;
- end-to-end latency and jitter;
- CPU/GPU usage;
- recovery behavior with weak clients;
- operational complexity/offline deployment requirements.

Exit criteria:

- a selected Wi-Fi fan-out strategy is backed by measured 5/10/20/30-client evidence where hardware is available;
- the chosen strategy does not force healthy clients to inherit the worst client’s quality.

## Phase 9 — Monitoring grid

Build a separate low-cost pipeline:

- low resolution;
- 2–5 FPS default;
- thumbnail-size-aware scaling;
- dirty/change-region awareness;
- priority scheduling so many thumbnails do not starve control traffic;
- promotion of a selected student into the interactive pipeline.

Exit criteria:

- expected classroom grid remains responsive at target device counts;
- full-resolution streams are not generated just to render tiny tiles.

## Phase 10 — Adaptive networking and quality controller

Inputs:

- RTT/loss/jitter/reordering;
- throughput estimate;
- decoder/render delay;
- queue age/depth/drop rate;
- wired/wireless topology;
- multicast viability;
- receiver capability/health.

Actions:

- bitrate/FPS/resolution changes;
- transport/cohort membership;
- keyframe/recovery decisions;
- optional rendition/SFU selection.

Requirements:

- hysteresis to avoid quality/protocol flapping;
- per-client/cohort adaptation instead of one global threshold;
- latest-frame-wins remains enforced during congestion.

## Phase 11 — Teacher UI and classroom UX

Only after the engine gates pass, build production UI:

- classroom/device list;
- monitoring grid;
- focus/remote-control view;
- presentation start/stop;
- stream-health indicators;
- detailed per-device diagnostics;
- controlled protocol/quality overrides for troubleshooting.

The UI consumes engine APIs; it does not own capture/network logic.

## Phase 12 — Administrative features

Add incrementally:

- lock/unlock policy actions;
- message;
- open URL/app using typed/validated commands;
- shutdown/restart;
- file transfer;
- clipboard;
- classroom configuration;
- roles/permissions.

Do not add an unrestricted remote-shell primitive as a convenience feature.

## Phase 13 — Installer, update and recovery

Implement:

- Windows installer;
- service/worker deployment;
- firewall rules;
- signed update metadata and package hashes;
- staged updates;
- rollback;
- compatibility checks;
- capability re-probe after relevant driver/GPU changes.

## Phase 14 — Hardening and 1.0 gate

Required matrix includes:

- Intel/NVIDIA/AMD where available;
- wired and Wi-Fi;
- multicast enabled/disabled;
- 1/5/10/20/30+ receivers;
- 1%, 3%, 5% synthetic loss plus bursts;
- jitter/reordering/bandwidth throttling;
- reconnect storms and weak receivers;
- boot/logon/lock/unlock/logoff/fast-user-switch;
- monitor hot-plug, primary-monitor change, resolution/orientation/DPI changes;
- sleep/wake;
- GPU/encoder/decoder reset;
- VDI/virtualized environments where available;
- protected-content diagnostics;
- long soak tests;
- protocol fuzzing and privilege-boundary review.

**ClassMesh 1.0 is gated by measured stability and recovery, not by feature count.**
