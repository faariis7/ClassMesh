# Architecture Research Synthesis

This note records which ideas from the initial external proposals are adopted, modified, deferred or rejected for ClassMesh.

## Adopt now

### Separate control and media planes

Strongly adopted. Administrative commands, input, heartbeat and file transfer must stay reliable even when video is congested.

### Hardware encode/decode

Strongly adopted. H.264 hardware acceleration is the first production codec target. Software encoding is compatibility fallback, not the normal classroom path.

### Multicast for suitable managed LAN presentation

Adopted with qualification. Teacher presentation benefits greatly from one encoded stream distributed by the network. Multicast viability must be probed and should be paired with IGMP-aware network configuration where available.

### Wi-Fi-aware behavior

Adopted. Do not assume multicast on Wi-Fi behaves like wired multicast. Wireless clients may use unicast and more aggressive adaptation.

### mDNS / managed directory discovery

Adopted as pluggable discovery backends rather than one mandatory mechanism.

### Detailed per-stage metrics

Strongly adopted. Capture, process, encode, queue, network, decode and render latency are first-class diagnostics.

### Adaptive bitrate and resolution scaling

Adopted. Monitoring tiles, focused remote-control sessions and presentation streams have different quality targets.

### Capture recovery as a first-class state machine

Strongly adopted after reviewing failure reports from Veyon/UltraVNC/RustDesk/OBS-class projects. A capture session must be considered disposable. Access loss, resolution/rotation changes, GPU reset/removal, output replacement, monitor hot-plug and interactive-session changes must trigger rediscovery and reconstruction instead of terminating the Agent.

The implementation should model capture states explicitly, e.g. `Starting -> Capturing -> Degraded -> Reinitializing -> Capturing`, with bounded retry/backoff and structured reason codes.

### Multi-monitor identity and topology change handling

Strongly adopted. A stream binds to a stable ClassMesh display identity, not merely a stale DXGI output pointer or index. Output topology is rediscovered after display-change events, and the UI must make the selected monitor unambiguous.

### Hardware capability probing and transparent fallback

Strongly adopted. Hardware acceleration must be tested at runtime, not inferred solely from GPU model. VDI, GPU partitioning, Remote Desktop sessions and older drivers can expose hardware that still cannot create the required encoder/decoder path. Capability probes and failure reasons are part of startup diagnostics.

### Protected-content awareness

Adopted. Windows may intentionally prevent capture of protected/DRM content. ClassMesh must distinguish likely protected-content behavior from generic capture failure where possible and surface a clear diagnostic rather than silently looping or reporting the device offline.

### Slow-client isolation and concurrency limits

Strongly adopted. One slow or reconnecting student cannot block the distributor, encoder or control plane. Queues are per-client/cohort and bounded. We will also define explicit safety limits for concurrent focused streams and fallback unicast streams so overload degrades predictably instead of exhausting the teacher host.

### GPU-native low-latency rendering

Adopted. The receiver path should decode into GPU surfaces and render with a modern D3D11 swap-chain/composition path rather than convert every frame into CPU image objects. Flip-model presentation is the target on Windows.

## Adopt with changes

### WebRTC as the universal secondary protocol

WebRTC is a strong option for unicast Wi-Fi, cross-subnet and future browser scenarios, but it is not mandatory in the first prototype. Native libwebrtc integration is substantial and multicast still needs another path. We first prove our Windows GPU pipeline and native real-time transport, then benchmark whether WebRTC should be added as a transport backend.

### Local SFU for teacher fan-out

The new research correctly highlights that one WebRTC P2P upload per student does not scale well. We therefore keep a **local SFU/fan-out service as a conditional architecture option**, especially for Wi-Fi, cross-subnet or browser/WebRTC deployments where multicast is unsuitable.

It is not mandatory for the first managed-LAN version. For a healthy wired classroom, encrypted multicast remains simpler and more bandwidth-efficient. The intended decision tree is topology-aware:

- managed wired LAN with healthy multicast -> multicast cohort;
- multicast-unfriendly Wi-Fi or routed network -> benchmark unicast/WebRTC and optional local SFU;
- isolated weak clients -> individual unicast fallback without downgrading the entire class.

If an SFU is introduced, it should forward already-encoded media where possible rather than decode/re-encode it.

### Fixed protocol fallback chain

A strict global `Multicast -> WebRTC -> WebSocket` chain is replaced by **per-client/cohort adaptation**. A single weak student must not switch the entire class away from a healthy multicast stream.

### Fixed packet-loss / RTT thresholds

Initial thresholds may exist as defaults, but they require hysteresis and multiple signals. Five percent loss by itself is not enough to decide the topology or protocol.

### Delta/dirty-region encoding

Very useful for monitoring and desktop-change detection. For full-motion H.264 presentation, temporal video compression already handles inter-frame redundancy; dirty regions should not complicate the first presentation encoder unless measurements show a clear gain.

### DXGI versus Windows Graphics Capture

DXGI Desktop Duplication remains the first implementation because it exposes the display-oriented behavior and metadata we need. Windows Graphics Capture remains a pluggable alternative and may be preferable for specific capture targets or failure cases. We do not assume one backend will handle every Windows/driver/topology edge case.

## Defer

### LiveKit / SRS / mandatory SFU

Useful for internet/cross-campus/browser deployments, but unnecessary for the primary local classroom. Making an SFU mandatory would add operational complexity and a new failure point.

### FFmpeg as the first Windows encoder layer

FFmpeg remains a valuable diagnostic/fallback option, but the Windows-first prototype prefers Media Foundation and Direct3D-aware hardware transforms to reduce deployment/licensing complexity and keep GPU surfaces native.

### Cross-platform clients

The architecture should not prevent them, but Windows compatibility and classroom reliability are higher priority than Flutter/macOS/Linux/Web clients for v1.

### VNC/RFB as the presentation transport

VNC-style pixel/rectangle update systems remain useful references for classroom workflows and static desktop optimization, but they are not the presentation media baseline because full-motion content requires temporal video compression and low-latency media transport.

## Reject as native baseline

### HLS fallback for interactive screen streaming

HLS is designed around buffered media distribution and conflicts with the sub-100-ms LAN goal. It may be useful for non-interactive viewing in a future web mode, but not as the native emergency transport.

### MJPEG/JPEG teacher presentation

JPEG-style full-frame streaming is not acceptable as the normal presentation path. It is reserved for monitoring, diagnostics or emergency low-rate fallback.

### Hard-coded mode based on student count alone

`>15 students => multicast` is too simplistic. Interface type, AP/switch multicast behavior, packet loss, receiver health and admin policy are more important than count alone.

### One WebRTC P2P session per student as the classroom broadcast architecture

Acceptable for a few peers during experiments, but not the scalable teacher-to-class design. If WebRTC becomes the main Wi-Fi transport, fan-out must be measured and an SFU/relay design considered before large classroom rollout.

## Additional validation scenarios added from open-source failure reports

ClassMesh test plans should explicitly include:

- display resolution changes while streaming;
- display rotation changes;
- monitor hot-plug and monitor removal/re-add;
- primary-display changes and multi-monitor selection;
- Windows lock/unlock and user session transitions;
- GPU driver reset/device removal simulation where practical;
- hardware-encoder unavailable/initialization-failure path;
- virtualized/VDI test environment when available;
- protected-content/black-frame diagnostic behavior;
- 30+ minute motion-video soak tests;
- slow receiver/reconnect storms without affecting healthy receivers;
- wired multicast baseline versus Wi-Fi unicast/SFU candidate paths.

## Primary reference families

- Microsoft DXGI Desktop Duplication / Windows Graphics Capture / D3D11 / Media Foundation
- Sunshine/Moonlight for low-latency GPU video and network behavior
- RustDesk for remote-control/service decomposition and capability fallback ideas
- Veyon/UltraVNC for classroom workflows, deployment patterns and historical failure modes
- OBS-class capture applications for DXGI lifecycle and display-topology edge cases
- RTP/H.264, QUIC and WebRTC standards for transport design

## Source-quality note

The external research notes supplied during planning contain useful issue-derived observations, but individual issue/review claims are treated as research leads rather than immutable requirements until reproduced or independently verified. ClassMesh architectural decisions should be driven by standards/vendor documentation plus our own benchmark and failure-injection results.
