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

## Adopt with changes

### WebRTC as the universal secondary protocol

WebRTC is a strong option for unicast Wi-Fi, cross-subnet and future browser scenarios, but it is not mandatory in the first prototype. Native libwebrtc integration is substantial and multicast still needs another path. We first prove our Windows GPU pipeline and native real-time transport, then benchmark whether WebRTC should be added as a transport backend.

### Fixed protocol fallback chain

A strict global `Multicast -> WebRTC -> WebSocket` chain is replaced by **per-client/cohort adaptation**. A single weak student must not switch the entire class away from a healthy multicast stream.

### Fixed packet-loss / RTT thresholds

Initial thresholds may exist as defaults, but they require hysteresis and multiple signals. Five percent loss by itself is not enough to decide the topology or protocol.

### Delta/dirty-region encoding

Very useful for monitoring and desktop-change detection. For full-motion H.264 presentation, temporal video compression already handles inter-frame redundancy; dirty regions should not complicate the first presentation encoder unless measurements show a clear gain.

## Defer

### LiveKit / SRS / mandatory SFU

Useful for internet/cross-campus/browser deployments, but unnecessary for the primary local classroom. Making an SFU mandatory would add operational complexity and a new failure point.

### FFmpeg as the first Windows encoder layer

FFmpeg remains a valuable diagnostic/fallback option, but the Windows-first prototype prefers Media Foundation and Direct3D-aware hardware transforms to reduce deployment/licensing complexity and keep GPU surfaces native.

### Cross-platform clients

The architecture should not prevent them, but Windows compatibility and classroom reliability are higher priority than Flutter/macOS/Linux/Web clients for v1.

## Reject as native baseline

### HLS fallback for interactive screen streaming

HLS is designed around buffered media distribution and conflicts with the sub-100-ms LAN goal. It may be useful for non-interactive viewing in a future web mode, but not as the native emergency transport.

### MJPEG/JPEG teacher presentation

JPEG-style full-frame streaming is not acceptable as the normal presentation path. It is reserved for monitoring, diagnostics or emergency low-rate fallback.

### Hard-coded mode based on student count alone

`>15 students => multicast` is too simplistic. Interface type, AP/switch multicast behavior, packet loss, receiver health and admin policy are more important than count alone.

## Primary reference families

- Microsoft DXGI Desktop Duplication / Windows Graphics Capture / D3D11 / Media Foundation
- Sunshine/Moonlight for low-latency GPU video and network behavior
- RustDesk for remote-control/service decomposition
- Veyon for classroom workflows, device management and educational deployment patterns
- RTP/H.264, QUIC and WebRTC standards for transport design
