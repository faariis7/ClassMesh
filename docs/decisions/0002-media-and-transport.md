# ADR-0002: Hybrid media transport, not one protocol for every classroom

- Status: Accepted for prototype
- Date: 2026-09-15

## Context

Teacher presentation and remote control have different scaling properties. Multicast is extremely efficient on a suitable managed wired LAN, while Wi-Fi and some switches/APs handle multicast poorly. WebRTC provides excellent unicast congestion control and recovery but does not replace multicast for one-to-many LAN distribution.

A proposed architecture used a strict fallback chain of Multicast -> WebRTC -> WebSocket/HLS based on fixed packet-loss/RTT thresholds.

## Decision

Use a transport abstraction with topology-aware policy rather than a single global fallback chain.

### Control plane

Use QUIC/TLS for reliable authenticated control and feedback.

### Presentation media

Prefer encrypted UDP multicast when a capability probe and network policy indicate it is suitable.

Receivers that cannot remain in the multicast cohort use a unicast real-time transport independently.

### Interactive/unicast media

Start with UDP/QUIC-datagram transport and explicit feedback. Keep WebRTC as an optional backend to evaluate for Wi-Fi/cross-subnet/browser scenarios.

### Restrictive fallback

Use a reduced-rate reliable native ClassMesh transport. Do not use HLS as the desktop fallback because its buffering model works against the low-latency target. WebSocket remains a possible browser-client transport, not the native baseline.

## Why reject a fixed `loss > 5% => switch everybody` rule?

- one receiver may have poor Wi-Fi while the rest of the class is healthy;
- transient loss can cause protocol flapping;
- multicast quality depends on topology/AP/switch behavior, not student count alone;
- the appropriate response may be bitrate/FPS reduction rather than a transport switch.

The policy engine therefore uses hysteresis and per-client state.

## Why not require LiveKit/SRS/SFU?

A central media server is useful for internet/cross-campus scenarios but unnecessary for the primary local-classroom mode and can introduce a new operational dependency. It can be added as an optional future deployment architecture.

## Consequences

- more deliberate transport abstraction work early;
- better failure isolation;
- main class stream can retain constant-ish sender bandwidth under multicast;
- Wi-Fi clients can be treated differently from wired clients;
- WebRTC integration can be justified by measurements instead of adopted by default due to feature breadth.
