# ClassMesh Protocol Baseline v0.1

This document describes the protocol intent currently represented by `classmesh-protocol`, `classmesh-network` and the `.proto` schemas. It is **not** a frozen wire-compatibility promise yet.

## 1. Separation of planes

ClassMesh never treats video delivery as the device connection itself.

### Control plane

Planned transport: QUIC/TLS 1.3 with mutually authenticated enrolled identities.

Carries:

- authentication/enrollment;
- heartbeat and device status;
- capability negotiation;
- stream offer/answer/reconfiguration;
- network/decoder feedback;
- input events;
- NACK/keyframe requests;
- file transfer and future administrative messages.

Messages are schema-driven with Protocol Buffers. See `proto/classmesh_control.proto`.

### Media plane

Carries encoded real-time media. Initial native transport work is UDP/datagram based with explicit packet framing. Future backends may include QUIC Datagram and WebRTC without changing the capture/codec engine.

Teacher-presentation fan-out is topology dependent:

- managed wired LAN: encrypted multicast cohort when viable;
- wired/wireless outliers: unicast;
- large Wi-Fi/routed/browser deployment: optional SFU/WebRTC cohort after benchmark evidence.

## 2. Native media datagram

The v0.1 fixed ClassMesh media header is 40 bytes. Payload budget is currently **1200 bytes** to stay conservative below common Internet/LAN MTUs and leave room for IP/UDP/security encapsulation.

All multi-byte integer fields are encoded in network byte order (big endian).

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `CMV1` |
| 4 | 1 | protocol major |
| 5 | 1 | protocol minor |
| 6 | 2 | flags |
| 8 | 4 | stream ID |
| 12 | 8 | frame ID |
| 20 | 4 | packet sequence |
| 24 | 2 | packet index within frame |
| 26 | 2 | packet count for frame |
| 28 | 8 | media timestamp in microseconds |
| 36 | 2 | payload length |
| 38 | 2 | reserved, zero in v0.1 |

Current flags:

- keyframe;
- frame start;
- frame end;
- retransmit;
- FEC (reserved for later implementation).

A datagram whose declared payload length, packet index/count or maximum payload is invalid is rejected before frame assembly.

## 3. Frame packetization and assembly

Encoded H.264 frames are split into bounded datagrams. The current prototype packetizer is codec-agnostic at this layer; H.264-specific RTP/NAL optimizations can be introduced once the hardware encoder output format is proven.

Receiver behavior:

1. accept reordering within a small active-frame window;
2. track packet sequence gaps independently from frame completeness;
3. request NACK only while the frame remains useful;
4. drop stale incomplete frames instead of accumulating latency;
5. request a new keyframe after useful retransmission time has expired;
6. never mark the device offline just because a video frame was lost.

## 4. Bounded recovery caches

Retransmission data is both count- and time-bounded. ClassMesh does not turn UDP media into an unlimited reliable queue.

The rule is:

> Recover a recent frame if recovery can still help live playback; otherwise abandon old media and return to the newest decodable frame/keyframe.

This protects latency during congestion and receiver stalls.

## 5. Keyframe requests

Many receivers can experience the same loss burst. ClassMesh coalesces receiver requests through a keyframe coordinator and enforces a minimum IDR interval. Ten receivers asking simultaneously must not cause ten large keyframes.

## 6. Adaptation signals

Current policy primitives accept:

- RTT;
- packet loss;
- jitter;
- decoder FPS;
- queue delay;
- estimated throughput;
- wired/wireless topology;
- multicast viability.

Production policy will add hysteresis and historical windows. A single sample crossing a threshold must not cause protocol flapping.

## 7. Monitoring vs presentation

The media protocol does not force every workload to use the same codec profile.

- Monitoring: low resolution, 2–5 FPS, change-aware; still-image techniques may be appropriate.
- Interactive: adaptive H.264 real-time unicast.
- Teacher presentation: H.264 hardware video path, encode once per rendition and fan out efficiently.

Dirty-rectangle optimization is valuable for monitoring. It is not a prerequisite for full-motion H.264 presentation because the video codec already performs temporal compression.

## 8. Service/Worker local IPC

The machine service and interactive user-session Worker communicate over a local-only authenticated IPC endpoint. The exact Windows transport is expected to be Named Pipes unless measurement or platform constraints justify another local transport.

The framing prototype uses:

- magic `CMIP`;
- protocol major/minor;
- typed message ID;
- bounded payload length (currently maximum 1 MiB).

The parser is incremental for stream-oriented pipe reads and rejects oversized input before unbounded allocation.

Security requirements before production:

- restrictive pipe ACL tied to expected service/worker principals;
- peer process/session validation;
- nonce/challenge handshake bound to the launched Worker;
- no trust solely because a peer is local;
- protocol/message validation after authentication as well.

See `proto/classmesh_ipc.proto`.

## 9. Media security

Security framing is deliberately **not invented ad hoc** in the prototype packet header.

- QUIC Datagram media uses QUIC protection when selected.
- WebRTC uses standard DTLS-SRTP.
- Direct RTP/UDP/multicast must use an established authenticated secure-media construction/group-key design before production.
- Multicast session keys are distributed only over an authenticated control session and rotate between presentation sessions/membership changes according to the final reviewed scheme.

Until that work is complete, native UDP packetization is a transport prototype, not a production-secure media channel.

## 10. Compatibility/versioning

Protocol compatibility currently requires equal major versions. Minor versions can evolve through capability negotiation. Before 1.0, every public wire field needs documented backward/forward compatibility rules and malformed-input tests/fuzzing.
