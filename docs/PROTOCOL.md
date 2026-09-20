# ClassMesh Protocol Baseline v0.2

This document describes the protocol intent currently represented by `classmesh-protocol`, `classmesh-network` and the `.proto` schemas. It is **not** a frozen wire-compatibility promise yet.

## 1. Separation of planes

ClassMesh never treats video delivery as the device connection itself.

### Control plane

Transport: reliable QUIC streams protected by TLS 1.3, with mutually authenticated enrolled identities once enrollment is established.

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

### QUIC control transport runtime

Phase 5B carries control envelopes on a long-lived reliable bidirectional QUIC stream.

Current transport bounds:

- ALPN: `classmesh-control/1`;
- frame prefix: 4-byte unsigned big-endian payload length;
- maximum encoded Protobuf payload: 256 KiB;
- malformed zero-length/oversized frames are rejected before payload allocation;
- connect and control I/O operations have explicit timeouts;
- QUIC idle timeout and keepalive are bounded independently from application heartbeat;
- reconnect attempts use bounded exponential backoff;
- application 0-RTT remains disabled.

The current server TLS helper is explicitly **pre-enrollment**: it authenticates the server certificate but does not yet require a client certificate. Phase 5C replaces this bootstrap mode with enrolled mutual authentication.

### Enrollment wire contract (v0.2)

Protocol minor 0.2 introduces the first enrollment messages. The pre-enrollment connection must already trust the intended ClassMesh authority/server certificate through explicit configuration or pinning; LAN discovery is never a trust anchor.

The flow is intentionally based on standard PKCS#10 rather than a custom key-proof format:

1. the enrolling peer creates a protected local key and a DER PKCS#10 CSR signed by that key;
2. `EnrollmentRequest` carries the stable `PrincipalId`, requested role, CSR, a fresh 32-byte client nonce and a display label;
3. the authority returns an opaque `enrollment_id` plus `csr_sha256` so approval/status is bound to the exact CSR;
4. the client polls with `EnrollmentStatusRequest` while teacher/admin approval is pending;
5. an approved `EnrollmentResult` carries a leaf-first DER certificate chain and SHA-256 fingerprint of the leaf certificate.

The client nonce is for deduplication/correlation, not authentication. The credential fingerprint never defines or replaces the stable `PrincipalId`. Rejected, revoked and expired states are explicit. Authority-side issuance must match the approved stable PrincipalId and exact CSR SHA-256 and use a bounded, non-expired validity window. Phase 5C3 now verifies PKCS#10 proof-of-possession, issues bounded end-entity X.509 credentials, supports protected Windows CNG signing without private-key export, and uses enrolled mutual TLS with verified certificate→stable PrincipalId resolution and live credential re-check.

### Reliable control envelope

Phase 5 uses a `ControlEnvelope` around control messages. The envelope carries a control-session ID, a monotonically increasing application sequence, negotiated protocol version, optional request ID, and a typed Protobuf payload. The sequence/request fields are application semantics for duplicate/replay suppression and correlation; they do not replace QUIC/TLS integrity.

A `Hello` / `HelloAck` exchange explicitly negotiates the protocol minor version and shared capabilities. A major-version mismatch is rejected rather than silently downgraded. On enrolled sessions, the claimed `Hello.device_id` must match the stable PrincipalId resolved from the verified mTLS credential; application identity claims never override TLS-authenticated identity.

After establishment, privileged control messages must use the exact established `control_session_id` and a strictly increasing application sequence on the ordered QUIC control stream. Permission checks re-validate the current credential/principal state for each privileged command; revoked, expired, future-issued, or disabled identities therefore stop authorizing even on an already-established transport.

Application heartbeat tracks device/control liveness independently from `MediaHealth`. The initial policy is a 2-second heartbeat interval, suspect after 6 seconds, and offline after 10 seconds. Peer monotonic timestamps are diagnostic only and are never directly compared across machines.

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

Phase 6 focused interactive adaptation uses authenticated `ReceiverFeedback` on the established control session to drive a hysteretic profile decision. A profile-only `StreamReconfigure` sets `transport` to `MEDIA_TRANSPORT_UNSPECIFIED` and leaves `transport_parameters` empty, which means the receiver keeps the stream's current media transport. This deliberately does not select the one-to-one UDP-vs-QUIC-Datagram default while Phase 4 Issue #3 remains physically unqualified.

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

Protocol compatibility requires equal major versions. Within one major version, the negotiated minor version is the lower of the two advertised minor versions, and features are enabled only through negotiated shared capabilities. Protobuf field numbers are append-only: existing field numbers are not repurposed, removed fields are reserved when the schema stabilizes, and unknown fields/unsupported capabilities must not imply authorization.

The QUIC control ALPN is versioned independently from media transport. Initial production control data uses 1-RTT only; 0-RTT application data is disabled until ClassMesh defines a replay-safe application profile.

Before 1.0, every public wire field needs documented backward/forward compatibility rules plus malformed-input tests/fuzzing.
