# ClassMesh Protocol Baseline v0.4

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
- negotiated text clipboard messages;
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

### Teacher Presentation lifecycle contract (v0.3)

Protocol minor 0.3 adds the transport-neutral Phase 7 presentation lifecycle contract. `CAPABILITY_TEACHER_PRESENTATION` is negotiated independently from media transport capabilities.

- `PresentationStart` binds a non-zero presentation ID to a non-zero media stream ID that fits the existing 32-bit media packet header.
- `PresentationStop` names the presentation to stop.
- `PresentationStatus` reports lifecycle state without selecting a transport; status IDs/state are validated and its free-form diagnostic is bounded to 1 KiB.
- Start/stop are correlated privileged commands with non-zero `request_id` and require `Permission::StartPresentation` on the authenticated peer.
- v0.2 sessions cannot dispatch the new lifecycle commands.
- The lifecycle contract does **not** choose UDP multicast, UDP unicast, QUIC Datagram, WebRTC, or any fallback. Media negotiation remains in `StreamOffer` and the Phase 4 UDP-vs-QUIC-Datagram decision remains physically gated.
- This schema/authorization slice does not claim a production presentation runtime exists; runtime ownership, cleanup, shared encoded output, multicast security and scale validation remain later Phase 7 slices.

### Group-media key contract (v0.4)

Protocol minor 0.4 adds the sensitive control-wire contract used by the Phase 7E SFrame coordinator. It does not enable production multicast by itself.

- `CAPABILITY_SFRAME_GROUP_MEDIA` is negotiated explicitly in addition to `CAPABILITY_TEACHER_PRESENTATION`; peers that only understand the v0.3 lifecycle contract must not receive a group key.
- `PresentationKeyGrant` binds a non-zero presentation ID, a non-zero 32-bit-compatible stream ID, a non-zero security epoch, and exactly 32 bytes of SFrame base-key material.
- `PresentationKeyAck` acknowledges only the exact presentation/stream/epoch installed by the receiver.
- The receiving PrincipalId is deliberately absent from the payload. Runtime delivery must bind the grant to the exact authenticated control peer/session selected by the authorization-gated coordinator rather than trusting a serialized recipient identity.
- Key grant/ack use a non-zero `ControlEnvelope.request_id`. The Phase 7E binding layer records exactly one pending ACK correlation per issued grant and matches request ID + presentation ID + stream ID + epoch.
- Sender-side key delivery binds to the exact TLS-authenticated StudentDevice and control session. A server-side enrolled peer can bind directly from the enrolled handshake result; for the current Teacher→Student Service client topology, the Teacher resolves the TLS-verified Student Service server certificate through the live authorization store and requires that stable Principal to be a `StudentDevice`. Both paths require negotiated v0.4, `TeacherPresentation`, and `SframeGroupMedia`. Immediately before issuing the grant, the authenticated credential is re-resolved and `ReceivePresentation` is re-authorized so a credential revoked after Hello cannot receive a key.
- ACK acceptance reuses the authenticated-session guard, so exact session/version/monotonic sequence and live credential state are checked again, then `ReceivePresentation` is re-authorized before the coordinator marks the receiver installed.
- A mismatched correlated ACK may consume its otherwise valid in-session sequence but never installs the key; the pending record remains usable for a later correctly correlated higher sequence.
- Raw key material must not be logged or durably persisted. Sensitive grant envelopes zeroize their wire key buffer on drop, in addition to the generic transport-buffer zeroization and receiver-side decoded-key zeroization.
- The binding primitive is deliberately not wired into the current Student Service runtime because that runtime accepts Teacher clients; production grant delivery requires the Teacher-side runtime where the authenticated peer is the StudentDevice receiver.

### Phase 6E clipboard skeleton

Clipboard support is deliberately narrow and opt-in:

- capability negotiation uses `CAPABILITY_CLIPBOARD_TEXT`; an unknown or unnegotiated capability never grants permission;
- the wire contract is text-only UTF-8 using `ClipboardReadRequest`, `ClipboardReadResponse` and `ClipboardWrite`;
- clipboard text is bounded to **64 KiB of UTF-8 bytes**, well below the 256 KiB control-envelope ceiling;
- clipboard reads are request/response operations and require a non-zero `request_id` for correlation;
- read and write are independent privileges: `Permission::ReadClipboard` and `Permission::WriteClipboard`;
- oversized clipboard writes are rejected before the privileged application sequence is consumed;
- empty clipboard text is valid and represents an explicit clear;
- binary clipboard objects, files, shell commands and arbitrary serialized objects are not part of this skeleton.

The schema/security skeleton does not by itself advertise production clipboard execution. A runtime must advertise the negotiated capability only when its interactive-session clipboard implementation exists and must preserve these authorization and size checks.

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

Interactive stream establishment is explicit rather than inferred. An authenticated peer with `ViewInteractive` may send `StreamOffer`; the Service validates the bounded H.264 profile, stream kind, explicit transport, transport-parameter size, and—critically—that the requested transport capability was negotiated in the established Hello. The Service answers with `StreamAnswer` using the same request correlation. A rejected offer is an ordinary preflight result and does not by itself imply that the authenticated control session is offline.

Until production media dispatch/sender ownership exists, a structurally valid offer still receives `accepted=false` with the stable diagnostic `control.stream.runtime_not_ready`. This prevents negotiation code from claiming a stream exists before the Worker has actually created its media runtime. `supported_transports` is derived only from transports already negotiated for that control session; it never invents UDP, QUIC Datagram, or WebRTC support from capture/codec capabilities.

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
