# ClassMesh Security Baseline

## Goals

ClassMesh is an administrative classroom tool. Security is part of the transport and identity architecture, not an optional deployment mode.

## Trust model

- Each managed device has a stable ClassMesh device identity.
- Teacher/control authority is explicitly enrolled, not inferred from IP address or hostname.
- Discovery is untrusted metadata until authenticated through the control plane.
- A flat school LAN is treated as hostile enough for sniffing, spoofing and unauthorized join attempts.

## Device identity

Planned device identity:

- a cryptographically random stable principal/device ID stored locally;
- generated private key stored using platform-appropriate protected storage;
- corresponding device certificate/credential;
- stable device ID is independent from mutable hostname/IP **and** independent from the active credential/public-key fingerprint, so credential rotation does not rename the device;
- private key material is never sent in discovery or application messages.

Enrollment establishes which teacher/classroom authority can control an agent.

## Control plane

- QUIC reliable streams with TLS 1.3.
- Mutual authentication after enrollment. The Phase 5B transport test/bootstrap configuration authenticates the server only; it is not the production enrolled mode and must not be treated as authorization.
- Explicit ALPN plus application protocol version and capability negotiation.
- Authorization checked per command, not only at connection creation.
- Replay-sensitive administrative commands carry control-session, sequence and request identifiers.
- QUIC/TLS 0-RTT application data is disabled for the initial control plane. Administrative actions are processed only after the authenticated 1-RTT handshake completes.

## Teacher presentation multicast

Plain multicast video is not acceptable.

Phase 7E adopts RFC 9605 SFrame behind `classmesh-security::group_media` (ADR-0008). The baseline cipher suite is AES-GCM-256/SHA-512 through the pinned `sframe` 2.0.0 implementation rather than a ClassMesh-defined cipher/nonce construction.

Security rules:

1. teacher and student establish an authenticated control session;
2. each presentation security epoch uses a fresh random 32-byte base key and a non-zero epoch/KID;
3. key material is delivered individually only over the authenticated control channel;
4. SFrame authenticates encrypted presentation frames plus bounded external ClassMesh binding metadata;
5. receiver replay state is bounded and recorded only after successful frame authentication;
6. a sender must never restart counters with the same epoch/key pair; rebuilding sender state requires a fresh epoch/key;
7. keys rotate for every new presentation and before more media after any active-epoch receiver membership change;
8. no Principal enters the group-key receiver set or receives a key grant without a live `ReceivePresentation` authorization check;
9. receiver/key state is bounded to 64 principals, and a slow receiver never creates a classroom-wide key-install barrier;
10. protocol v0.4 key delivery requires explicit `SframeGroupMedia` capability negotiation in addition to `TeacherPresentation`;
11. the wire grant never carries a recipient PrincipalId: the recipient is the exact authenticated control peer/session selected by the coordinator, preventing a payload-supplied identity from redirecting a group key;
12. serialized key bytes are sensitive transient material: the generic control framing/QUIC path zeroizes its process-owned intermediate encoded payloads and raw send/receive frame buffers; generated wire values and buffers must not be logged;
13. receiver-side decoded `PresentationKeyGrant.key_material` is imported through a dedicated installer that zeroizes the protobuf buffer on success and failure, derives bounded SFrame receiver/replay state, and retains no raw base-key bytes in the control-layer installed-key object;
14. sender-side delivery is bound to the TLS-authenticated StudentDevice + exact control session and v0.4 group-media contract. Server-side enrolled sessions bind directly from the authenticated peer; in the current Teacher→Student Service topology, the Teacher client resolves the verified Student Service certificate back to the stable StudentDevice PrincipalId through the live authorization store and requires an exact caller-selected receiver match. No payload-supplied recipient identity is trusted, and the authenticated credential + `ReceivePresentation` permission are rechecked immediately before grant issuance;
15. each issued key has one bounded pending ACK record keyed by authenticated PrincipalId + control session + request ID + presentation + stream + epoch; ACK acceptance rechecks the live credential and `ReceivePresentation` permission before installation;
16. sensitive sender envelopes are one-shot: sending consumes the grant wrapper and zeroizes the decoded protobuf key bytes before returning on either success or transport failure;
17. receiver ACK construction is derived from the same already-installed grant envelope and preserves its exact control session, protocol version, request ID, presentation, stream and epoch without re-exposing raw key material;
18. the Student Service receiver accepts a key grant only when the v0.4 group-media contract was negotiated, the authenticated Teacher credential still has `StartPresentation`, and the grant matches the exact active Teacher principal + control session + presentation + stream owner tuple;
19. within one live Student Service presentation binding, replacement key epochs must increase strictly; stale/equal epochs fail closed, and every pre-install rejection explicitly zeroizes decoded protobuf key bytes;
20. the Student Service is not used as the grant sender because its authenticated peer is the Teacher. Teacher-side delivery binds the selected StudentDevice to the exact Quinn connection stable ID + control-session ID + negotiated version; the Quinn ID is transport ownership only and never PrincipalId;
21. Teacher delivery state is capped at 64 receivers with exactly one pending ACK per receiver. The TLS credential is re-resolved to the exact expected stable PrincipalId before grant and ACK handling, and `ReceivePresentation` remains live-authorized;
22. pending ACK state is installed before the asynchronous one-shot grant write. An ambiguous or failed transport send therefore remains fail-closed and cannot silently trigger a second key issuance; disconnect/removal drops only that receiver state;
23. Teacher ACK acceptance reuses the caller-owned authenticated-session guard and its global monotonic sequence. A structurally valid but mis-correlated ACK may consume sequence state but cannot mark the key installed and does not clear the pending record; only an exact authorized ACK does.
24. Phase 7F production frames use the canonical fixed-width `CMG1` SFrame binding for presentation/stream/epoch/frame/timestamp/keyframe metadata. The security layer exposes an opaque sealed-frame type that carries that exact non-secret binding, so multicast transport integration can derive packet metadata from the authenticated binding and require ciphertext rather than arbitrary encoded video bytes.
25. The Phase 7F multicast sender is fail-closed behind successful local multicast-probe evidence, binds and explicitly selects the configured IPv4 egress interface, keeps multicast TTL at one hop, and accepts only sealed frames matching its exact presentation/stream/epoch. It intentionally keeps no group retransmission cache: one receiver's loss report must never cause NACK-driven retransmission to every healthy multicast receiver.
26. The Phase 7F multicast receiver is likewise probe-gated and joins only the configured administratively scoped group/interface. The expected Teacher source IP is a media filtering hint only and is never identity or authorization. Wrong-source/version/stream packets, FEC and multicast retransmit markers are media-local drops. Packet count is rejected before reassembly when it could exceed the SFrame sealed-frame ceiling, and completed ciphertext is checked again before exposure. Reassembled bytes remain untrusted ciphertext until SFrame authenticates the installed presentation/stream/epoch plus frame metadata; NACK output is bounded to the control-plane 64-index limit.
26a. Presentation multicast offer parameters contain only a versioned administratively scoped group and port. They never carry a claimed Teacher source address or Student interface. Runtime must derive the expected Teacher source from the authenticated QUIC peer and select the Student interface from local multicast probe/configuration evidence. The offer requires negotiated `TeacherPresentation`, `SframeGroupMedia`, and `UdpMulticast` capabilities.
26b. Local `UdpMulticast` capability evidence uses a bounded self-looped probe on one explicitly selected IPv4 interface. The probe uses a fresh random token and exact protocol/tag/stream correlation, enables multicast loopback deliberately, keeps TTL at one hop, and requires clean leave. Success is host-local runtime evidence only and never substitutes for the separate two-PC Phase 7D network viability gate.
26c. Service capability advertisement is fail-closed: `UdpMulticast` is added to Hello only when an explicitly configured local IPv4 interface passes the bounded runtime probe. Missing configuration, unavailable multicast, or probe errors leave control and transport-neutral Teacher Presentation available but omit `UdpMulticast`; probe evidence never upgrades identity, authorization, or physical-network qualification.
27. Phase 7F presentation NACK/keyframe feedback is per-receiver authenticated control data, never multicast-group recovery traffic. The Teacher first revalidates the receiver against its exact registered StudentDevice PrincipalId, Quinn connection, control-session ID and negotiated version, then consumes the caller-owned global replay sequence under live `ReceivePresentation` authorization and requires the exact presentation stream. A wrong connection fails before sequence consumption; a structurally valid wrong-stream or correlated event may consume its sequence but cannot influence recovery or be replayed later.
28. Worker-owned group-media decryption uses a dedicated zeroizing IPC v0.6 key-install path over the existing per-generation, ACL-restricted, exact-PID/session-validated named pipe. Sensitive install frames are rejected by the generic decoder. The Worker returns only non-secret install status bound to its PID/session and the exact control-session/request/presentation/stream/epoch; the Service must not send the Teacher key ACK until that exact result is `Installed`.
29. Worker key installation retains only derived SFrame receiver/replay state plus non-secret binding metadata. Within one exact control-session/presentation/stream binding, epochs must increase strictly. Any binding change requires explicit lifecycle clear before install, preventing a delayed old-session key message from implicitly replacing the active presentation. A stream mismatch is rejected before SFrame replay state is touched.
30. The interactive Worker consumes post-handshake IPC through the zeroizing sensitive decoder and a bounded 128-entry event queue with backpressure. Sensitive install events are never cloned; channel teardown drops their zeroizing storage. The Worker emits `Installed` only after derived SFrame state construction succeeds and emits `Rejected` otherwise. Key cleanup is a typed exact-bound message over control-session/request/presentation/stream/epoch; the Worker ignores non-matching clears, preventing delayed cleanup from erasing a newer installed presentation.
31. Student Service is an orchestrator, not a second group-media decryptor. Sensitive grants cross a bounded Service dispatch queue exactly once and are written to the exact PID/session-bound Worker pipe. Upstream `PresentationKeyAck` is emitted only after an exact Worker result matches PID, Windows session, control session, request, presentation, stream and epoch and that same Worker remains alive. Miscorrelated/stale results cannot authorize ACK. A non-secret exact-bound lease schedules cleanup on presentation stop or control-session teardown; delayed cleanup cannot clear a newer binding.
32. Worker presentation loss feedback is non-secret but exact-bound before it can leave the local IPC boundary: Worker PID/session, control-session ID, key-grant request ID, presentation ID and security epoch accompany the bounded feedback payload. The embedded stream ID must be non-zero. Service runtime must recheck those fields against the exact live Worker/key binding before constructing authenticated network feedback.
33. Feedback runtime publication is bounded and receiver-isolated. Only the current PID/session/generation-validated Worker can enter the 64-entry in-process bus; each control session independently rechecks its exact key-grant request/presentation/stream/epoch lease and active presentation ownership before send. The Teacher credential is re-resolved to the same PrincipalId and `StartPresentation` is live-authorized immediately before feedback emission. A dedicated receive-half pump owns framed QUIC reads to completion; feedback backpressure may drop media feedback for a lagging session but never cancels partial control reads or blocks other sessions.
34. Service→Worker presentation multicast startup is a fixed-width, non-secret IPC v0.6 contract bound to a non-zero control session, request, presentation and stream plus a validated bounded H.264 profile. The multicast group must be administratively scoped IPv4 (239/8), the port non-zero, the Worker interface an explicit local unicast IPv4 address, and the expected Teacher source a non-multicast/non-broadcast IPv4 address. The Worker start result is separately fixed-width and exact-bound to current Worker PID/session plus the same control-session/request/presentation/stream tuple; only `Started` may authorize an upstream accepted StreamAnswer. A pipe write, stale result, wrong Worker generation, or `Rejected` result must fail closed. Neither message can carry hostnames, arbitrary serialized endpoints, key bytes, or identity claims; runtime construction remains responsible for sourcing the interface from local probe/config and the Teacher source from the authenticated QUIC peer.\n35. Worker multicast presentation ownership is subordinate to the exact installed group-media key binding. A start without an installed matching control-session/presentation/stream key is rejected; a key install that would conflict with an active receiver is rejected; and an exact key clear drops both receiver and decode/render runtime before a later presentation may install a different binding. `Started` means the Media Foundation/D3D11 presentation runtime initialized and bind+join succeeded; partial startup, stale retry state, a closed presentation window, or receiver failure tears down the paired runtime rather than leaving half-live media state. The receive thread uses a bounded 64-outcome queue, suppresses empty timeout ticks, and drops local media outcomes under backpressure rather than blocking authenticated Worker IPC.\n36. Multicast ciphertext is not decoder input. The production Worker constructs an H.264 access unit only after `GroupMediaReceiver` validates the installed epoch key, canonical frame associated data and replay window. Only that authenticated access unit is submitted to the reusable Media Foundation decoder/presenter. Authentication, binding, epoch or replay failure yields no decoder input. SFrame authentication/binding/replay failure remains a media-local drop and cannot reset decoder state or emit control feedback. Only decoder keyframe-wait/recovery may emit at most one pending authenticated keyframe request until a valid authenticated keyframe arrives. Control-session availability is unchanged.

Phase 7E control/security implementation is complete through PR #172. Phase 7F now includes the protected-frame boundary (#173), sender transport (#174), receive-side socket/reassembly boundary (#175), authenticated per-receiver feedback contract (#177), zeroizing Service→Worker key IPC contract (#176), exact Worker install-result contract (#178), Worker-owned derived SFrame key state (#179), Worker sensitive-key runtime integration (#180), Worker-confirmed Service forwarding/ACK orchestration (#181), split control-channel ownership (#182), exact Worker feedback IPC (#183), and authenticated feedback runtime pump (#184). The reusable Worker decode/render runtime is now paired with exact key-bound multicast receive: only SFrame-authenticated access units reach Media Foundation, startup is fail-closed unless both receive and decode/render are ready, unauthenticated media cannot drive recovery feedback, and decoder recovery uses the authenticated feedback path. Service StreamOffer→Worker dispatch is now fail-closed: `StartPresentation` authorization, exact principal/control-session/presentation/stream ownership and the exact Worker-confirmed installed key binding are required before dispatch; Teacher source comes only from the authenticated QUIC peer and Student interface only from local probe/config. A bounded cancel/commit gate prevents a pre-dispatch timeout from causing a later unacknowledged Worker start, and only an exact current Worker `Started` result may produce `StreamAnswer.accepted=true`. Matching key clear and Worker restart/exit invalidate pending starts; stale/miscorrelated results are ignored. Physical multicast viability remains the 7D two-PC gate, and scale qualification remains 7H.

## Unicast media

- Protect unicast media independently of LAN trust.
- QUIC Datagram media inherits QUIC connection protection.
- If RTP/UDP is used directly, protect payloads with an established secure media construction rather than unauthenticated custom encryption.
- WebRTC transport, if added, uses its standard DTLS-SRTP model.

## Local IPC

Windows Service <-> interactive Agent IPC must:

- use a local-only transport;
- authenticate the peer/process context;
- apply restrictive ACLs;
- validate every message;
- never trust user-session input merely because it is local.

## Input and command safety

Administrative commands are typed/versioned messages. Avoid arbitrary shell execution as a general-purpose protocol primitive.

Commands such as opening URLs/applications, shutdown/restart, file delivery and input injection require explicit validation and policy checks.

## Updates

Production update design must include:

- signed release metadata;
- package digest verification;
- rollback capability;
- version compatibility policy;
- no execution of downloaded content before verification.

## Logging and privacy

Logs should contain session/device IDs and diagnostics, but should avoid:

- private keys;
- session encryption keys;
- raw passwords/tokens;
- clipboard/file contents by default;
- full screen-frame dumps unless an explicit debug mode requests them.

## Security work required before 1.0

- threat model;
- enrollment/authentication review;
- multicast key-management review;
- protocol fuzzing;
- malformed-packet tests;
- privilege-boundary review for Windows Service <-> Agent;
- update-chain review;
- dependency/license audit.
