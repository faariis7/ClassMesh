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
12. serialized key bytes are sensitive transient material: the generic control framing/QUIC path zeroizes its process-owned intermediate encoded payloads and raw send/receive frame buffers; payload-specific decoded key storage must also be zeroized immediately after the later key-install handler consumes it; generated wire values and buffers must not be logged.

The crypto/coordinator/wire-contract slices alone do not enable production multicast. Service session binding, authenticated key delivery/ack handling, production sender/receiver wiring and physical scale qualification remain separate Phase 7 gates.

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
