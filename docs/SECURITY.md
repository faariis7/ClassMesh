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

Design:

1. teacher and student establish an authenticated control session;
2. teacher creates a random presentation session key;
3. key is delivered individually over the authenticated control channel;
4. multicast video payloads are encrypted/authenticated with an AEAD construction;
5. keys rotate for new presentation sessions and can rotate when membership changes.

Exact nonce/key-rotation format must be specified before production use and covered by cryptographic review/tests. Do not invent a custom cipher.

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
