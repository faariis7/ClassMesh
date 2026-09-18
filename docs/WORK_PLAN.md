# ClassMesh Living Work Plan

Last updated: 2026-09-18

This is the active execution plan for ClassMesh. It is updated as implementation evidence changes so roadmap intent, code status, and physical validation are not confused.

## Current execution state

| Track | State | Current gate |
|---|---|---|
| Phase 4 — one-to-one live video | **Implementation complete; physical qualification pending** | Issue #3 stays open until two physical Windows PCs pass the documented 1080p30, latency, impairment and soak criteria |
| Phase 5A — control protocol foundation | **Complete — PR #33** | Generated Protobuf, control envelope, version/capability negotiation, heartbeat/liveness |
| Phase 5B — QUIC/TLS runtime | **In progress** | Reliable bounded control stream, TLS 1.3, ALPN, timeouts, reconnect policy and loopback integration tests |
| Phase 5C — identity + enrollment | Next | Persistent stable principal IDs, credential storage, approval flow, mTLS, revocation and key rotation |
| Phase 5D — authorization + session negotiation | Planned | Per-command authorization, replay controls, capability/session negotiation over the real transport |
| Phase 5E — hardening | Planned | malformed input, reconnect storms, fuzzing, protocol compatibility and security tests |

Tracking issue: #32.

## Rules while Phase 4 hardware is unavailable

Phase 5 may proceed in parallel because control-plane correctness does not depend on selecting the final unicast media transport.

The following decision remains deliberately open until Phase 4 physical evidence exists:

- default one-to-one media transport: UDP vs QUIC Datagram.

Do not close Issue #3 or claim Phase 4 acceptance from hosted CI.

## Phase 5 transport/security baseline

- QUIC is the reliable control transport.
- TLS 1.3 protects the QUIC connection.
- Enrolled peers will use mutual authentication.
- ALPN will identify the ClassMesh control protocol independently of media transport.
- Administrative application data will not use QUIC 0-RTT until ClassMesh has an explicit replay-safe profile. Initial production behavior is 1-RTT only.
- Stable device/principal identity is independent from mutable hostname/IP and independent from the currently active credential, so certificates/keys can rotate without changing the device ID.
- Authorization is checked for each privileged command, not only when the connection is established.
- Control health and media health remain independent state machines.
- Control messages are schema-driven Protocol Buffers inside a bounded application envelope.
- Application sequence/request IDs complement TLS/QUIC protection with duplicate/replay suppression and request correlation.

## Initial heartbeat policy

Current code defaults are deliberately conservative and testable:

- send interval: 2 seconds;
- peer becomes suspect after 6 seconds without an accepted heartbeat;
- peer becomes offline after 10 seconds.

These are application-liveness defaults, not a replacement for QUIC idle timeout or transport keepalive. They can be tuned after classroom-scale evidence without changing the wire protocol.

## Dependency/research policy

Before introducing or materially changing transport, cryptography, identity, codec, Windows API or update-chain dependencies:

1. check current upstream documentation and release state;
2. prefer standards and maintained upstream crates over custom protocol/crypto;
3. confirm project MSRV and Windows support;
4. add deterministic tests before making the component production-critical;
5. record any architecture decision that would be expensive to reverse.

Current control-plane research baseline:

- RFC 9000 — QUIC transport;
- RFC 9001 — QUIC + TLS security and 0-RTT replay considerations;
- RFC 8446 — TLS 1.3;
- Quinn 0.11.x / rustls 0.23.x for Rust QUIC/TLS;
- Prost 0.14.x for Protocol Buffers.

## Planned PR sequence

1. **5A Control foundation — complete in PR #33** — generated control Protobuf, envelope/versioning, heartbeat/liveness and capability negotiation.
2. **5B QUIC/TLS transport — active** — Quinn reliable streams with ALPN, 256 KiB bounded framing, connect/I/O/idle timeouts, bounded reconnect and loopback handshake tests.
3. **5C Identity store + enrollment** — stable IDs, local credential persistence, bootstrap approval, post-enrollment mTLS, rotation/revocation.
4. **5D Authorization/session integration** — connect authenticated principal to command permissions and stream/session negotiation.
5. **5E Hardening** — malformed messages, replay/duplicate cases, reconnect storms, fuzz targets and diagnostics.

Each merged PR updates this file and docs/IMPLEMENTATION_STATUS.md.
