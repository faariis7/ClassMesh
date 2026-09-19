# ClassMesh Living Work Plan

Last updated: 2026-09-19

This is the active execution plan for ClassMesh. It is updated as implementation evidence changes so roadmap intent, code status, hosted-CI evidence, and physical validation are not confused.

## Current execution state

| Track | State | Current gate |
|---|---|---|
| Phase 4 — one-to-one live video | **Implementation complete; physical qualification pending** | Issue #3 stays open until two physical Windows PCs pass the documented 1080p30, latency, impairment and soak criteria |
| Phase 5A — control protocol foundation | **Complete — PR #33 merged** | Generated Protobuf, version/capability negotiation and heartbeat/liveness are on `main` |
| Phase 5B — QUIC/TLS runtime | **Complete — PR #36 merged** | Current-baseline CI #232 passed on Synology Portable + Windows; merge `794fd45a5a20b6e4c623b7ecbbcfda5264e52ec0` |
| Phase 5C1 — identity/rotation model | **Complete — PR #39 merged** | Stable PrincipalId, multi-credential lifecycle, enrollment binding and credential→principal mapping; CI #239 green, merge `aaf22a1f0caea908322620667d52f544fb59cb27` |
| Phase 5C2 — Windows protected key backend | **Complete — PR #40 merged** | CI #243 passed on Synology Portable + Windows; merge `8608a1497a7e339eda2ba4447d08183d29de65bd` |
| Phase 5C3 — enrollment + mTLS | **In progress — X.509 issuance active in PR #52** | PR #41–#47 established enrollment, pinned bootstrap trust, bounded issuance, PKCS#10 proof-of-possession and bounded credential rotation; PR #50 merged verified certificate→stable PrincipalId resolution with CI #285 green; PR #51 merged enrolled QUIC mTLS with CI #288 green. PR #52 adds bounded X.509 issuance from approved CSRs; authority-provider integration and transport revocation enforcement remain next |
| Phase 5D — authorization + session negotiation | Planned | Per-command authorization, replay controls, capability/session negotiation over the real transport |
| Phase 5E — hardening | Planned | Malformed input, reconnect storms, fuzzing, protocol compatibility and security tests |
| AI quality workflow | **Active** | Project skills + official plugins documented in `docs/AI_QUALITY_STACK.md` |

Tracking issue: #32.

## Rules while Phase 4 hardware is unavailable

Phase 5 may proceed in parallel because control-plane correctness does not depend on selecting the final unicast media transport.

The following decision remains deliberately open until Phase 4 physical evidence exists:

- default one-to-one media transport: UDP vs QUIC Datagram.

Do not close Issue #3 or claim Phase 4 acceptance from hosted CI.

## Engineering workflow

For non-trivial repository work, follow:

**Research → Plan → Test → Implement → Review → Security Scan → Runtime/Visual Verification → CI → Merge → Update living docs**

Project-specific instructions live in:

- `.agents/skills/classmesh-engineering/`
- `.agents/skills/classmesh-design/`
- `.agents/skills/frontend-design-review/`
- `docs/AI_QUALITY_STACK.md`

External general-purpose tooling should normally remain installed through its maintained upstream distribution instead of being copied into the repository.

Current preferred layers:

- Superpowers for planning/TDD/debugging/verification discipline;
- UI/UX Pro Max as a maintained UI/UX knowledge layer;
- Microsoft Frontend Design Review as an independent critique layer;
- Codex Security for security-sensitive diffs and threat-model work;
- ClassMesh skills for project-specific architecture, evidence, Windows UI and phase gates.

## Phase 5 transport/security baseline

- QUIC is the reliable control transport.
- TLS 1.3 protects the QUIC connection.
- Enrolled peers will use mutual authentication.
- ALPN identifies the ClassMesh control protocol independently of media transport.
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

Before introducing or materially changing transport, cryptography, identity, codec, Windows API, update-chain, security-scanning or agent-tooling dependencies:

1. check current upstream documentation, release state, source and license;
2. prefer standards and maintained upstream crates/tools over custom protocol/crypto;
3. confirm project MSRV and Windows support;
4. add deterministic tests before making the component production-critical;
5. record architecture decisions that would be expensive to reverse;
6. for external AI skills/plugins, review scripts/hooks/MCP servers, write permissions, credentials and network dependencies before upgrade;
7. do not add overlapping skills that only increase context without adding a distinct quality gate.

Current control-plane research baseline:

- RFC 9000 — QUIC transport;
- RFC 9001 — QUIC + TLS security and 0-RTT replay considerations;
- RFC 8446 — TLS 1.3;
- Quinn 0.11.x / rustls 0.23.x for Rust QUIC/TLS;
- Prost 0.14.x for Protocol Buffers;
- RFC 2986 — PKCS#10 certification requests for enrollment.

## Planned PR sequence

1. **5A Control foundation — complete, PR #33.**
2. **5B QUIC/TLS transport — complete, PR #36 merged, CI #232.**
3. **5C1 Stable identity + rotation model — complete, PR #39 merged, CI #239.**
4. **5C2 Windows protected key backend — complete, PR #40 merged, CI #243.**
5. **5C3 Enrollment + mTLS — active** — PR #41–#47 landed enrollment/trust/issuance-policy/PKCS#10/bounded-rotation slices; PR #50 merged verified certificate→stable PrincipalId resolution with CI #285 green; PR #51 merged enrolled QUIC mTLS with CI #288 green. PR #52 is the active bounded X.509 issuance slice; authority-provider integration and transport revocation/rotation enforcement follow.
6. **5D Authorization/session integration** — connect authenticated principal to command permissions and stream/session negotiation.
7. **5E Hardening** — malformed messages, replay/duplicate cases, reconnect storms, fuzz targets and diagnostics.

Quality-tooling changes should stay in small independent PRs so they do not block or obscure Phase implementation diffs.

Each merged Phase PR updates this file and `docs/IMPLEMENTATION_STATUS.md`.
