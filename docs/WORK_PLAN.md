# ClassMesh Living Work Plan

Last updated: 2026-09-23

This is the active execution plan for ClassMesh. It is updated as implementation evidence changes so roadmap intent, code status, hosted-CI evidence, and physical validation are not confused.

## Current execution state

| Track | State | Current gate |
|---|---|---|
| Phase 4 — one-to-one live video | **Implementation complete; physical qualification pending** | Issue #3 stays open until two physical Windows PCs pass the documented 1080p30, latency, impairment and soak criteria |
| Phase 5A — control protocol foundation | **Complete — PR #33 merged** | Generated Protobuf, version/capability negotiation and heartbeat/liveness are on `main` |
| Phase 5B — QUIC/TLS runtime | **Complete — PR #36 merged** | Current-baseline CI #232 passed on Synology Portable + Windows; merge `794fd45a5a20b6e4c623b7ecbbcfda5264e52ec0` |
| Phase 5C1 — identity/rotation model | **Complete — PR #39 merged** | Stable PrincipalId, multi-credential lifecycle, enrollment binding and credential→principal mapping; CI #239 green, merge `aaf22a1f0caea908322620667d52f544fb59cb27` |
| Phase 5C2 — Windows protected key backend | **Complete — PR #40 merged** | CI #243 passed on Synology Portable + Windows; merge `8608a1497a7e339eda2ba4447d08183d29de65bd` |
| Phase 5C3 — enrollment + mTLS | **Core path complete through PR #62** | PR #41–#47 established enrollment/trust/issuance-policy/PKCS#10/bounded rotation; PR #50 merged verified certificate→stable PrincipalId resolution with CI #285 green; PR #51 merged enrolled QUIC mTLS with CI #288 green; PR #55 removed unbounded rotation; PR #58 merged safe credential persistence with CI #307 green; PR #59 merged bounded X.509 issuance with PR CI #309/current-main CI #310 green; PR #60 merged protected CNG→rcgen signing with PR CI #311/current-main CI #312 green; PR #61 merged protected CNG→rustls client signing and negative mTLS coverage with CI #314 green; PR #62 merged live credential re-check with CI #316 green |
| Phase 5D — authorization + replay controls | **Complete — PR #63 merged** | Verified mTLS PrincipalId is bound to Hello.device_id; exact control_session_id, strictly increasing sequence, live credential state and per-command permission are enforced; PR CI #330 green, merge `221e53bf981f9fdd33526fb5ac359b1282cb655f` |
| Phase 5E — authenticated capability/session negotiation | **Complete — PR #63 merged** | Capability intersection and negotiated protocol/session are established inside the authenticated enrolled Hello path; spoofed application identity is rejected before the session is accepted |
| Phase 5F — hardening | **Complete — through PR #107** | Fuzzing, malformed-envelope coverage, stable diagnostics, durable authorization/identity state, protected CNG server credentials, fail-closed Service startup, enrolled QUIC runtime, authenticated post-Hello session handling, centralized privileged dispatch, and end-to-end authorized input forwarding are merged; PR #107 CI #427 green |
| Phase 6 — interactive remote control | **Implementation complete through 6E; physical validation pending — Issue #108** | 6A–6C are merged; 6D production focused-stream adaptation/media is complete through PR #145 (CI #619 green), including measured/cached H.264 capability evidence, peer-bound UDP stream start, bounded Worker H.264 sender, authenticated StreamAnswer acceptance, and bounded NACK/keyframe recovery forwarding; 6E clipboard skeleton merged in PR #116; only 6F physical interactive-control validation remains |
| AI quality workflow | **Active** | Project skills + official plugins documented in `docs/AI_QUALITY_STACK.md` |

Phase 5 tracking issue #32 is complete. Active Phase 6 tracking issue: #108.

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
5. **5C3 Enrollment + mTLS — core path complete** — PR #41–#47 landed enrollment/trust/issuance-policy/PKCS#10/bounded-rotation slices; PR #50 merged verified certificate→stable PrincipalId resolution with CI #285 green; PR #51 merged enrolled QUIC mTLS with CI #288 green; PR #55 removed unbounded rotation; PR #58 merged safe credential persistence with CI #307 green; PR #59 merged bounded X.509 issuance with CI #309 green. PR #60–#62 completed protected signing, enrolled mTLS negative coverage, and live credential re-check.
6. **5D Authorization/replay integration — complete, PR #63.** Verified identity, session binding, monotonic command sequence and live per-command permission checks are connected.
7. **5E Authenticated capability/session negotiation — complete, PR #63.** Negotiated protocol/capabilities and session establishment occur inside the enrolled authenticated Hello path.
8. **5F Hardening — complete through PR #107.** PR #66/#69/#70 hardened Hello/HelloAck consistency and malformed framing; PR #73/#75 added durable authorization metadata and restrictive Worker IPC ACLs; PR #77/#79 hardened reconnect/timeout configuration; PR #81/#83 completed negotiated-version binding and bounded full-session reconnect; PR #86/#88/#91 added fuzzing, stable security diagnostics and malformed established-envelope coverage; PR #93–#95 added protected server credentials, durable machine identity and fail-closed Service state loading; PR #101/#103/#104 connected the enrolled QUIC runtime, privileged dispatch and post-handshake session loop; PR #105–#107 delivered the first end-to-end authorized input path into the interactive Worker.
9. **Phase 6 interactive remote control — implementation complete through 6E; 6F physical validation pending under Issue #108.** 6A–6C are merged. 6D progressed through focused adaptation/profile plumbing (#113–#115), bounded contracts and failure isolation (#117–#124), measured and Service-owned encoder capability evidence/cache integration (#125–#137), peer-bound UDP stream dispatch and production Worker H.264 sending (#138–#142), and bounded authenticated NACK/keyframe recovery forwarding (#143–#145). PR #145 CI #619 is green. 6E is merged in PR #116. Hosted CI does not satisfy 6F or the independent Phase 4 Issue #3 physical gate.
10. **Phase 7 wired-classroom Teacher Presentation — active in parallel with physical gates.** 7A transport-neutral lifecycle landed in PR #154; 7B bounded authenticated ownership/session cleanup landed in PR #156/#157; 7C bounded shared encoded fan-out landed in PR #158; 7D multicast lifecycle/probe implementation landed in PR #159/#160 with physical multicast viability still unproven. The RFC 9605 SFrame crypto core landed in PR #161, the bounded `ReceivePresentation`-gated receiver/key coordinator in PR #162, and the protocol v0.4 key grant/ack contract plus explicit `SframeGroupMedia` capability in PR #163. PR #165 zeroizes process-owned control-frame encode/send/receive buffers and PR #166 adds receiver-side decoded-key installation with success/failure zeroization. The current 7E follow-up binds sender-side grants to the exact enrolled StudentDevice PrincipalId/control session, keeps one bounded pending ACK correlation per grant, and rechecks live `ReceivePresentation` authorization before marking installation. The current Student Service direction is intentionally not reused as a key sender; Teacher-side runtime delivery/receiver ACK emission remain the next runtime slice. Production multicast wiring remains later. 7H classroom-scale physical qualification remains required before production multicast media.

Quality-tooling changes should stay in small independent PRs so they do not block or obscure Phase implementation diffs.

Each merged Phase PR updates this file and `docs/IMPLEMENTATION_STATUS.md`.
