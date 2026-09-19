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
| Phase 5C3 — enrollment + mTLS | **Core path complete through PR #62** | PR #41–#47 established enrollment/trust/issuance-policy/PKCS#10/bounded rotation; PR #50 merged verified certificate→stable PrincipalId resolution with CI #285 green; PR #51 merged enrolled QUIC mTLS with CI #288 green; PR #55 removed unbounded rotation; PR #58 merged safe credential persistence with CI #307 green; PR #59 merged bounded X.509 issuance with PR CI #309/current-main CI #310 green; PR #60 merged protected CNG→rcgen signing with PR CI #311/current-main CI #312 green; PR #61 merged protected CNG→rustls client signing and negative mTLS coverage with CI #314 green; PR #62 merged live credential re-check with CI #316 green |
| Phase 5D — authorization + replay controls | **Complete — PR #63 merged** | Verified mTLS PrincipalId is bound to Hello.device_id; exact control_session_id, strictly increasing sequence, live credential state and per-command permission are enforced; PR CI #330 green, merge `221e53bf981f9fdd33526fb5ac359b1282cb655f` |
| Phase 5E — authenticated capability/session negotiation | **Complete — PR #63 merged** | Capability intersection and negotiated protocol/session are established inside the authenticated enrolled Hello path; spoofed application identity is rejected before the session is accepted |
| Phase 5F — hardening | **Active** | PR #66/#69/#70 hardened handshake/framing; PR #73 durable authorization state (CI #354); PR #75 per-user SID Worker IPC ACL (CI #357); PR #77 reconnect-policy validation (CI #361); PR #79 I/O-timeout validation (CI #364); PR #81 command-version binding (CI #367); PR #83 dropped-session full reconnect (CI #372); fuzzing and broader malformed authenticated-envelope/security diagnostics remain |
| AI quality workflow | **Active** | Project skills + official plugins documented in `docs/AI_QUALITY_STACK.md` |

Tracking issue: #32.

## Rules while Phase 4 hardware is unavailable

Phase 5 may proceed in parallel because control-plane correctness does not depend on selecting the final unicast media transport.

The following decision remains deliberately open until Phase 4 physical evidence exists:

- default one-to-one media transport: UDP vs QUIC Datagram.

Do not close Issue #3 or claim Phase 4 acceptance from hosted CI.

### 2026-09-19 Parallels qualification attempt

Two running Windows 11 ARM Parallels VMs were used for a preliminary Phase 4
diagnostic run against `main` commit
`27f97bfb3e07d9a7e06479cde76d2a14098faa64` and CI #353 artifact 10588923268.

- Synthetic transport measurement completed: UDP p50/p95 2.58/10.80 ms and
  QUIC Datagram p50/p95 1.83/7.31 ms, with 0.00% final effective loss and zero
  send errors in both valid 60-second client runs.
- The nominal 500 packets/s workload was not achieved in the VMs: UDP attempted
  13,187 and QUIC attempted 11,398 rather than 30,000 datagrams. Record the
  actual counts; do not normalize or claim the requested rate passed.
- Live media is blocked in this environment. Teacher capture found the display
  but returned `NoHardwareEncoder`; Student failed to activate a D3D11-aware
  H.264 decoder with `0x80004005`. The zero-loss proxy consequently received
  zero media datagrams.
- The standalone 10-cycle GPU recovery probe also stopped before cycle 1 with
  the same decoder activation error; it did not measure recovery latency.
- A follow-up Parallels configuration audit confirmed both VMs already have
  `3d-acceleration=highest`, automatic video memory, and current Parallels Tools
  27.0.0-58628. Do not spend another run toggling VM 3D acceleration; the gate
  needs physical Windows GPU hardware or a future explicitly supported virtual
  hardware Media Foundation path.
- 1080p30 render, glass-to-glass latency, 1/3/5% media recovery, GPU recovery,
  and the 30-minute no-growing-delay soak remain **not measured**.
- Do not select UDP or QUIC as the default and do not close Issue #3. Resume the
  live-media matrix on two physical Windows PCs with hardware Media Foundation
  H.264 encode/decode support. See `docs/PHASE4_TWO_PC_RESULTS.md` for the exact
  environment, artifact identity, measurements, and blocker evidence.

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
8. **5F Hardening — active.** PR #66/#69/#70 hardened Hello/HelloAck consistency and malformed framing; PR #73/#75 added durable authorization metadata and restrictive Worker IPC ACLs; PR #77/#79 hardened reconnect/timeout configuration; PR #81 binds privileged commands to the negotiated version; PR #83 retries the full connect + stream + Hello session after transport drops without re-enrollment. Fuzz targets, broader malformed authenticated-envelope coverage, compatibility/security diagnostics, and production control-runtime integration remain.

Quality-tooling changes should stay in small independent PRs so they do not block or obscure Phase implementation diffs.

Each merged Phase PR updates this file and `docs/IMPLEMENTATION_STATUS.md`.
