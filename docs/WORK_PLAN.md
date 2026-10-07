# ClassMesh Living Work Plan

Last updated: 2026-10-07

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
| Phase 7 — wired-classroom Teacher Presentation | **7A–7G software complete; 7H physical scale qualification pending — Issue #153** | Production protected multicast, bounded unicast outlier fallback and coordinated/rate-limited recovery are wired through PR #272. PR #273 adds the repeatable 2/5/10/20/30-receiver evidence harness/runbook and CI-tested qualification bundle; hosted CI does not satisfy 7D multicast viability or 7H physical scale evidence |
| Phase 8 — Wi-Fi fan-out benchmark / optional relay | **Software baselines + qualification tooling complete; physical strategy decision pending — Issue #276** | Direct and relay synthetic baselines are merged through PR #279; PR #280 adds the physical 5/10/20/30-receiver Wi-Fi evidence harness. Hosted CI does not select the production Wi-Fi strategy. |
| Phase 9 — monitoring grid | **9A–9E software complete; 9F physical qualification pending — Issue #281** | Low-cost 2–5 FPS monitoring profile/scheduler, GPU-native Worker thumbnail encode path, change-aware heartbeat, bounded Teacher fan-in and interactive promotion are merged through PR #286. PR #287 adds synthetic/classroom qualification tooling; physical 5/10/20/30-source evidence remains pending. |
| Phase 10 — adaptive networking / quality controller | **10A–10F + 10G tooling complete; 10G physical evidence pending — Issue #288** | Per-receiver health sampling, hysteretic profile adaptation, independent cohort routing, physical-gated transport/topology decisions, and recovery/latest-frame-wins integration are merged through PR #293. PR #294 merged evidence-gated rendition/SFU eligibility without selecting a topology; PR #296 merged the adaptive-controller benchmark, physical evidence harness and qualification bundle. Physical 10G execution remains pending. |
| Phase 11 — Teacher UI / classroom UX | **COMPLETE — Issue #298** | 11A–11E and 11F1–11F4 are complete. PR #327 resolved the runtime-confirmed navigation clipping by removing the duplicated in-app title, using wrapped navigation, and defining explicit default/minimum viewport sizing. Portable + Windows CI #1315 were green; the exact PR artifact passed SHA-256 bundle validation and a second interactive Session 1 smoke on the connected Windows 11 ARM64 VM. Classroom/Focus/Presentation/Diagnostics were all fully visible, keyboard reachable/activatable, visibly focused and truthful at 100% DPI. This closes only the Phase 11 UI gate; Phase 4/6/7/8/9/10 physical gates remain independent. |
| Phase 12 — Administrative features | **12A + 12B1–12B4a + 12C1 + 12C2a–12C2b complete; 12B4b physical gate open; 12C2c + 12C3a complete; 12C3b current — Issue #328** | PR #330 merged protocol v0.5 and typed SystemActions; PR #337 completed exact system-action permissions; PRs #339/#341/#343/#345/#347/#350 completed the portable executor boundary, typed Worker Lock path, bounded Service orchestration and narrow Win32 Restart/Shutdown execution. PR #352 completed 12B4a with CI #1411 green and a non-destructive exact-build evidence bundle while physical actions remained undetermined. PR #354 completed additive control v0.6 plus bounded Teacher-message / typed HTTPS-or-app contracts with Portable + Windows CI #1422 green; media datagrams remain on v0.4. PR #357 completed 12C2a permissions/dispatch and PR #359 completed IPC minor 0.10 typed request/result contracts. PR #361 completed bounded exact-Worker Service orchestration and correlated results with Portable + Windows CI #1448 green. PR #363 completed 12C3a narrow injectable Win32 Teacher-message / typed target executors with Portable + Windows CI #1456 green; hosted tests invoked no display/launch side effects and capability advertisement remains disabled. |
| AI quality workflow | **Active** | Project skills + official plugins documented in `docs/AI_QUALITY_STACK.md` |

Phase 5 tracking issue #32 and Phase 11 Issue #298 are complete. Active product tracking is Phase 12 Issue #328. Active physical/qualification tracking remains under Phase 6 Issue #108, Phase 7 Issue #153, Phase 8 Issue #276, Phase 9 Issue #281, and Phase 10 Issue #288.

## Current priority

1. **Phase 12C3a is complete in PR #363 with Portable + Windows CI #1456 green; Phase 12C3b is current under Issue #328.**
2. Reuse the existing exact-bound `ServiceTeacherInteractionRequest` Worker event path. Revalidate the full 12C1 request immediately before execution, then invoke only the injected 12C3a message/target boundaries.
3. Map only `DefaultBrowser`, `Calculator` and `TextEditor` to the closed Win32 app identity enum. Reject missing/unknown values before any side effect; HTTPS must pass the existing strict protocol validator again.
4. Preserve exact process/session/control-session/request/action correlation in `WorkerTeacherInteractionResult`. Map asynchronous acceptance only to `Accepted`; validation or OS rejection returns bounded non-sensitive `Failed`/diagnostic results rather than crashing the Worker.
5. Keep `TeacherMessage` / `OpenTarget` Hello advertisement disabled until 12C3b is merged and the end-to-end execution path is serviceable; do not alter Phase 6E clipboard or media protocol ownership.
6. Keep Phase 4, 6F, 7D/7H, 8D, 9F, 10G and Phase 12B4b physical gates open; preserve Phase 13 installer/update/recovery and Phase 14 hardening in roadmap order.

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
10. **Phase 7 wired-classroom Teacher Presentation — active in parallel with physical gates.** 7A transport-neutral lifecycle landed in PR #154; 7B bounded authenticated ownership/session cleanup landed in PR #156/#157; 7C bounded shared encoded fan-out landed in PR #158; 7D multicast lifecycle/probe implementation landed in PR #159/#160 with physical multicast viability still unproven. The RFC 9605 SFrame crypto core landed in PR #161, the bounded `ReceivePresentation`-gated receiver/key coordinator in PR #162, and the protocol v0.4 key grant/ack contract plus explicit `SframeGroupMedia` capability in PR #163. PR #165 zeroizes process-owned control-frame encode/send/receive buffers and PR #166 adds receiver-side decoded-key installation with success/failure zeroization. PR #167 binds sender-side grants to the exact enrolled StudentDevice PrincipalId/control session, keeps one bounded pending ACK correlation per grant, and rechecks live `ReceivePresentation` authorization before marking installation. PR #168 adds one-shot sensitive grant sending that zeroizes protobuf key bytes after success/failure and exact receiver ACK construction from the already-installed grant binding. PR #169 wires the authenticated Student Service receiver handler: exact live presentation owner/session/stream binding, live `StartPresentation` authorization, strictly increasing in-session key epochs, pre-install rejection zeroization, post-install ACK emission and derived receiver-state retention/cleanup. The Student Service is still not reused as a key sender. PR #170 adds fail-closed client-side resolution of the TLS-verified Student Service certificate to the exact caller-selected stable `StudentDevice` PrincipalId on the bundled `ClientControlSession`, while requiring Teacher role plus the negotiated v0.4 group-media contract. PR #172 completes 7E implementation with a 64-receiver-bounded Teacher delivery manager, exact Quinn connection/control-session/version ownership, live TLS identity re-binding, one-shot grant send, one pending ACK per receiver, fail-closed ambiguous-send behavior and exact ACK acceptance using the caller-owned global authenticated-session sequence guard. PR #173 starts 7F with a canonical SFrame binding over presentation/stream/epoch/frame metadata plus an opaque sealed-frame transport type. PR #174 adds the sender half of the protected multicast transport: probe-gated startup, exact IPv4 egress-interface selection, one-hop TTL, sealed-frame-only packetization and no multicast retransmission cache. PR #175 adds the receive-side socket/reassembly boundary with source/version/stream filtering, media-local malformed-packet isolation, bounded loss feedback and explicit ciphertext output pending SFrame verification. PR #177 adds the authenticated per-receiver feedback contract: uncorrelated NACK/keyframe events on the existing control session, exact registered StudentDevice/Quinn connection/control-session/version binding, caller-owned global replay state, live `ReceivePresentation` authorization and exact stream checks. PR #176 adds the zeroizing IPC v0.6 Service→Worker presentation-key contract, preserving Worker ownership of the interactive media/decode path instead of streaming H.264 through the Service. PR #178 adds the non-sensitive exact Worker→Service install-result correlation required before an upstream Teacher key ACK can truthfully mean the Worker installed the epoch. PR #179 adds portable Worker-owned derived SFrame receiver state: raw keys are consumed through the zeroizing install contract, epoch rotation is strictly increasing for the exact live binding, binding changes require explicit lifecycle clear, and authenticated ciphertext opening reuses the canonical presentation/frame binding. PR #180 wires that state into the interactive Worker runtime with the zeroizing sensitive decoder, a bounded 128-entry IPC event queue with backpressure, exact Worker install-result emission only after install processing, and an exact-bound typed local key-clear message that can only clear the matching control-session/request/presentation/stream/epoch. PR #181 moves Student Service key handling to orchestration only: a bounded install queue forwards the one-shot sensitive key to the authenticated Worker pipe, ACK is built only from an exact Worker-confirmed non-secret binding while the same PID/session is still alive, stale/miscorrelated results are ignored, and an exact-bound lease clears Worker state on stop/session teardown. PR #183 adds exact Worker→Service presentation-feedback IPC correlation around the existing bounded NACK/keyframe payload so stale feedback can be rejected before network emission. PR #182 provides independent control send/receive ownership, and PR #184 uses it for a bounded authenticated feedback pump: exact Worker generation + key lease + presentation binding checks, live Teacher credential/`StartPresentation` reauthorization, session-global outbound sequencing, and per-session lag isolation. The presentation multicast offer contract now carries only versioned administratively scoped group+port parameters; authenticated Teacher source and Student NIC remain runtime-local bindings. A bounded local multicast probe now gates Service `UdpMulticast` capability advertisement for one explicitly configured IPv4 interface, while control and transport-neutral Teacher Presentation remain available when the probe is absent or fails. The fixed-width Service→Worker presentation-multicast start IPC is now request-correlated and paired with an exact Worker PID/session `Started`/`Rejected` result, preventing a pipe write or delayed prior attempt from being treated as successful receiver startup. Worker bind/join/leave ownership and bounded receive/feedback pumping are now implemented behind an exact installed group-media key binding; authenticated SFrame opening now reconstructs decoder-eligible H.264 access units only after binding/replay verification. The proven Media Foundation H.264 + D3D11 presentation lifecycle is now extracted from the diagnostic receiver into one reusable Worker runtime; the multicast Worker now pairs receiver + decode/render startup, submits only SFrame-authenticated access units, coalesces authenticated keyframe recovery only from decoder keyframe-wait/recovery while keeping SFrame-rejected media from driving control feedback, and tears both runtimes down together on exact key clear or media-local failure. PR #198 completes the Student-side Service `StreamOffer` dispatch boundary: presentation offers require `StartPresentation`, exact authenticated presentation ownership and the Worker-confirmed key lease; source/interface remain runtime-local; bounded commit/cancel dispatch prevents timeout ambiguity; and only an exact current Worker `Started` result can authorize an accepted `StreamAnswer`. PR #201 bridges encode-once `SharedEncodedFrame` output into the protected multicast sender through the single-owned `GroupMediaCoordinator`; PR #203 adds the bounded multicast `FrameDistributor` attachment; PR #206/#211 provide one-encoder Teacher fan-out and protected multicast runtime composition; PR #212 preserves recovery keyframes under bounded queue pressure; PR #215 adds fail-fast nonblocking protected multicast sending; and PR #220 wires that path into the live Teacher runtime without moving `GroupMediaCoordinator` or authorization ownership. Phase 7F implementation is complete. Phase 7G software is also complete through PR #272: bounded unicast fallback admission/transport, stable outlier slots, transactional plan/runtime application with fail-closed rollback, authenticated fallback-target orchestration, and authenticated feedback → rate-limited granted-keyframe application are wired into the live Teacher sender composition without duplicating key/counter ownership. PR #273 starts 7H with a Windows-CI-tested qualification harness, a receiver-correlated evidence manifest, a 2/5/10/20/30-receiver runbook and a dedicated artifact bundle; the harness deliberately reports qualification as undetermined until reviewed physical evidence exists. Physical multicast viability remains unproven under 7D, and 7H classroom-scale physical qualification remains required.

Quality-tooling changes should stay in small independent PRs so they do not block or obscure Phase implementation diffs.

Each merged Phase PR updates this file and `docs/IMPLEMENTATION_STATUS.md`.