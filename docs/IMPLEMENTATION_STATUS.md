# ClassMesh Implementation Status

Last updated: 2026-09-24

This file distinguishes **implemented code**, **hosted-CI validation**, **real-hardware validation still required**, and **future product work**. Architecture documents must not be read as claims that every planned feature is already production-ready.

## Current baseline

`main` includes Phase 4 implementation and qualification tooling through PR #31, Phase 5A from PR #33, Phase 5B from PR #36, Phase 5C1 from PR #39, Phase 5C2 from PR #40, and the Phase 5C3 v0.2 enrollment wire contract from merged PR #41.

Phase 4 physical acceptance remains pending. Issue #3 must remain open until two physical Windows PCs pass the documented qualification.

Phase 5 is complete under Issue #32 through PR #107. Phase 6 implementation is complete through 6E under Issue #108: authenticated input/lifecycle/secure-desktop handling is merged; the focused interactive media path now includes measured and Service-owned H.264 capability evidence/cache validation, peer-bound UDP stream dispatch, production Worker H.264 sending, profile adaptation, and bounded authenticated NACK/keyframe recovery through PR #145 (CI #619 green); the typed bounded clipboard skeleton is merged in PR #116. Phase 6F remains a physical interactive-control validation gate and is not satisfied by hosted CI.

The hosted CI baseline covers Portable Rust / Ubuntu rustfmt, Clippy with warnings denied, full workspace tests and `classmesh-lab`, plus Windows workspace Clippy/tests and release builds for the media qualification executables. Hosted runners do not replace real interactive GPU/driver or two-PC validation.

## Phase 4 physical validation gate

Keep Issue #3 open. Run `docs/PHASE4_TWO_PC_QUALIFICATION.md` and `scripts/phase4-two-pc.ps1` on two signed-in Windows PCs before accepting Phase 4. Required evidence includes sustained hardware capture/encode/decode/render, measured healthy-LAN end-to-end latency, a 30-minute soak without growing display delay, recovery under 1/3/5% deterministic impairment, and recorded UDP-vs-QUIC-Datagram benchmark results. Do not select the default one-to-one media transport until that evidence exists.

## Implemented baseline

The repository currently contains the Phase 4 media runtime and qualification tooling: bounded queues/recovery/adaptation primitives; validated media datagrams, reassembly/NACK/retransmission and UDP/multicast primitives; Windows Service/interactive Worker IPC and lifecycle; DXGI Desktop Duplication with recoverable device/access loss; GPU BGRA→NV12 processing; hardware H.264 Media Foundation encode/decode; D3D11 presentation; receiver feedback/recovery; deterministic network impairment tooling; and the UDP/QUIC Datagram benchmark. These remain subject to the physical qualification gate above.

Phase 5A provides generated Protobuf control messages, bounded envelopes, explicit version/capability negotiation, heartbeat/liveness tracking, stable-identity semantics and a 1-RTT-only administrative security baseline.

Phase 5B provides reliable bidirectional QUIC control streams using Quinn/rustls, TLS 1.3, ALPN `classmesh-control/1`, bounded length-prefixed Protobuf framing, connect/I/O/idle/keepalive timeouts, bounded reconnect behavior, and loopback transport coverage. Production client identity remains Phase 5C work.

### Phase 5C1 — merged PR #39

- Stable `PrincipalId` is independent of hostname/IP and credential fingerprints.
- A principal can own multiple credentials during bounded rotation overlap.
- Active, retiring and revoked credential states are explicit.
- Future-issued, expired and revoked credentials do not authenticate.
- Enrollment approval is bound to the exact pending credential.
- Credential fingerprints map back to the stable principal.
- A credential fingerprint cannot silently bind to two principals.

### Phase 5C2 — merged PR #40

- Machine-scope Windows CNG ECDSA P-256 protected key backend.
- Persisted export policy prohibits private-key export.
- Signing and public-key data are exposed without exporting private material.
- Project MSRV remains Rust 1.85; current `rustls-cng` is not an unconditional dependency.

### Phase 5C3 — enrollment, credential binding and mTLS integration in progress

Merged PR #41 provides the protocol v0.2 PKCS#10 enrollment request/receipt/status/result contract, strict request validation, explicit rejection of enrollment on negotiated v0.1, and result binding to the stable `PrincipalId` plus exact CSR SHA-256.

PR #42 adds status-dependent validation before credential persistence/mTLS wiring. Approved terminal results require a bounded certificate chain, 32-byte credential fingerprint, expiry, and the identity/CSR binding fields. Rejected/revoked/expired terminal results may not carry credential material; pending/unspecified statuses are not accepted as terminal results; certificate count, per-certificate DER size and aggregate chain size are bounded. CI #256 passed after the validator was wired into the public control crate.

PR #43 adds explicit bootstrap authority pinning using a SHA-256 certificate fingerprint and binds the bootstrap challenge to the expected stable PrincipalId and fresh client nonce. Discovery metadata is not trusted to select the authority and no TOFU behavior is introduced. CI #260 passed on Synology Portable and Windows.

PR #45 merged bounded authority-side issuance policy; PR #46 merged PKCS#10 proof-of-possession verification; PR #47 merged explicit bounded credential overlap. PR #50 merged verified TLS leaf-certificate fingerprint resolution through `AuthorizationStore` to the stable `PrincipalId`, preserving revocation/expiry/future-issued/disabled-principal checks. CI #285 passed before merge.

PR #51 merged enrolled-QUIC mTLS with CI #288 green. PR #55 then removed the legacy unbounded credential-rotation path, and PR #58 merged safe conversion of validated approved enrollment results into bounded active credentials with CI #307 green.

PR #59 merged bounded X.509 issuance with CI #309 green. It signs verified approved PKCS#10 requests through rcgen's `SigningKey` abstraction, forces end-entity CA/key-usage constraints instead of trusting CSR-requested privilege, and returns the issued leaf DER/fingerprint together with the exact stable PrincipalId + CSR binding.

PR #60 merged the Windows protected rcgen signing provider with CI #311 green. It adapts the persisted non-exportable CNG ECDSA P-256 key to rcgen's `SigningKey` interface, converts the CNG public blob to SEC1 public-point bytes, and converts fixed-width CNG ECDSA signatures to DER without exporting private-key material.

PR #61 merged the protected mTLS-client slice with CI #314 green. It adapts the same CNG key to rustls `SigningKey`/`Signer`, validates certificate/key SPKI consistency with `CertifiedKey::keys_match`, produces a `ResolvesClientCert` without private-key DER, and adds negative tests proving the enrolled server rejects missing or untrusted client certificates.

PR #62 merged live authenticated-credential re-check with CI #316 green. The established peer identity retains both stable `PrincipalId` and the presented credential fingerprint, and privileged authorization re-validates current revocation/expiry/principal-enabled state instead of relying only on handshake-time authentication.

PR #63 merged authenticated Hello identity/session/replay authorization with PR CI #330 green, completing Phase 5D/5E on the authenticated control path.

### Phase 5F — hardening complete

PR #66 merged after CI #338 green and rejects missing or internally inconsistent Hello protocol versions before negotiation/session establishment. PR #69 merged after CI #343 green and adds explicit malformed-Protobuf control-frame regression coverage. PR #70 merged after CI #345 green and validates HelloAck envelope session/request/sequence/version consistency before the client accepts the negotiated control session.

PR #73 merged after CI #354 green and adds versioned, bounded durable persistence for authorization metadata without exporting private keys. PR #75 merged after CI #357 green and replaces the Worker pipe NULL DACL with a per-user SID + LocalSystem ACL while retaining exact PID/session validation and remote-client rejection. PR #77 merged after CI #361 green and rejects reconnect policies that could produce zero-delay retry storms or inverted backoff bounds. PR #79 merged after CI #364 green and rejects zero control I/O timeouts as invalid configuration.

PR #81 merged after CI #367 green and requires each privileged post-handshake command to carry the exact negotiated protocol version before its sequence can be consumed. PR #83 merged as `e36d26b8c606e087a47e408717f409dd8b4ac35f` after CI #372 green and adds bounded full-session reconnect: connection + control stream + Hello are retried only for transport failures, while protocol/authentication/administrative rejections remain terminal. The same configured QUIC endpoint/credential resolver is reused, so reconnect does not require re-enrollment.

PR #86 added the isolated control-frame fuzz harness; PR #88 added stable non-sensitive security diagnostics; PR #91 added malformed established-envelope regression coverage; PR #93/#94 added protected CNG server credentials and durable machine identity; PR #95 added fail-closed Service startup state validation; PR #101 hosted the enrolled QUIC runtime in the Windows Service; PR #103/#104 connected centralized privileged dispatch and the authenticated post-handshake session loop. PR #105–#107 then established the first Phase 6 input slice end-to-end: defined input semantics, stateful Win32 SendInput execution, authenticated bounded Worker IPC, and bounded Service forwarding after live authorization. PR #107 CI #427 was green. PR #111 added exclusive-controller ownership and lifecycle/stuck-input cleanup with CI #436 green. PR #112 added explicit secure-desktop/input-availability diagnostics with CI #441 green. PR #113–#115 established the motion-preserving Interactive profile ladder, authenticated ReceiverFeedback → hysteretic profile-only StreamReconfigure loop, Service→Worker profile delivery, capture-cadence application and configurable GPU H.264 target plumbing. PR #116 merged the typed bounded clipboard skeleton. PR #117 merged the bounded shared profile contract; PR #118 merged explicit StreamOffer validation; PR #119 merged media-failure/control-survival hardening; PR #120 merged independent named-pipe read/write handles; PR #121 merged typed Worker runtime capability IPC; and PR #122 merged generation-bound Service capability state. PR #123 merged after CI #522 green and publishes current-Worker runtime capability evidence into future authenticated Hello capability sets while remaining transport-neutral. DXGI is published only after a real capture backend starts; `H264HardwareEncode` remains false until ADR-0004's bounded real encode validation is implemented. PR #124 merged after CI #526 green and turns authenticated Interactive `StreamOffer` into an explicit `StreamAnswer` preflight without creating media state or claiming a stream exists. PR #125 merged after CI #530 green and exposes real submission-to-output H.264 latency, selected encoder metadata and `MF_LOW_LATENCY` acceptance as reusable benchmark evidence. PR #126 merged after CI #537 green and adds bounded benchmark accumulation plus shared benchmark→presentation target conversion. PR #127 merged after CI #546 green and drives that evidence from the existing diagnostic GPU capture→NV12→hardware-H.264 path with full-sample completion, actual target geometry/FPS class caps and frame-correlated keyframe evidence. PR #128 merged after CI #549 green and proves reset/recovery by draining/dropping the first pipeline, recreating the same selected backend and target, and requiring real encoded output within a bounded submission window. PR #129 merged after CI #556 green and binds that diagnostic evidence to exact DXGI adapter identity, UMD driver version, encoder CLSID and full measured profile. PR #130 merged versioned, bounded, atomic, fail-closed persistence (CI #564 green); PR #131 moved durable machine-level encoder capability ownership under the Service ProgramData boundary (CI #567); PR #132 bound Worker evidence to the current PID/session/generation before Service persistence (CI #572); PR #133–#137 completed the bounded production benchmark, exact durable-cache verification/query and current-generation cache fast path (latest CI #591 green). PR #138–#142 then added peer-bound UDP transport parameters, bounded Service→Worker stream start, production Worker H.264→UDP sending and StreamAnswer acceptance only after successful Worker start IPC (CI #610 green). PR #143–#145 completed bounded NACK/keyframe IPC, Worker retransmit/keyframe application, and authenticated current-session/current-stream Service forwarding (CI #619 green). Dynamic bitrate remains deliberately unclaimed; profile adaptation uses the validated pipeline reset/recreate behavior instead.

### Phase 5D/5E — authenticated authorization and negotiation complete through PR #63

PR #63 merged the authenticated control-session guard with PR CI #330 green. The enrolled server derives identity from the verified QUIC/mTLS connection, binds `Hello.device_id` to that stable PrincipalId, and rejects spoofing before session establishment. Negotiated protocol version and capability intersection are therefore established inside the authenticated Hello path. Privileged envelopes then require the exact established `control_session_id`, a strictly increasing sequence number, current credential validity, and the requested permission. A denied in-session sequence is consumed so the same administrative command cannot be replayed after a later permission grant.

### Phase 7 — wired classroom Teacher Presentation active

Phase 7 is progressing without weakening the still-open Phase 4 and Phase 6F physical gates. PR #154 added the transport-neutral authenticated presentation lifecycle contract. PR #156/#157 added bounded single-owner presentation state, exact authenticated-session cleanup and Service runtime integration. PR #158 hardened the existing shared encoded-frame distributor so one encoded allocation can fan out to bounded independent sinks without a slow sink blocking healthy receivers. PR #159 added bounded multicast membership/probe contracts, administratively scoped IPv4 group validation and explicit join/receive/leave probe outcomes.

PR #160 completed the 7D two-PC diagnostic bundle after CI #666, and the corresponding `main` push CI #667 is green. Hosted CI verifies the tool/contracts but does not establish wired-classroom multicast viability; the physical probe result remains pending.

PR #161 merged the first Phase 7E security slice after CI #675: RFC 9605 SFrame is isolated behind `classmesh-security`, with a pinned security dependency, non-zero monotonic key epochs and CSPRNG-generated keys, authenticated external metadata, bounded frame/AAD sizes and bounded replay protection.

PR #162 merged the bounded 7E receiver/key coordinator: at most 64 receiver principals, live `ReceivePresentation` authorization before registration/key grant, exact principal + epoch acknowledgement, and fail-closed epoch rotation whenever active membership or authorization changes. Per-receiver install state stays independent so a slow receiver does not stall healthy presentation receivers.

PR #163 merged the protocol v0.4 `PresentationKeyGrant`/`PresentationKeyAck` contract, exact 32-byte SFrame key validation and explicit `SframeGroupMedia` capability negotiation after CI #684 passed on Portable and Windows. PR #165 then hardened the generic control framing/QUIC path so process-owned intermediate protobuf payloads and raw send/receive frame buffers are zeroized after use.

PR #166 adds the receiver-side key-install primitive: validated `PresentationKeyGrant.key_material` is imported through `classmesh-security`, the caller-owned protobuf buffer is zeroized on success or failure, and the control-layer installed object retains only presentation/stream/epoch metadata plus derived SFrame decryption/replay state.

PR #167 adds authenticated sender-side session binding and ACK correlation. A grant can be built only from an enrolled server-side `StudentDevice` peer whose stable PrincipalId, exact control-session ID and v0.4 group-media capabilities agree, and the authenticated credential + `ReceivePresentation` permission are rechecked immediately before key issuance. Each issued grant creates one bounded pending ACK record; ACK acceptance uses the authenticated control guard and live `ReceivePresentation` authorization before coordinator installation.

The current follow-up makes the sensitive grant itself one-shot over `ControlChannel`: the wrapper is consumed and its decoded protobuf key bytes are zeroized before return on success or transport failure. Receiver-side ACK construction is derived only from the same already-installed grant envelope, preserving exact session/version/request/presentation/stream/epoch correlation after the raw key buffer has been zeroized. The Student Service remains deliberately fail-closed for this capability until the authenticated receiver runtime actually retains/uses the installed group-media receiver; Teacher-side session-manager wiring and receiver runtime integration remain pending.

## Remaining security/control work

- Phase 6F physical interactive-control validation under Issue #108, including degraded/lost media while authenticated control remains responsive; hosted CI cannot close this gate;
- encrypted multicast media key distribution/replay/rotation for the later classroom-presentation phase;
- final privilege-boundary, dependency and update-chain review before the 1.0 gate.

## Other production work still required

Encoder/runtime hardening still needs bounded async Media Foundation watchdogs, deliberate multi-GPU selection, broader real-hardware device-loss/recovery evidence and long-running leak/driver soak tests. Classroom fan-out still needs production shared-output integration, multicast protection, per-client fallback and classroom-scale tests. Installer/update/product work still needs service/firewall installation, signed update/rollback, polished Console/Agent UI, diagnostics export and support bundles.

## Next implementation sequence

1. Keep Issue #3 open and perform Phase 4 physical qualification when two Windows PCs are available; do not select the default one-to-one UDP-vs-QUIC-Datagram transport before that evidence exists.
2. Run Phase 6F physical interactive-control validation, including degraded/lost media while authenticated control remains responsive, stuck-input cleanup, secure-desktop diagnostics and bounded focused-media recovery.
3. Continue Phase 7 wired-classroom presentation work in parallel where it does not depend on unresolved physical transport evidence; keep multicast production/security and scale claims behind their explicit 7E/7H gates and never treat hosted CI as transport-selection evidence.
4. Continue later production security, Wi-Fi fan-out, monitoring-grid, installer/update and UI work in roadmap order.
