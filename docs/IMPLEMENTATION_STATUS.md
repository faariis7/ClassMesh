# ClassMesh Implementation Status

Last updated: 2026-09-19

This file distinguishes **implemented code**, **hosted-CI validation**, **real-hardware validation still required**, and **future product work**. Architecture documents must not be read as claims that every planned feature is already production-ready.

## Current baseline

`main` includes Phase 4 implementation and qualification tooling through PR #31, Phase 5A from PR #33, Phase 5B from PR #36, Phase 5C1 from PR #39, Phase 5C2 from PR #40, and the Phase 5C3 v0.2 enrollment wire contract from merged PR #41.

Phase 4 physical acceptance remains pending. Issue #3 must remain open until two physical Windows PCs pass the documented qualification.

Phase 5 is tracked in Issue #32. Phase 5B is merged with CI #232 green; Phase 5C1 is merged in PR #39 with CI #239 green; Phase 5C2 is merged in PR #40 with CI #243 green; and PR #41 merged the protocol v0.2 PKCS#10 enrollment CSR/receipt/status/result contract. Phase 5C3 continued through merged PR #42 with bounded, status-dependent validation of terminal enrollment certificate results, then merged PR #43 added explicit pinned bootstrap trust bound to stable PrincipalId and a fresh client nonce. CI #260 passed on Synology Portable and Windows for PR #43.

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

### Phase 5C3 — PRs #41, #42 and #43 merged

Merged PR #41 provides the protocol v0.2 PKCS#10 enrollment request/receipt/status/result contract, strict request validation, explicit rejection of enrollment on negotiated v0.1, and result binding to the stable `PrincipalId` plus exact CSR SHA-256.

PR #42 adds status-dependent validation before credential persistence/mTLS wiring. Approved terminal results require a bounded certificate chain, 32-byte credential fingerprint, expiry, and the identity/CSR binding fields. Rejected/revoked/expired terminal results may not carry credential material; pending/unspecified statuses are not accepted as terminal results; certificate count, per-certificate DER size and aggregate chain size are bounded. CI #256 passed after the validator was wired into the public control crate.

PR #43 adds explicit bootstrap authority pinning using a SHA-256 certificate fingerprint and binds the bootstrap challenge to the expected stable PrincipalId and fresh client nonce. Discovery metadata is not trusted to select the authority and no TOFU behavior is introduced. CI #260 passed on Synology Portable and Windows.

This does **not** yet claim certificate authority issuance or production trust-store behavior. The next security slice is certificate issuance using the explicit bootstrap trust model, followed by post-enrollment mTLS and revocation/rotation integration without exporting private keys.

## Remaining security/control work

- certificate issuance and persistence;
- explicit bootstrap trust policy;
- post-enrollment mTLS identity and stable-principal resolution;
- revocation/key rotation integrated with transport authentication;
- per-command authorization and replay/duplicate enforcement;
- authenticated capability/session negotiation;
- malformed-input/reconnect/fuzz hardening;
- encrypted multicast media key distribution/replay/rotation;
- production per-user SID ACL on local Named Pipes.

## Other production work still required

Encoder/runtime hardening still needs bounded async Media Foundation watchdogs, measured low-latency codec controls, real adapter/driver capability caching, deliberate multi-GPU selection, device-loss recovery evidence and long-running leak/driver soak tests. Classroom fan-out still needs production shared-output integration, multicast protection, per-client fallback and classroom-scale tests. Installer/update/product work still needs service/firewall installation, signed update/rollback, polished Console/Agent UI, diagnostics export and support bundles.

## Next implementation sequence

1. Keep Issue #3 open and perform Phase 4 physical qualification when two Windows PCs are available.
2. Implement certificate issuance against the explicit bootstrap trust model merged in PR #43.
3. Wire post-enrollment mTLS without weakening stable identity or exporting private keys.
4. Integrate revocation/rotation with transport authentication, then Phase 5D authorization/replay/session negotiation.
5. Add malformed-input/reconnect/fuzz and dependency/advisory/license gates when useful to the active phase.
6. Begin product UI work under `classmesh-design` with runtime/visual verification when Console/Agent UI becomes active.
