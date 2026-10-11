# ClassMesh Agent Handoff

> Evidence snapshot: 2026-10-11. **GitHub Live is always authoritative.** Recheck current main, open PRs, Issues, jobs and instructions before work. This file is a checkpoint, not automatic proof that no later change exists.

## Current
- Main verified after documentation PR #409: `316067a7143179a3602a20dd149216b8860eb6e3`. Recheck GitHub Live before changing code.
- Active product Issue: [#328](https://github.com/faariis7/ClassMesh/issues/328), Phase 12 administrative features.
- Clipboard 12E3+ orchestration / Teacher UI **not yet implemented**; existing Phase 6E text-only bounded protocol must be reused.
- Phase 12D Teacher file transfer remains incomplete at the live staged-candidate producer and authenticated transport/result UI integration boundaries.

## Completed
- PR #407 (12E1): existing-wire 64 KiB clipboard text validation and unavailable-response semantics.
- PR #408 (12E2): central privileged ClipboardWrite dispatch calls `validate_write`, preserving validation before authorization/replay checks and explicit WriteClipboard permission.
- PRs #400–#405: bounded Teacher file-transfer UI pending-action/candidate lifecycle contracts; **not** a real end-to-end file-transfer claim.

## In progress
- Phase 12E3a PR #410 is in CI #1653 at this checkpoint (Portable Rust succeeded; Windows Build had not yet completed). Opaque dispatch tokens and their tests are proposed, not merged until all gates pass.

## Next
1. Inspect the current authenticated Teacher/Service post-Hello pipeline and existing clipboard read/write Worker routes.
2. Specify the smallest missing 12E3 slice, exact authorization/capability/sequence/correlation requirements and negative tests; retain a bounded queue and text-only wire.
3. Use test-first implementation on a branch from up-to-date main. Verify Rustfmt, Clippy, workspace tests and Portable Rust + Windows Build CI; review before merge.
4. Return to 12D4b's trusted staged-file producer and actual Teacher transport/result handoff without exposing arbitrary filesystem paths.
5. Execute exact-build interactive Teacher UI qualification on Windows; keep VM evidence distinct from physical PC/GPU/network acceptance.
6. Continue Phase 12F/12G then Phase 13 per ROADMAP, without closing open qualification gates.

## Blocked / deferred
- No second Windows target required yet; cross-VM/multi-PC tests are deliberately deferred.
- Hosted CI and one ARM64 virtual Windows instance do not qualify physical GPU capture, throughput, classroom-scale or two-physical-PC outcomes.
- Production Teacher file-pull candidate source, transport-result path, and clipboard interactive execution are not accepted by existing hosted CI.

## Open PRs
- ClassMesh: [PR #410](https://github.com/faariis7/ClassMesh/pull/410), Phase 12E3a, awaiting CI/review in this snapshot. [PR #409](https://github.com/faariis7/ClassMesh/pull/409) already merged.
- agent-skills: [PR #5](https://github.com/faariis7/agent-skills/pull/5) merged as `a4bead87e34e7180df939787e109bd66bfb6b642` after live 0.69 CLI/guest verification.

## CI status
- [PR #408 CI #1650](https://github.com/faariis7/ClassMesh/actions/runs/38145955105): completed success; Portable Rust and Windows Build jobs passed on head `0a6a65a`.
- [Merged-main CI #1651](https://github.com/faariis7/ClassMesh/actions/runs/38146937198): completed success; Portable Rust and Windows Build jobs passed on `780d7ec`.
- [PR #409 CI #1652](https://github.com/faariis7/ClassMesh/actions/runs/38150139588): Portable Rust + Windows Build completed successfully on `9fd51a8` before squash merge `316067a`.
- PR #410 CI #1653: Portable Rust success, Windows Build still pending as this checkpoint was authored. Verify CI Live before merging; do not substitute earlier green statuses.
- The statuses above apply **only to those exact commits**, not to future PRs.

## VMPal / test evidence
- Mac host observed VMPal 0.69 build 69; `vmpal list --json` confirms Windows VM 1 (`DF60038E-4C4D-4DCB-B310-1D2ACAAD798A`) running with agent control enabled.
- Guest `vmpal exec` succeeded: Windows 11 Pro ARM64 24H2, OS build 26100, PowerShell 5.1.26100.9457, interactive user. `vmpal ui ... status --json` reports authorized USB-HID control; `observe --text` returned desktop text. VMPal Tools 0.48.
- This confirms **CLI bridge access via Remote Desktop Commander**, not a native VMPal MCP connection in this conversation.
- **Exact-build Teacher GUI runtime evidence (2026-10-11):** CI #1646 x64 `classmesh-teacher-ui.exe` SHA-256 `ce9e88e3d724dbf11b92a7aa23eae9da77023c7480aa3c3e2ff02e17676eb75e` initially failed visibly with missing `VCRUNTIME140.dll` on the ARM64 Windows VM. A VMPal snapshot `Before-VC-Redist-ClassMesh-2026-10-11` was taken. Downloaded official Microsoft x64 VC++ redistributable, verified Valid Microsoft Corporation Authenticode signature (SHA-256 `843068991daaa1f73ad9f6239bce4d0f6a07a51f18c37ea2a867e9beca71295c`), installed using `/install /quiet /norestart`, exit 0; x64+ARM64 version `14.51.36247.00` appeared in registry.
- **GUI re-test:** Same executable then showed ClassMesh Teacher in interactive Session 1, `Responding=True`, with truthful empty states and successful VMPal HID navigation of Classroom, Focus, Presentation, Diagnostics and Device Actions; screenshots retained on authorized Mac in `/tmp/classmesh-teacher-{classroom,focus,presentation,diagnostics,actions,tab-focus}-20261011.png`. Process remained responsive on subsequent check. This is a *single-VM visual/launch qualification only*, not authenticated production clipboard, FileTransfer or physical network/GPU evidence. Deployment fix tracked [Issue #411](https://github.com/faariis7/ClassMesh/issues/411).

## Physical gates (OPEN)
- Phase 4 Issue #3: two physical Windows PCs, 1080p30/latency/impairment/soak; UDP vs QUIC Datagram choice remains undecided.
- Phase 6F Issue #108; Phase 7D/7H #153; Phase 8D #276; Phase 9F #281; Phase 10G #288.
- Phase 12B4b safe Lock/destructive power acceptance; Phase 12C4b interactive Teacher UI qualification; Phase 12D4 real file-transfer runtime/visual qualification.

## Next executable task
**12E3b after #410 CI/merge:** consume opaque authorized clipboard read/write tokens through a narrow bounded Service→Worker seam with exact session/request/capability/permission binding, defined read-response correlation, failure/backpressure/cancel tests and injected non-destructive Windows interfaces. No production clipboard claim until such routing exists. No parallel clipboard protocol or shell endpoint.

## Operating rules
- Read `.agents/skills/classmesh-engineering/SKILL.md`, `docs/WORK_PLAN.md`, `docs/IMPLEMENTATION_STATUS.md`, `docs/ROADMAP.md` and affected security/protocol docs.
- The repository root did not contain `AGENTS.md` on 2026-10-11; recheck before later edits.
- Preserve least privilege, bounded queues, explicit replay suppression, existing protocol versioning and no destructive tests on hosted runners or a non-disposable VM.
