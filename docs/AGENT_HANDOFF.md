# ClassMesh Agent Handoff

> Evidence snapshot: 2026-10-11. **GitHub Live is always authoritative.** Recheck current main, open PRs, Issues, jobs and instructions before work. This file is a checkpoint, not automatic proof that no later change exists.

## Current
- Main at handoff: `780d7ece183f58f7917fc82b86a7d52ef59a65d5` (squash merge PR #408).
- Active product Issue: [#328](https://github.com/faariis7/ClassMesh/issues/328), Phase 12 administrative features.
- Clipboard 12E3+ orchestration / Teacher UI **not yet implemented**; existing Phase 6E text-only bounded protocol must be reused.
- Phase 12D Teacher file transfer remains incomplete at the live staged-candidate producer and authenticated transport/result UI integration boundaries.

## Completed
- PR #407 (12E1): existing-wire 64 KiB clipboard text validation and unavailable-response semantics.
- PR #408 (12E2): central privileged ClipboardWrite dispatch calls `validate_write`, preserving validation before authorization/replay checks and explicit WriteClipboard permission.
- PRs #400–#405: bounded Teacher file-transfer UI pending-action/candidate lifecycle contracts; **not** a real end-to-end file-transfer claim.

## In progress
- Next Phase 12E production clipboard execution architecture assessment. No unverified work should be marked complete.

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
- ClassMesh: none as of this checkpoint; verify GitHub before acting.
- agent-skills: [PR #5](https://github.com/faariis7/agent-skills/pull/5), VMPal agent control skill, requires independent review and validation.

## CI status
- [PR #408 CI #1650](https://github.com/faariis7/ClassMesh/actions/runs/38145955105): completed success; Portable Rust and Windows Build jobs passed on head `0a6a65a`.
- [Merged-main CI #1651](https://github.com/faariis7/ClassMesh/actions/runs/38146937198): completed success; Portable Rust and Windows Build jobs passed on `780d7ec`.
- The statuses above apply **only to those exact commits**, not to future PRs.

## VMPal / test evidence
- Mac host observed VMPal 0.69 build 69; `vmpal list --json` confirms Windows VM 1 (`DF60038E-4C4D-4DCB-B310-1D2ACAAD798A`) running with agent control enabled.
- Guest `vmpal exec` succeeded: Windows 11 Pro ARM64 24H2, OS build 26100, PowerShell 5.1.26100.9457, interactive user. `vmpal ui ... status --json` reports authorized USB-HID control; `observe --text` returned desktop text. VMPal Tools 0.48.
- This confirms **CLI bridge access via Remote Desktop Commander**, not a native VMPal MCP connection in this conversation and not ClassMesh UI/runtime acceptance.

## Physical gates (OPEN)
- Phase 4 Issue #3: two physical Windows PCs, 1080p30/latency/impairment/soak; UDP vs QUIC Datagram choice remains undecided.
- Phase 6F Issue #108; Phase 7D/7H #153; Phase 8D #276; Phase 9F #281; Phase 10G #288.
- Phase 12B4b safe Lock/destructive power acceptance; Phase 12C4b interactive Teacher UI qualification; Phase 12D4 real file-transfer runtime/visual qualification.

## Next executable task
**12E3 discovery/test design:** locate the exact existing Phase 6E ClipboardReadRequest/ClipboardWrite dispatch and Worker execution seam, identify missing read-response return path and capability gating, add fail-closed tests before any production change. No parallel clipboard protocol or shell endpoint.

## Operating rules
- Read `.agents/skills/classmesh-engineering/SKILL.md`, `docs/WORK_PLAN.md`, `docs/IMPLEMENTATION_STATUS.md`, `docs/ROADMAP.md` and affected security/protocol docs.
- The repository root did not contain `AGENTS.md` on 2026-10-11; recheck before later edits.
- Preserve least privilege, bounded queues, explicit replay suppression, existing protocol versioning and no destructive tests on hosted runners or a non-disposable VM.
