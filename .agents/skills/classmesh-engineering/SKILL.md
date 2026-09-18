---
name: classmesh-engineering
description: >
  Apply the ClassMesh engineering workflow when planning, implementing, debugging, reviewing, testing,
  or hardening ClassMesh code. Enforces current roadmap gates, evidence-based verification, small PRs,
  Windows + portable CI, and security constraints.
---

# ClassMesh Engineering

Use this skill for repository work that changes behavior, architecture, protocol, security, networking,
media, Windows runtime, installer/update behavior, tests, CI, or technical documentation.

Do not use this skill as a substitute for visual design review; use `classmesh-design` for UI/UX work.

## Read first

Before making a non-trivial change, inspect the smallest relevant set of:

- `docs/WORK_PLAN.md`
- `docs/IMPLEMENTATION_STATUS.md`
- `docs/ROADMAP.md`
- `docs/SECURITY.md`
- `docs/PROTOCOL.md`
- the tracking issue/PR for the current phase

Treat implementation status, hosted-CI evidence, and physical-hardware evidence as different facts.

## Mandatory workflow

1. **Research**
   - Verify current upstream APIs, standards, crate versions, Windows behavior, or security guidance when the change depends on them.
   - Prefer primary sources and maintained upstream projects.
   - Do not introduce custom cryptography when a maintained standard/library exists.

2. **Plan**
   - State the narrow goal, acceptance criteria, risks, and files/subsystems expected to change.
   - Keep changes reversible and reviewable.
   - Split unrelated work into separate PRs.

3. **Test first where practical**
   - Add or update deterministic tests that fail for the missing behavior before changing production logic.
   - For hardware-only behavior, add the best hosted-CI coverage possible, but keep the physical validation gate explicit.

4. **Implement**
   - Prefer bounded queues, bounded retries, explicit timeouts, and recoverable state transitions.
   - Avoid hidden global state and sticky permanent fallbacks.
   - Preserve protocol compatibility unless a deliberate versioned break is documented.
   - Keep control-plane and media-plane health independent.

5. **Review**
   - Review the diff for correctness, unnecessary complexity, error handling, observability, and rollback behavior.
   - Re-read changed public interfaces and wire formats from the caller/peer perspective.

6. **Security**
   - Use Codex Security or an equivalent structured security review when the diff touches authentication,
     authorization, enrollment, credentials, update trust, IPC trust, network exposure, parsers, or unsafe code.
   - Re-check trust boundaries and threat-model assumptions, not only syntax.

7. **Verify**
   - Run rustfmt, Clippy with warnings denied, workspace tests, and the relevant Linux/Windows CI path.
   - Verify runtime behavior for Windows-specific code when a real environment is available.
   - Never report a gate as passed from inference or compilation alone.

8. **Merge**
   - Merge only after required CI and review evidence is green.
   - Update `docs/WORK_PLAN.md` and `docs/IMPLEMENTATION_STATUS.md` when phase state materially changes.

## Current hard gates

These remain true until repository evidence explicitly changes them:

- Phase 4 Issue #3 stays open until two physical Windows PCs pass the documented qualification.
- The default one-to-one media transport remains **undecided: UDP vs QUIC Datagram** until physical Phase 4 evidence.
- Do not claim hosted CI proves GPU capture/encode/decode/render or glass-to-glass latency on real hardware.
- QUIC is the reliable control transport; administrative application data does not use QUIC 0-RTT initially.
- Stable principal/device identity must not be derived from mutable hostname/IP or from the active certificate fingerprint.
- Enrolled privileged sessions require authenticated identity and per-command authorization.
- Do not weaken TLS, certificate validation, replay controls, or enrollment boundaries for convenience.
- Keep the documented project MSRV unless a deliberate toolchain change is reviewed and recorded.

## Coordination with external skills/plugins

When available:

- Use **Superpowers** for planning, TDD, systematic debugging, verification-before-completion, and branch-finish discipline.
- Use **Codex Security** for security-sensitive diffs and repository threat-model work.
- Use this ClassMesh skill to resolve project-specific constraints when a generic skill conflicts with the roadmap or evidence gates.

Do not duplicate a large external skill inside this repository merely to pin it. Prefer the official plugin or package
and record the source/version in `docs/AI_QUALITY_STACK.md`.

## Verification checklist

Before calling work complete:

- [ ] Acceptance criteria are explicit and satisfied.
- [ ] Tests cover the important behavior or the missing hardware evidence is clearly documented.
- [ ] No unbounded queue/retry/wait was introduced.
- [ ] Error paths are observable and recoverable where expected.
- [ ] Security boundaries were reviewed when relevant.
- [ ] Portable and Windows CI requirements are green.
- [ ] Documentation reflects the real implementation state.
- [ ] Phase 4 hardware-only claims remain pending unless physical evidence exists.
