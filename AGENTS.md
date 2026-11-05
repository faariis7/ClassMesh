# ClassMesh agent entry point

Read .agents/skills/classmesh-engineering/SKILL.md and CONSTRAINTS.md before changing anything. For UI work, also follow the project design skill. Project-specific constraints take precedence over generic agent skills.

## Resume from live evidence
- Start from the current GitHub main HEAD, open PRs, docs/WORK_PLAN.md, docs/IMPLEMENTATION_STATUS.md, docs/AGENT_HANDOFF.md and relevant tracking issue. Never trust an older handoff over the live repository.
- Use Graphify first for symbol ownership, dependencies, blast radius and test mapping. Check that the indexed commit matches the code being changed; fall back to direct source inspection for non-indexed files.
- Do not overwrite other agents' working trees. Use a separate feature branch/worktree and one bounded scope per PR.

## Safe execution
- Plan explicit acceptance conditions, run failing tests first for behavior changes, implement minimally, then test and review independently.
- Keep Rust portable, native Windows and hardware/physical evidence separate. Never claim GPU, Session 0 or two-PC behavior from Linux CI alone.
- Preserve protocol/security boundaries, Windows Service trust, enrollment, authenticated command authorization and the existing feature gates.
- Run rustfmt, Clippy and workspace tests; require the applicable Windows and hosted CI plus security review before proposing merge.
- No changes to production enrollment, secrets, deployment or privileged Windows service installation as part of a tooling-only task.

## Reporting
Report changed paths, exact commands and results, remaining risks, GitHub PR/commit and any blocked physical tests. Do not silence checks or weaken gates to get green.
