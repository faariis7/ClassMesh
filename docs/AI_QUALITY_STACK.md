# ClassMesh AI Quality Stack

Last updated: 2026-09-18

This document defines the small, maintained set of AI skills/plugins used to improve ClassMesh engineering and design quality.

The goal is not to install the largest number of skills. Each layer must have a distinct responsibility and a clear update path.

## Stack

| Layer | Tool | Source | Integration |
|---|---|---|---|
| Engineering workflow | Superpowers | OpenAI Codex official marketplace / upstream `obra/superpowers` | User-level plugin; do not vendor |
| Project engineering constraints | `classmesh-engineering` | This repository | `.agents/skills/classmesh-engineering` |
| UI/UX knowledge | UI/UX Pro Max | `nextlevelbuilder/ui-ux-pro-max-skill` | Maintain via upstream CLI; do not hand-copy its data set |
| Independent UI critique | Frontend Design Review | `microsoft/skills` | Vendored repo-level skill |
| Project desktop design constraints | `classmesh-design` | This repository | `.agents/skills/classmesh-design` |
| Application security | Codex Security | OpenAI Codex official marketplace | User-level plugin; do not vendor |

## Verified upstream state at this update

- Superpowers Codex plugin manifest: **6.3.0**, MIT.
- Codex Security plugin manifest: **0.1.24**.
- UI/UX Pro Max CLI package: **2.5.0**, MIT.
- Microsoft `frontend-design-review`: sourced from `microsoft/skills`, MIT.

Versions above are evidence from upstream on 2026-09-18, not permanent pins. Re-check before upgrades.

## Installation/update policy

### Superpowers

Install/update through the official Codex plugin marketplace rather than copying its skills into this repository.

Use it for:
- brainstorming and implementation plans;
- TDD;
- systematic debugging;
- verification before completion;
- code review and finish-the-branch discipline.

### Codex Security

Install/update through the official Codex plugin marketplace.

Use it when a diff touches:
- authn/authz;
- enrollment or credentials;
- TLS/QUIC trust;
- parser or protocol boundaries;
- unsafe Rust/FFI;
- installer/update trust;
- IPC or local privilege boundaries.

Keep scan credentials minimal. Do not expose unrelated environment secrets to security tooling.

### UI/UX Pro Max

Use the maintained CLI/package rather than copying its large searchable knowledge base into ClassMesh.

Current upstream commands:

```bash
npm install -g ui-ux-pro-max-cli
uipro update --global
uipro init --ai universal --global
```

For a project-scoped install instead:

```bash
uipro init --ai universal
```

Never commit a GitHub token or other credential used only to raise public API rate limits.

### Microsoft Frontend Design Review

A small project-level copy is stored under:

```text
.agents/skills/frontend-design-review/
```

It is used as an independent critique layer. ClassMesh desktop-specific constraints live in `classmesh-design` and take precedence over web-only assumptions.

## ClassMesh execution workflow

For non-trivial work:

1. **Research** — current primary sources, standards, maintained dependencies.
2. **Plan** — narrow scope, acceptance criteria, risks, rollback.
3. **Test** — deterministic failing coverage first where practical.
4. **Implement** — bounded, observable, recoverable behavior.
5. **Review** — correctness, complexity, UX where applicable.
6. **Security scan** — required for trust-boundary/security-sensitive changes.
7. **Runtime/visual verification** — real Windows/runtime evidence when relevant.
8. **CI** — portable + Windows validation.
9. **Merge** — only after required evidence is green.
10. **Update living docs** — plan/status must match reality.

## Rules for adding another skill

Add a new skill/plugin only when all are true:

- it covers a recurring gap not already handled by this stack;
- it is actively maintained or simple enough to audit and vendor safely;
- its source/license/permissions are understood;
- it does not require broad secrets or unrelated account access;
- it improves a measurable quality gate, not merely prompt style;
- its instructions do not conflict with ClassMesh architecture/security gates.

Prefer one precise skill over several overlapping general-purpose skills.

## Security and privacy

Treat external skills/plugins as third-party code or instructions.

Before upgrading:
- inspect the source/change log or manifest;
- review new scripts, hooks, MCP servers, write permissions, and network dependencies;
- avoid auto-running untrusted repository code;
- never grant credentials solely because a skill requests them;
- keep project-specific authority in the ClassMesh skills and repository docs.

## Next tooling candidates

Evaluate later, only when the relevant phase arrives:

- Windows UI Automation/runtime inspection for Console/Agent visual QA;
- fuzzing for control/protocol parsing and state machines;
- dependency/advisory/license policy gates such as RustSec/cargo-deny;
- SBOM/release provenance for installer/update work.
