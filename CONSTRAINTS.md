# ClassMesh engineering quality constraints

These are minimum rules for every agent. Do not weaken them to make a PR pass. See .agents/skills/classmesh-engineering/SKILL.md, docs/SECURITY.md and docs/TESTING.md for the authoritative project-specific detail.

## Required on code-changing PRs
- No unreviewed secret, credential, test fixture with real data or generated private key in commits. The secret-scan workflow is an additional detection layer, not permission to leak anything.
- No skips, ignored warnings, security bypasses, unsafe trust fallback, disabled tests or CI shortcuts without a separately reviewed rationale.
- Portable Rust: cargo fmt --all -- --check; cargo clippy --workspace --all-targets -- -D warnings; cargo test --workspace.
- Windows changes: pass the full exact-head Windows Build workflow and native Windows tests relevant to the affected Service/Worker/GPU boundary. Windows gates cannot be substituted with portable tests.
- Security-sensitive code: document the attacker-controlled input, identity/trust boundary, negative tests, cleanup and reviewer outcome.
- Do not claim hardware streaming, 1080p30, end-to-end latency, large classrooms or physical two-PC completion without a recorded real-world test.

## Review / performance / recovery
- Measure changes against existing project baselines before defining new numeric thresholds. Record p50/p95 latency, FPS, queue/drop behavior, resource/handle growth and recovery outcomes when the changed path requires them.
- Ensure bounded queues, retries, timeouts and inputs. No regression in media/control health independence or per-command authorization.
- CI status is evidence only for its exact commit. A merged PR, test log, experimental proof and production-qualified feature are distinct states.

## After-release evidence (when deployment is authorized separately)
- Record release commit, artifact hash, deployment target, smoke results, error/health counters and rollback command.
- For Service/media releases, verify installation/start/stop and actual native session behavior before declaring success. Preserve prior-known-good artifacts.
- Record unresolved gaps under docs/WORK_PLAN.md and docs/IMPLEMENTATION_STATUS.md rather than inventing success.
