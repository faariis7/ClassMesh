# Efficient development workflow — ClassMesh

Status: adopted 2026-10-21. This is an execution policy, not permission to
lower safety, code review, CI or Windows hardware qualification standards.

## Work in one reviewable, coherent batch

1. Check GitHub Live main, existing PRs, CI and current roadmap/status/handoff
   before touching files. Prefer Graphify before broad symbol searches.
   Avoid replaying merged work or editing Astra-owned Phase 12 worktrees.
2. State goal, risks, acceptance criteria, affected files and tests. Group
   RELATED implementation, regression tests and necessary docs into ONE
   reviewable branch/PR. Split unrelated work and security-sensitive
   interfaces that need separate reviews. Never enlarge a diff for its own sake.
3. Use Remote Desktop Commander first where available. Bundle bounded and
   auditable reads/edits/commands rather than dozens of tiny calls. Confirm
   exact branch and revision before mutation.
4. Follow TDD with focused, fast RED/GREEN tests while iterating. At the END
   of the batch run cargo fmt --all -- --check, cargo test --workspace,
   cargo clippy --workspace --all-targets -- -D warnings, and native Windows
   tests for Windows-only behavior. Never skip the full required CI gates.
5. Review the complete diff and its security/trust boundaries; push one
   coherent candidate rather than triggering full CI on every tiny edit.
   Merge only on verified required green checks and appropriate review.
6. While CI runs, avoid repeated polling. Investigate real failures or prepare
   separately isolated work; only inspect CI at meaningful transitions.
7. Report completed code/tests/PR/SHA and actual blockers, not progress
   inferred from queued tests or synthetic physical tests.

## Historical, reproducible CI baseline

Four successful GitHub Actions PR runs (2026-10-21):

| Run | Windows Build | Portable Rust |
|---|---:|---:|
| 39622622083 | 18m 07s | 33s |
| 39638009758 | 18m 00s | 55s |
| 39640876061 | 17m 56s | 28s |
| 39649464235 | 18m 24s | 1m 01s |

Median Windows Build was 18m 04s. In run 39649464235, costly Windows
steps were Test (3m 15s), Teacher UI shell (2m 50s), Clippy (2m 37s),
network impairment proxy (2m 18s), media diagnostics (1m 52s), and
Teacher UI MSRV (1m 24s). These are timestamps from actual job steps,
not evidence that any step can safely be deleted.

Reproduce with the read-only, standard-library script:

  for id in 39622622083 39638009758 39640876061 39649464235; do
    gh run view "$id" --repo faariis7/ClassMesh --json databaseId,jobs > "/tmp/classmesh-ci-$id.json"
  done
  python3 scripts/ci_timing_report.py /tmp/classmesh-ci-*.json --top 6
  python3 -B -m unittest discover -s scripts/tests -p test_ci_timing_report.py

The report script reads local JSON only; it does not call GitHub, touch CI,
or claim that VMs can replace physical-scale qualification.

## Cached Windows builds: known regression, not a quick toggle

PR #428 added a commit-pinned Windows Rust cache action. PR #569
INTENTIONALLY REMOVED it because the optional cache action HUNG.
Older GitHub caches of approximately 1.4–1.7 GB still exist, but
their presence is NOT proof that re-enabling the action is safe.

Any future cache experiment must first diagnose the previous hang;
use a separate reversible PR, pin and review the action, bound
save/restore latency and total artifact size, keep failure cancellation
and security gates unchanged, and compare at least THREE successful
equivalent warm runs before claiming a repeatable speedup. Account for
cold/warm differences, runner image and total network/archive cost.
Do not reintroduce the old caching action without these protections.

## Unchanged security and release gates

Do not change shared IPC or Astra Phase 12 trust policy without
coordination. Physical Phase 4/7/8/9 gates remain independent. Phase 10
is NOT complete until the production authenticated nonblocking
Worker-to-Service-to-Teacher telemetry path and the real 5/10/20/30
receiver physical tests and 30-minute soak are qualified.
