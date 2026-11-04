# V2 acceptance and evidence plan

Baseline: PR #685 open at 5bcfd1044b2d592e7d07a8315520105b63709f16; 61 offline tests pass. Work is in the independent `classmesh-pr-audit-v2` worktree. Continue this branch with ordinary pushes. Python changes stay here; a separate stacked PR changes only `.github/workflows/classmesh-pr-audit.yml`.

Acceptance:

1. Keep the V1 evaluation callable for comparisons; layer decision stages, evidence conditions, next actions and explainable priority on existing collection/check/review logic. Output schema becomes 2, accepting schema-1 snapshots conservatively.
2. Distinguish technical blockers, missing essential evidence, independent review, remaining final reviews, and all recorded verifiable conditions met. No stage is authority to merge.
3. Preserve current-HEAD CI results. Bind bounded checkout-log observations to the exact GitHub job/run/attempt/check, and inspect immutable commit parents. HEAD-only observations survive base movement; integration results on an older base require revalidation. Missing/ambiguous proof or a moving collection stays UNKNOWN. A rerun timestamp alone is insufficient.
4. Retain security-source links and distinguish confirmed review/scan blockers, human review, chronological history, API-resolved discussions and unknown data. Keywords alone cannot confirm a vulnerability or clear a finding.
5. Derive dependencies from branch identity and explicit `Depends-On: #N` declarations; preserve unknown parents/cycles. Suggest roles, never invented assignees. Rank parents before children with visible contributions for actual blockers and transitive work unlocked.
6. Produce an Arabic executive summary, top five actions, per-PR evidence/action/owner/priority, and a V1/V2 comparison from one canonical snapshot hash. Optional snapshots stay in the selected output directory and contain no raw job logs.
7. Add offline negative tests before implementation. Run all 61 original cases plus new cases, syntax/whitespace and deterministic sample checks. New CI uses supported Python versions on GitHub-hosted Linux with read-only permissions, no special token, no cache or VM.
8. Verify both final remote heads and all their applicable CI jobs before reporting completion. Do not merge, dispatch workflows, or change scheduler/device/service settings.

Known boundaries: CI logs are execution evidence supplied by the repository's workflows, not cryptographic attestation that tests are sufficient. Strict parsing rejects ambiguity and subsequent visible Git tree changes. Physical acceptance and unimplemented advanced repository rules remain human/UNKNOWN gates. Recorded responsibility mappings are not available, so suggestions use roles.

## Verification record (2026-11-04)

- Baseline: `python3 -B -m unittest discover -s tools/classmesh-pr-audit/tests` — 61 cases passed at 5bcfd104.
- Red: initial V2 suite (27 cases) failed because the new decision API, checkout proof parser and log transport did not exist. Dependency/priority additions produced 37 cases with 39 errors before their implementation.
- Green: all 37 V2 cases passed after decision and dependency implementation.
- Red: output/scope verification and additional identity tests produced 50 cases with 5 failures and 4 errors (missing CLI flags/verifier, unknown mandatory review decision accepted, untrusted proof URL, false diamond path).
- Green: 111 combined cases passed after fixes, fixture expansion and deterministic schema-2 examples.
- Red: Windows quoted-git-path cases exposed two failures: legitimate checkout unrecognized and a subsequent quoted checkout accepted.
- Green: 115 combined cases passed after the parser correction, including full mocked collection, moving base/merge commit, denied logs, exact attempts, cycles/multiple parents, historical security and role-only ownership.
- Final review red/green: two further failures exposed an absent strict-base flag defaulting to false and a lost log-permission error reason. Both were corrected; 117 combined cases (61 original + 56 new) passed.
- Delivery review red/green: edited historical comments and unknown/wrong-HEAD commit timestamps exposed two false historical classifications. Editing now uses the latest timestamp, and history requires a known current-HEAD commit date no later than capture. Final total: 119 passing cases (61 original + 58 new).
- `python3 -B tools/classmesh-pr-audit/verify.py` — syntax and exact sample outputs passed; `git diff --check` passed.
- Live read-only smoke run collected 13 PRs with 279 GET/query-only requests. It correctly preserved one current CI failure, two merge conflicts, two stale root integrations plus another old root, dependency chains and missing hardware/manual evidence. The first run used the pre-correction Windows parser and explicitly reported its missing checkout evidence; it is not used as final-head proof. A final live run follows delivery.

Security review: PR bodies/comments, API payloads and job logs are untrusted. Static API routes/quoted identifiers, GET/query-only calls, job/run/attempt/head binding, immutable commit-parent checks and conservative parser rejection define the evidence boundary. Missing permissions cannot become success. Text cannot close a review thread. Logs remain in memory and are discarded; credential filtering and pinned-directory atomic file writes are retained. Optional snapshots use a fixed filename with the same link protections. No shell evaluation of API text or guessed responsibility assignments. The log evidence limitation is explicit in README and every report.

This record is local Python/tool evidence. Existing hosted Portable Rust, Windows and scanning checks must be verified on each final PR head; local Python tests do not replace them. No physical hardware/VM/scheduler tests are run or claimed.
