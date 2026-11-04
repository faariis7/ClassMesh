# V2.1: stability, performance and reliability

Scope: auditor Python, tests, fixtures and documentation only. Baseline: main
`a645faaac21db97756492bb2c1f79a0cf39a900d` (both #685 and #686 merged).
Branch: `codex/pr-readiness-auditor-v2-1-20261104`. No scheduler, developer
branch, VM, application, Rust, workflow, protection or merge operation.

## Investigation and established cause

V2 compares ordered whole-PR fingerprints for the first/last open-PR lists.
The fingerprint includes `updated_at` and `merge_commit_sha` alongside refs.
A timestamp-only edit, a moved HEAD, membership change, incomplete response,
request exhaustion or timeout all collapse to `INVENTORY_CHANGED_OR_UNAVAILABLE`.
The final response/error is then discarded, and policy propagates the gap to
every PR. These are reproducible causes of an indiscriminate global block and
lost diagnostic information. Reviews/comments are read only once: a dismissal
with unchanged PR metadata can leave the old approval counted.

The specific historical 12-PR incident **cannot be attributed retrospectively**:
its original first/last responses and transport failure were not provided or
retained. A fresh unmodified V2 live run with 12 PRs did **not** reproduce the
inventory warning. All 254 requests succeeded, both inventories matched and all
per-PR observations were stable. Its PARTIAL status was nevertheless correct:
12 missing manual-acceptance assessments, five missing current CodeQL/Gitleaks
results each, three unknown base proofs, and one missing current Windows/Portable
result each. These overlap and are not a count of unique PRs.

V2.1 retains the same evidence gaps and all 12 BLOCKED classifications on the
paired live workload. No missing evidence was promoted to success.

## Implementation and acceptance

- Compare validated unique membership sets, preserving first/last availability,
  original error codes, added IDs and removed IDs. Actual inventory changes or
  unavailable inventories still block global readiness.
- Revalidate every PR at closeout. Ref/base/merge movement, material metadata,
  reviews/decisions/threads and comments have separate per-PR states. A later
  list timestamp change remains `LATE_PR_CHANGE`, not silently ignored.
- Ignore title/timestamp differences only when material PR fields and two
  complete review/discussion observations agree. A body edit is material even
  without a timestamp change. Unknown/change prevents READY_FOR_MERGE locally;
  unrelated candidates retain their own evidence. Dependencies remain enforced.
- Read reviews, threads and issue comments in one bounded GraphQL bundle twice;
  paginate each connection, detect missing counts, duplicate identities, cursor
  cycles, nested truncation, partial GraphQL errors and denied data. A changed
  or unavailable closing review cannot reuse the opening approval.
- Gather core structured evidence for all PRs before job logs. Cache job lists
  only during this collection, keyed by repository/run/attempt. Bind every job
  ID, head, attempt and conclusion, and still inspect each individual job log.
  Commit, branch and policy caches remain limited to one collection.
- Reserve `2 * PRs + distinct bases + 2` requests and up to 20% of remaining
  time (maximum 60 seconds) during execution-proof collection for closeout.
  Exhausted proof budget yields UNKNOWN, never success. Large paginated reviews
  may need more than this estimate; closeout can still fail explicitly.
- Record actual request count, elapsed wall time and category/error/unsent-call
  totals. No raw response, log, credential, persistent cache or network retry.
  `BUDGET_EXHAUSTED` remains compatible and adds REQUEST_LIMIT/DEADLINE cause.
- JSON remains schema 2, with optional collection_diagnostics,
  collection_metrics and per-PR stability. Existing V2 sample outputs are
  byte-for-byte unchanged. The Arabic live report displays the diagnostics.
  `merge_authorized` remains false in every case.

## TDD and local verification

Baseline: **121 tests**. Final: **150 tests** (all original tests retained).

| Cycle | RED observed before implementation | GREEN |
| --- | --- | --- |
| Scoped stability and repeated review observations | 10 failing scenarios against V2; final replay: 10 assertion failures, 0 errors | 131 total pass |
| Batched jobs, reserved budget, transport metrics | 6 assertion failures | 139 total pass |
| Report diagnostics | 1 assertion failure | 143 total pass |
| Base unavailable versus changed; preserve endpoint cause | 2 assertion failures | 150 total pass |

Additional negative tests cover paginated reviews, nested thread truncation,
duplicate jobs/inventory, rate limits, wrong attempts, deadline reserve, isolation
between collections and unrelated-PR readiness. All are offline mocked GitHub
responses; no Windows or third-party Python dependencies.

Commands (from repository root):

```sh
python3 -B -m unittest discover -s tools/classmesh-pr-audit/tests
python3 -B tools/classmesh-pr-audit/verify.py
git diff --check
```

Full suite: PASS (150 tests, about 0.26 seconds locally). Syntax, deterministic
JSON/Arabic sample and whitespace: PASS. Existing hosted CI separately checks
Python 3.11/3.14, Rust formatting/Clippy/tests, Windows and security on the PR SHA.
Local Python evidence is not Rust/Windows/security-review/physical acceptance.

## Measured comparison (12 identical PR IDs and HEADs)

Defaults: per-call timeout 20s, overall deadline 600s, maximum 1200 requests.
One serial live before/after pair on 2026-11-04; not a statistical latency SLA.
Read-only GET/query calls, no requested data omitted, no API failures or skips.

| Measure | V2 | V2.1 |
| --- | ---: | ---: |
| Actual API requests | 254 | 224 |
| Wall seconds | 207.048 | 196.883 |
| Job metadata requests | 36 | 18 |
| Job log requests | 36 | 36 |
| Job log seconds | 72.224 | 72.759 |
| GraphQL review observations | 12 | 24 |
| Separate REST review/comment requests | 24 | 0 |
| Code scanning requests | 12 | 12 |
| Immutable commit requests | 23 | 23 |
| Offline identical API fixture requests | 28 | 25 |

Requests decreased **11.8%**, observed wall time **4.9%**, while adding closing
review verification. Network variance affects wall time; logs still dominate
and are not dropped for speed. Neither run had an inventory change. Both return
exit 2/PARTIAL, 12 BLOCKED and zero merge candidates, for the same evidence gaps.
The live reports/snapshots are local delivery artifacts, not committed PR data.

## Trust review and remaining limits

Untrusted input: GitHub PR prose, JSON/GraphQL shapes, pagination, job IDs and
workflow logs. No prose is executed. Fixed repo-relative REST paths and query-only
GraphQL remain enforced. No blanket cache of mutable responses; closing reads
always reach the transport. Unknown, rate limits and permission failures are
preserved; no fallback to an earlier successful attempt. Existing output
confinement, redaction, independent-review and security policies are unchanged.

Collection is observational, not an atomic GitHub transaction. Review changes
between/after observations, CI reruns after checks were read, or protection and
permission changes after their read can still race a report. Re-run before a
human decision. Policies are not modified. API limits, >100 nested comments,
ambiguous checkout logs and unavailable hardware evidence remain UNKNOWN.
No claim is made to prove a vulnerability, fix, hardware acceptance, or permission
to merge. The original historical incident remains unproven; diagnostics now
retain the evidence needed to distinguish a future occurrence.

Primary API references: [list PRs](https://docs.github.com/en/rest/pulls/pulls#list-pull-requests),
[jobs for a specific attempt](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt),
[GitHub API best practices](https://docs.github.com/en/rest/using-the-rest-api/best-practices-for-using-the-rest-api).
