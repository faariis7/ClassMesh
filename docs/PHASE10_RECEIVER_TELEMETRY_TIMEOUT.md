# Phase 10 — bounded receiver telemetry silence

## Failure demonstrated

A receiver with a previously High quality route stays High indefinitely if its telemetry simply stops: `observe` runs only when the receiver reports new samples. A stream without packets should not remain classified healthy forever.

## Opt-in periodic expiration contract

`ReceiverCohortPlanner::expire_stale(now_us)` is a new independent core-only hook for periodic scheduler integration. After a receiver has delivered at least one accepted sample, the hook checks its latest accepted `observed_at_us` against `max_sample_age_us` (default 2 seconds). Exact boundary remains valid; elapsed time strictly greater than the threshold or a clock regression immediately forces *that receiver* to Emergency using the existing profile mapping, without waiting for two additional missing samples. This clears pending recovery, retains the last actual sample sequence/time and re-routes only the affected receiver. Repeated timeout ticks are idempotent; unobserved receivers receive no fabricated route. Once fresh valid data returns, normal three-sample recovery hysteresis still applies.

This API **must be called periodically from the real owner of the cohort planner**; adding it to the library alone does not wire a production watchdog. No Service, protocol, durable policy, media transport, or Astra worktree is modified.

## Tests and limits

Native unit tests cover two healthy peers unaffected by a single expired receiver, exact age boundary, no duplicate routing, absent samples, clock rollback, post-expiry recovery, and the normal healthy and poor-network hysteresis behavior. VM1/VM2 targeted and full core suites plus Clippy and hosted Portable/Windows CI are gates. Physical weak-network/5-30 devices and scheduling the real periodic call remain separate acceptance tasks.
