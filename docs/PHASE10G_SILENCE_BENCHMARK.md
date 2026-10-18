# Phase 10G — synthetic per-receiver telemetry-silence qualification

## Purpose

Phase 10's cohort planner has an explicit `expire_stale(now_us)` API, but a silent receiver was not part of the existing adaptive-controller CI/lab benchmark. This change adds deterministic timer-tick coverage to the *existing* `classmesh-adaptive-controller-benchmark` used by the portable and hosted Windows CI jobs.

## Scenario and assertions

At supported 5/10/20/30-receiver scale, first exercise the existing noisy-receiver, loss/queue degradation, replay rejection, independent recovery, transport and rendition qualification gates. Then keep every peer except the formerly weak receiver reporting fresh data, simulate a timed `expire_stale` call past that receiver's maximum telemetry age and require: exactly one route change; only the silent receiver moves to Emergency; the other N−1 peers stay High. A second timer tick must emit no duplicate transition. Three strictly newer healthy readings are necessary for the expired receiver to return to High; the first two must stay Emergency. The new report fields and CLI lines expose these deterministic checks, and any violated invariant returns a nonzero exit code.

Tests use the existing Rust package suite; the synthetic benchmark is run at multiple classroom sizes. The first regression was added before implementation and failed compilation for missing silence qualification report fields (RED), followed by GREEN on native Windows x64. Exact-head hosted Portable Rust/Windows Build are still required before merge.

## Security and qualification boundaries

This is a synthetic **test-tool** consumer of the same `ReceiverCohortPlanner` used by the library tests. It does not add the missing real-time owner/timer for a production receiver telemetry channel; that integration must be done only after a validated live telemetry ingest path is identified. No actual Wi-Fi impairment, latency throughput, media packet capture, GPU, or physical two-host qualification is claimed. Production transport choices, Service authorization, Phase 12 root/epoch worktrees, and physical gates remain unchanged.
