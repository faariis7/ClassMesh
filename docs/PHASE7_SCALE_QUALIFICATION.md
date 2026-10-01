# Phase 7H Classroom-Scale Qualification

Phase 7H validates the production Teacher Presentation path at classroom scale on real Windows hardware and the intended network. Hosted CI prepares tooling only and **cannot** close this gate.

## Scale points

Run the largest feasible sequence without skipping the smaller checkpoints:

- 2 receivers;
- 5 receivers;
- 10 receivers;
- 20 receivers;
- 30 receivers when hardware is available.

Record unavailable scale points explicitly rather than inferring them.

## Required scenarios

At each feasible scale point, exercise:

1. healthy wired multicast;
2. multicast with one bounded unicast outlier;
3. slow/degraded receiver isolation;
4. receiver disconnect/reconnect while healthy receivers continue;
5. coordinated keyframe recovery without request storms;
6. at least a 30-minute early-milestone soak.

Phase 7D multicast probe evidence must exist for the intended wired path before treating multicast behavior as physically viable. Phase 4 Issue #3 and Phase 6F Issue #108 remain independent gates.

## Evidence preparation

Initialize a run directory from the qualification bundle:

```powershell
.\phase7h-scale.ps1 -Mode Init -ReceiverCount 5 -ReceiverId student-01,student-02,student-03,student-04,student-05 -ResultsDir .\phase7h-results
```

For each receiver preserve its runtime/telemetry log as:

```text
phase7h-results\receivers\<receiver-id>.log
```

Then verify that the expected evidence set is complete:

```powershell
.\phase7h-scale.ps1 -Mode ValidateEvidence -ResultsDir .\phase7h-results
```

`ValidateEvidence` verifies presence/correlation only. It intentionally prints `qualification_passed=undetermined`.

## Telemetry to retain

For the Teacher and every receiver retain, where available:

- capture/encode FPS and p50/p95 latency;
- sender queue depth/age and media-drop counters;
- multicast packet/frame counts;
- per-outlier unicast queue/drop counters;
- RTT/loss/jitter/reorder feedback;
- decode/render FPS and p50/p95 latency;
- keyframe request/grant/apply counters;
- process CPU, GPU, memory and handle counts;
- reconnect/recovery reason counters;
- control-session liveness while media is degraded.

A single average or end-to-end number is not enough to diagnose scale regressions.

## Acceptance principles

A scale point may be recorded PASS only when the retained evidence and physical observation show:

- healthy receivers remain live while a slow/outlier receiver degrades;
- queue depth/age remains bounded with no steadily increasing latency;
- one classroom rendition is encoded once rather than once per receiver;
- fallback remains bounded to admitted outliers;
- keyframe recovery is coordinated/rate-limited and does not become a request storm;
- media failure/recovery does not terminate healthy authenticated control sessions;
- memory/handles do not show monotonic growth during the run;
- the result is based on real hardware/network evidence, not hosted CI.

Do not use Phase 7H results to decide the Phase 4 one-to-one UDP-vs-QUIC-Datagram default.

## Results

Record reviewed evidence in `docs/PHASE7_SCALE_RESULTS.md`. A missing scale point remains pending.
