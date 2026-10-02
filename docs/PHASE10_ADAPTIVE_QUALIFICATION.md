# Phase 10G Adaptive Controller Qualification

Phase 10G qualifies the adaptive networking/quality controller as a composed system. Hosted CI validates deterministic invariants and evidence tooling only. It does **not** qualify real network behavior and must not select unresolved production defaults.

## Synthetic coverage

The bundled `classmesh-adaptive-controller-benchmark` exercises the existing production contracts for:

- per-receiver quality-sample validation and hysteretic profile decisions;
- independent cohort routing so one weak receiver does not downgrade healthy peers;
- noisy-sample stability without tier flapping;
- physical-gated transport/topology switching with explicit hysteresis;
- evidence-gated optional multi-rendition/SFU eligibility;
- reliable fallback eligibility without treating it as a normal production default.

Run:

```powershell
.\classmesh-adaptive-controller-benchmark.exe --receivers 30 --rounds 30
```

The benchmark must report:

```text
physical_qualification=false
production_default_selected=false
synthetic_invariants_passed=true
```

## Physical scale points

Run comparable evidence at:

- 5 receivers;
- 10 receivers;
- 20 receivers;
- 30 receivers where hardware allows.

Unexecuted scale points remain pending.

## Required physical scenarios

At each feasible scale point retain evidence for:

1. healthy steady state;
2. one weak receiver degrading while healthy peers remain unchanged;
3. noisy/borderline telemetry that must not flap profiles or paths;
4. congestion/latest-frame-wins recovery without growing media latency;
5. stale/replayed/future or malformed health samples failing closed;
6. candidate transport/topology changes only when their independent physical gates are actually qualified;
7. optional relay/SFU or multi-rendition eligibility only when retained encoder/scale evidence supports it;
8. at least a 30-minute adaptation/recovery soak for the final feasible scale point.

## Evidence

Initialize a result directory:

```powershell
.\phase10g-adaptive.ps1 -Mode Init -ReceiverCount 5 -ReceiverId student-01,student-02,student-03,student-04,student-05 -ResultsDir .\phase10g-5
```

Required:

```text
<ResultsDir>\teacher.log
<ResultsDir>\receivers\<receiver-id>.log
```

Optional but strongly recommended:

```text
<ResultsDir>\network.log
<ResultsDir>\topology.log
<ResultsDir>\recovery.log
<ResultsDir>\encoder.log
```

Then:

```powershell
.\phase10g-adaptive.ps1 -Mode ValidateEvidence -ResultsDir .\phase10g-5
```

The validator checks exact receiver correlation, non-empty evidence, and SHA-256 hashes. It deliberately keeps qualification and all production-default selections undetermined.

## Gate interactions

Phase 10G cannot override independent open gates:

- Phase 4 one-to-one UDP vs QUIC-Datagram selection;
- Phase 6F physical interactive-control validation;
- Phase 7D multicast viability / 7H classroom scale;
- Phase 8D Wi-Fi fan-out strategy;
- Phase 9F monitoring-grid physical qualification.

A candidate may remain blocked even if the adaptive-controller software behaves correctly.

## Results

Record reviewed conclusions in `docs/PHASE10_ADAPTIVE_RESULTS.md`. Hosted CI is software/tooling evidence only.
