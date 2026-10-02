# Phase 9F Monitoring Grid Qualification

Phase 9F validates the low-cost classroom monitoring grid at realistic device counts. Hosted CI proves deterministic software invariants and the evidence tooling only; it is **not** physical classroom performance evidence.

## Scale points

Run physical monitoring qualification at:

- 5 students;
- 10 students;
- 20 students;
- 30 students where hardware allows.

Do not infer an unexecuted scale point.

## Monitoring bounds

The run must remain inside the Phase 9 monitoring contract:

- thumbnail target no larger than 640×360;
- 2–5 FPS;
- no full-resolution monitoring stream for tiny tiles;
- selected-student full-resolution work must use the existing interactive path instead of increasing the monitoring profile.

## Required observations

Retain enough evidence to review:

- Teacher grid responsiveness and update cadence;
- per-student thumbnail freshness;
- aggregate monitoring network throughput;
- Teacher CPU/GPU/memory/handle usage;
- Student CPU/GPU/memory where measurable;
- bounded scheduler/fan-in queue behavior and dropped/superseded update counts;
- authenticated control responsiveness while the grid is busy;
- selected-student promotion latency and return to thumbnail mode;
- evidence that one delayed/weak monitoring source does not stall healthy sources;
- confirmation that monitoring targets remain low-resolution.

## Synthetic baseline

The portable benchmark exercises the production scheduler and fan-in contracts:

```text
classmesh-monitoring-grid-benchmark --sources 30 --rounds 30
```

It must report `physical_classroom=false` and `physical_qualification=false`. It cannot close this gate.

## Physical evidence workflow

Initialize one directory per scale point:

```powershell
.\scripts\phase9f-monitoring.ps1 -Mode Init -ReceiverCount 5 -ReceiverId student-01,student-02,student-03,student-04,student-05 -ResultsDir .\phase9f-5
```

Preserve:

```text
<ResultsDir>\teacher.log
<ResultsDir>\receivers\<receiver-id>.log
<ResultsDir>\network.log       # optional when separately captured
<ResultsDir>\teacher-ui.log    # optional UI/grid telemetry or observation log
```

Validate completeness and write SHA-256 evidence references:

```powershell
.\scripts\phase9f-monitoring.ps1 -Mode ValidateEvidence -ResultsDir .\phase9f-5
```

The validator intentionally leaves `qualification_passed=null`.

## Exit review

Phase 9 can be considered physically qualified only after retained evidence shows the classroom grid remains responsive at the required scale, control traffic remains responsive, weak sources stay isolated, and full-resolution streams are not created merely to render monitoring tiles.
