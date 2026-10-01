# Phase 8D Physical Wi-Fi Qualification

Phase 8D is the physical evidence gate for selecting a Wi-Fi Teacher Presentation fan-out strategy. Hosted CI validates tooling only and **cannot** select the production strategy.

## Strategies under comparison

Run comparable physical evidence for:

- `direct-unicast`: Teacher sends one encoded rendition over one bounded path per receiver;
- `relay`: Teacher sends one encoded rendition to one local relay, which performs bounded per-receiver fan-out.

The relay baseline is topology-neutral. It does not require LiveKit, WebRTC or any specific SFU implementation. Introduce a concrete relay dependency only if retained physical evidence justifies it.

## Scale points

Execute the same strategy/profile at:

- 5 receivers;
- 10 receivers;
- 20 receivers;
- 30 receivers where hardware allows.

Do not infer unexecuted scale points.

## Required measurements

Retain, where measurable:

- Teacher uplink bitrate;
- per-client RTT, loss, jitter and reordering;
- sender/relay queue age, depth and drop count;
- end-to-end latency;
- Teacher and relay CPU/GPU/memory/handle usage;
- receiver decode/render health;
- weak-client degradation and recovery behavior;
- AP airtime/load/channel utilization;
- authenticated control-session liveness during media degradation;
- operational complexity and offline deployment requirements.

## Evidence workflow

Initialize one directory per strategy and scale point:

```powershell
.\phase8d-wifi.ps1 -Mode Init -Strategy direct-unicast -ReceiverCount 5 -ReceiverId student-01,student-02,student-03,student-04,student-05 -ResultsDir .\phase8d-direct-5
```

Preserve:

```text
<ResultsDir>\teacher.log
<ResultsDir>\receivers\<receiver-id>.log
<ResultsDir>\ap.log                      # optional when AP telemetry is available
```

Then validate evidence completeness and write a SHA-256 evidence index:

```powershell
.\phase8d-wifi.ps1 -Mode ValidateEvidence -ResultsDir .\phase8d-direct-5
```

The validator intentionally reports `strategy_selected=undetermined`.

## Decision requirements

Do not select a strategy unless reviewed physical evidence shows:

- healthy receivers remain isolated from weak-client degradation;
- queue age/depth remains bounded instead of accumulating latency;
- one encoded rendition is reused rather than encoding per receiver;
- control remains responsive while media degrades or recovers;
- resource usage remains stable without monotonic memory/handle growth;
- the selected topology is operationally supportable offline;
- comparisons use equivalent scale points, media profile and test duration.

A relay is not automatically preferred because its Teacher replication factor is one. Real Teacher uplink, AP airtime, relay resource cost, latency, reliability and operational complexity must all be considered.

## Results

Record reviewed observations in `docs/PHASE8_WIFI_PHYSICAL_RESULTS.md`. Missing scale points remain pending.
