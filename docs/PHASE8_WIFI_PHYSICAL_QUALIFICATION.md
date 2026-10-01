# Phase 8D Physical Wi-Fi Fan-Out Qualification

Phase 8D selects a Wi-Fi Teacher Presentation fan-out strategy from retained **physical** evidence. Hosted CI and the Phase 8B synthetic baseline cannot close this gate.

Phase 8C remains conditional: add a relay/SFU benchmark adapter only if the direct physical baseline or operational requirements show that a comparable relay/SFU measurement is necessary.

## Scale points

Execute each candidate strategy at the feasible checkpoints:

- 5 receivers;
- 10 receivers;
- 20 receivers;
- 30 receivers.

Do not infer an unexecuted checkpoint from a smaller run.

## Scenarios

For each feasible receiver count, retain separate runs for:

1. `healthy` — all receivers on a healthy Wi-Fi path;
2. `weak-receiver` — one explicitly identified weak client while healthy receivers continue;
3. `reconnect` — receiver disconnect/reconnect churn without collapsing healthy clients or control sessions;
4. `soak` — at least 30 minutes during early qualification.

## Evidence harness

Initialize one run:

```powershell
.\phase8-wifi-scale.ps1 -Mode Init -Scenario healthy -ReceiverCount 5 `
  -ReceiverId student-01,student-02,student-03,student-04,student-05 `
  -Strategy direct-unicast -RunId wifi-direct-5-healthy-001
```

For a weak-client run:

```powershell
.\phase8-wifi-scale.ps1 -Mode Init -Scenario weak-receiver -ReceiverCount 5 `
  -ReceiverId student-01,student-02,student-03,student-04,student-05 `
  -WeakReceiverId student-01 -Strategy direct-unicast -RunId wifi-direct-5-weak-001
```

Use `-ApEvidenceExpected` when the access point exposes airtime/load telemetry that can be retained.

Required files are correlated by the manifest:

```text
teacher.log
physical-observations.md
receivers/<receiver-id>.log
ap.log                        # only when requested
```

Then verify the evidence set:

```powershell
.\phase8-wifi-scale.ps1 -Mode ValidateEvidence -ResultsDir .\phase8-wifi-results
```

The validator checks evidence presence/correlation only. It intentionally reports both qualification and strategy selection as `undetermined`.

## Required measurements

Retain, where available:

- Teacher uplink bitrate/packets per second;
- per-client RTT, loss, jitter and reorder;
- per-receiver sender queue depth/age/drop count;
- end-to-end latency and decode/render FPS where measurable;
- Teacher CPU/GPU/memory/handle counts;
- recovery/keyframe behavior;
- control-session liveness during media degradation;
- AP airtime/load/channel metrics where measurable;
- reconnect/recovery counters and human-visible observations.

## Selection rule

Do not choose direct UDP, QUIC Datagram, WebRTC, or an SFU from hosted CI, the synthetic baseline, or one small physical run.

A strategy may be selected only after reviewed physical evidence across the feasible scale matrix shows acceptable healthy-client isolation, bounded latency/queues, sustainable Teacher/AP load, recoverability, and deployability. Any optional SFU must remain self-hostable/offline-operable and must demonstrate a measured benefit that justifies its operational cost.

Phase 4 Issue #3, Phase 6F Issue #108, and Phase 7 physical gates remain independent.
