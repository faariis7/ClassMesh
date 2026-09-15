# Phase 4 two-PC qualification results

Status: **PENDING PHYSICAL WINDOWS RUN**

Do not mark Phase 4 complete until this file contains measured results from two physical Windows PCs. Hosted CI results are not substitutes for the GPU/network acceptance gates.

## Test environment

- Date:
- Teacher PC model:
- Teacher CPU/GPU:
- Teacher Windows build:
- Teacher GPU driver:
- Student PC model:
- Student CPU/GPU:
- Student Windows build:
- Student GPU driver:
- Network: wired / Wi-Fi:
- Link speed:
- Switch/AP:
- Teacher IPv4:
- Student IPv4:
- ClassMesh commit:
- CI run/artifact source:

## Synthetic transport comparison

Workload: 60 s, 500 packets/s, 1000-byte application datagrams unless noted otherwise.

| Metric | UDP | QUIC Datagram |
|---|---:|---:|
| Attempted | pending | pending |
| Accepted | pending | pending |
| Effective loss | pending | pending |
| Send errors | pending | pending |
| RTT min ms | pending | pending |
| RTT avg ms | pending | pending |
| RTT p50 ms | pending | pending |
| RTT p95 ms | pending | pending |
| RTT p99 ms | pending | pending |
| RTT max ms | pending | pending |
| Notes | pending | pending |

QUIC-only path observations:

- congestion window:
- lost packets:
- lost bytes:
- congestion events:
- MTU:
- send-buffer behavior:

Initial unicast default decision: **PENDING**

Rationale:

## Live media baseline — healthy wired LAN

Duration: 120 s minimum.

- Student visibly renders continuous motion: pending
- Hardware H.264 encoder selected: pending
- Hardware H.264 decoder initialized: pending
- Presented frames:
- Decode errors:
- Present errors:
- Sequence gaps:
- NACK requests:
- Keyframe requests:
- Stale drops:
- Sender retransmits:
- Sender pool/rate drops:
- Proxy peak queue depth:
- Queue returned to zero/bounded: pending
- Observed latency behavior:
- End-to-end latency instrumentation status: pending
- `<100 ms` target demonstrated: **NOT YET MEASURED**

## Deterministic impairment matrix

| Profile | Duration | Loss | Jitter | Reorder | Video recovers | Queue bounded | Session preserved | Notes |
|---|---:|---:|---:|---:|---|---|---|---|
| Baseline | 120 s | 0% | 0 ms | 0% | pending | pending | pending | |
| Mild | 120 s | 1% | 5 ms | 1% | pending | pending | pending | |
| Poor | 120 s | 3% | 20 ms | 3% | pending | pending | pending | |
| Stress | 120 s | 5% | 40 ms | 5% | pending | pending | pending | |

For each profile, retain the Teacher sender, Teacher proxy, and Student receiver logs from `phase4-results`.

## GPU media recovery injection

- `--recover-after-frames` value: 300
- Recovery triggered: pending
- Stream resumed without process restart: pending
- GPU recoveries:
- Forced GPU recoveries:
- Last recovery ms:
- Longest recovery ms:
- Decode/present errors around recovery:
- Notes:

## 30-minute soak

Profile: 3% loss, 20 ms jitter, 3% reorder, 20 ms reorder delay, seed 42.

- Full 1800 s completed: pending
- Continuous live presentation: pending
- No steadily increasing display delay: pending
- Proxy queue bounded: pending
- Receiver queues/recovery bounded: pending
- Sender in-flight/pool bounded: pending
- Process memory stable enough for Phase 4 gate: pending
- Handle/resource growth observed: pending
- Device/control session remained alive: pending
- Final notes:

## Phase 4 exit checklist

- [ ] 1080p30 teacher motion renders on the second Windows PC.
- [ ] Healthy wired-LAN latency target is measured and `<100 ms`, or missing instrumentation is explicitly tracked as a blocking task.
- [ ] No steadily increasing latency during the 30-minute run.
- [ ] 1%, 3%, and 5% impairment runs degrade/recover without losing the device/control session.
- [ ] UDP and QUIC Datagram results are recorded.
- [ ] Final unicast default is chosen from measured evidence.
- [ ] Issue #3 is updated with the result summary and relevant logs/commit.

Final Phase 4 result: **PENDING**