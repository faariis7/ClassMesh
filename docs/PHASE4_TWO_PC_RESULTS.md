# Phase 4 two-PC qualification results

Status: **PENDING PHYSICAL WINDOWS RUN**

Preliminary Parallels run completed on 2026-09-19. The synthetic UDP and QUIC
Datagram benchmark ran between two Windows 11 ARM virtual machines and produced
the measurements below. This is useful diagnostic evidence, but it is not the
required physical two-PC acceptance run. Live media qualification was blocked
before the first encoded frame because the Parallels virtual GPU exposed neither
a usable Media Foundation hardware H.264 encoder nor a D3D11-aware hardware H.264
decoder. Latency, impairment recovery, GPU recovery, and soak results therefore
remain **not measured**.

A 2026-09-20 Parallels configuration audit confirmed both VMs already use the
Parallels video adapter with `3d-acceleration=highest`, automatic video memory,
and Parallels Tools 27.0.0-58628. The missing Media Foundation hardware
transforms are therefore not explained by disabled VM 3D acceleration; no
supported VM setting was identified that could turn this into the required
physical-GPU qualification.

Do not mark Phase 4 complete until this file contains measured results from two physical Windows PCs. Hosted CI results are not substitutes for the GPU/network acceptance gates.

## Test environment

- Date: 2026-09-19
- Teacher PC model: Parallels ARM Virtual Machine (`AHMEDBINHAMF460`)
- Teacher CPU/GPU: Apple Silicon / Parallels Display Adapter (WDDM), Virtual Adapter, 2 GiB reported
- Teacher Windows build: Windows 11 Pro 10.0.26200 (build 26200)
- Teacher GPU driver: 20.18.2700.58628
- Student PC model: Parallels ARM Virtual Machine (`TEST1`)
- Student CPU/GPU: Apple Silicon / Parallels Display Adapter (WDDM), Virtual Adapter, 2 GiB reported
- Student Windows build: Windows 11 Pro 10.0.26200 (build 26200)
- Student GPU driver: 20.18.2700.58628
- Network: Parallels virtual LAN on one macOS host; not a physical wired-LAN qualification
- Link speed: both guests report 10 Gbps VirtIO Ethernet
- Switch/AP: Parallels virtual network
- Teacher IPv4: 192.168.100.215
- Student IPv4: 192.168.100.203
- ClassMesh commit: `27f97bfb3e07d9a7e06479cde76d2a14098faa64`
- CI run/artifact source: CI #353 / run 35460059684; `classmesh-phase4-qualification-windows-x64` artifact 10588923268; GitHub digest `sha256:02b47e78c1c809b763cc65179d636a5980fcf2e1abf6f5fcd9eeab15e8dbebb4`

## Synthetic transport comparison

Workload: 60 s, 500 packets/s, 1000-byte application datagrams unless noted otherwise.

| Metric | UDP | QUIC Datagram |
|---|---:|---:|
| Attempted | 13,187 | 11,398 |
| Accepted | 13,187 | 11,398 |
| Effective loss | 0.00% | 0.00% |
| Send errors | 0 | 0 |
| RTT min ms | 0.12 | 0.38 |
| RTT avg ms | 3.69 | 2.78 |
| RTT p50 ms | 2.58 | 1.83 |
| RTT p95 ms | 10.80 | 7.31 |
| RTT p99 ms | 21.49 | 15.98 |
| RTT max ms | 106.05 | 81.92 |
| Notes | Valid 60 s client run with 90 s server guard; actual attempted count was below the nominal 30,000 packets | Valid 60 s client run with 90 s server guard; actual attempted count was below the nominal 30,000 packets |

QUIC-only path observations:

- congestion window: 22,713 bytes at the final sampled client path observation
- lost packets: 0
- lost bytes: 0
- congestion events: 0
- MTU: 1452
- send-buffer behavior: final sampled space 4,194,272 bytes; no application send errors

Initial unicast default decision: **PENDING — do not choose from same-host VM evidence**

Rationale: QUIC had lower RTT percentiles in this preliminary virtual run, but
both guests shared one physical host and the requested packet rate was not
achieved. Live hardware media could not start. The physical hardware gate and a
production default decision remain open.

## Live media baseline — healthy wired LAN

Duration: 120 s minimum.

- Student visibly renders continuous motion: no; stream never started
- Hardware H.264 encoder selected: no — Teacher returned `NoHardwareEncoder`
- Hardware H.264 decoder initialized: no — Student returned `0x80004005` while activating a D3D11-aware H.264 decoder
- Presented frames: 0
- Decode errors: initialization failed before frame decode
- Present errors: not measured
- Sequence gaps: not measured
- NACK requests: not measured
- Keyframe requests: not measured
- Stale drops: not measured
- Sender retransmits: not measured
- Sender pool/rate drops: not measured
- Proxy peak queue depth: 0; no media datagrams were produced
- Queue returned to zero/bounded: not applicable to a live stream
- Observed latency behavior: not measured

## Glass-to-glass latency measurement

Source: `tools/phase4-latency-source.html` displayed fullscreen on Teacher and carried through the normal ClassMesh capture/encode/network/decode/render path.

Measurement method: common-camera frame containing both physical displays; latency sample = Teacher elapsed-ms value minus Student rendered elapsed-ms value.

- Camera/device:
- Camera frame rate:
- Number of readable samples (minimum 20):
- Warm-up before sampling:
- Glass-to-glass min ms:
- Glass-to-glass p50 ms:
- Glass-to-glass p95 ms:
- Glass-to-glass max ms:
- Estimated measurement uncertainty:
- Healthy wired-LAN p95 `<100 ms`: **NOT YET MEASURED**
- Notes: Teacher latency source launched successfully, but the hardware encode/decode path could not start. No common-camera samples were taken.

Optional raw samples:

| Sample | Teacher ms | Student ms | Difference ms |
|---:|---:|---:|---:|
| 1 | pending | pending | pending |
| 2 | pending | pending | pending |
| 3 | pending | pending | pending |

## Deterministic impairment matrix

| Profile | Duration | Loss | Jitter | Reorder | Video recovers | Queue bounded | Session preserved | Notes |
|---|---:|---:|---:|---:|---|---|---|---|
| Baseline | 120 s requested | 0% | 0 ms | 0% | not measured | not measured | not measured | Sender and receiver initialization failed before media traffic; proxy received 0 datagrams |
| Mild | 120 s | 1% | 5 ms | 1% | not measured | not measured | not measured | Blocked by missing hardware H.264 path in Parallels |
| Poor | 120 s | 3% | 20 ms | 3% | not measured | not measured | not measured | Blocked by missing hardware H.264 path in Parallels |
| Stress | 120 s | 5% | 40 ms | 5% | not measured | not measured | not measured | Blocked by missing hardware H.264 path in Parallels |

For each profile, retain the Teacher sender, Teacher proxy, and Student receiver logs from `phase4-results`.

## GPU media recovery injection

- `--recover-after-frames` value: 300
- Recovery triggered: no — standalone recovery probe failed during initial decoder activation
- Stream resumed without process restart: not measured
- GPU recoveries: not measured
- Forced GPU recoveries: not measured
- Last recovery ms: not measured
- Longest recovery ms: not measured
- Decode/present errors around recovery: not measured
- Notes: `classmesh-media-recovery-probe.exe --cycles 10 --pause-ms 250` returned the same D3D11-aware decoder activation error `0x80004005` before cycle 1

## 30-minute soak

Profile: 3% loss, 20 ms jitter, 3% reorder, 20 ms reorder delay, seed 42.

- Full 1800 s completed: no
- Continuous live presentation: not measured
- No steadily increasing display delay: pending
- Visual latency near start — p50/p95/max ms:
- Visual latency near midpoint — p50/p95/max ms:
- Visual latency near end — p50/p95/max ms:
- Proxy queue bounded: not measured
- Receiver queues/recovery bounded: not measured
- Sender in-flight/pool bounded: not measured
- Process memory stable enough for Phase 4 gate: not measured
- Handle/resource growth observed: not measured
- Device/control session remained alive: not measured
- Final notes:

Not run in Parallels because the prerequisite live hardware media path failed to
initialize. A 30-minute process run with zero encoded frames would not measure
display-delay growth and must not be reported as a soak pass.

## Phase 4 exit checklist

- [ ] 1080p30 teacher motion renders on the second Windows PC.
- [ ] Healthy wired-LAN glass-to-glass p95 is measured below 100 ms using the documented common-camera method or a more accurate equivalent.
- [ ] No steadily increasing latency during the 30-minute run.
- [ ] 1%, 3%, and 5% impairment runs degrade/recover without losing the device/control session.
- [ ] UDP and QUIC Datagram results are recorded.
- [ ] Final unicast default is chosen from measured evidence.
- [ ] Issue #3 is updated with the result summary and relevant logs/commit.

Final Phase 4 result: **PENDING**
