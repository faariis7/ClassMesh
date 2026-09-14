# ClassMesh Testing Strategy

ClassMesh is a real-time systems project. Passing unit tests is necessary but not sufficient; every layer needs a failure/recovery test and measurable latency budget.

## 1. Test layers

### Pure unit tests

Run on every commit where CI is available:

- packet/header validation;
- frame packetization/reassembly;
- sequence wrapping and loss tracking;
- receiver NACK/stale-frame logic;
- bounded latest-frame queues;
- adaptation decisions;
- recovery/backoff state machines;
- Session Worker supervision;
- IPC framing/limits;
- encoder benchmark classification;
- keyframe coalescing and frame pacing.

### Windows integration tests

Require a Windows interactive session and cannot be trusted when run only in Session 0 CI:

- adapter/display enumeration;
- DXGI duplication creation;
- capture GPU texture acquisition;
- resolution/orientation changes;
- lock/unlock and secure desktop;
- monitor hot-plug;
- Media Foundation hardware encode/decode;
- D3D11 render path;
- WTS session events and Worker launch;
- Named Pipe ACL/peer validation.

### Two-machine media tests

Teacher + student Windows machines:

- 1080p30 high-motion source;
- latency growth over 30+ minutes;
- recovery after sender/receiver media restart;
- induced UDP loss/reordering/jitter;
- input responsiveness while video is degraded.

### Classroom scale tests

At 2/5/10/20/30 clients where equipment allows:

- wired unicast;
- wired multicast;
- multicast + unicast outliers;
- Wi-Fi direct unicast;
- optional Wi-Fi SFU/WebRTC fan-out;
- slow receiver and reconnect storm isolation.

## 2. Latency budget

Record separate timestamps for:

```text
capture -> GPU process -> encode -> sender queue -> network
        -> receiver reassembly/jitter -> decode -> render
```

A single `end_to_end_ms` value is not sufficient for debugging. Each stage reports p50/p95/max and drop counts.

The initial healthy-LAN engineering target is <100 ms end-to-end for 1080p30. This target is provisional and must not be achieved by hiding latency in an ever-growing buffer.

## 3. Soak requirements

For each production media backend:

- 30 minutes minimum during early milestones;
- multi-hour soak before release candidate;
- stable process memory;
- bounded queue depth;
- no monotonically increasing display delay;
- recovery counters remain explainable;
- no resource/handle growth across repeated capture/codec resets.

## 4. Network chaos profiles

Baseline synthetic profiles:

| Profile | Loss | Jitter | Reorder | Bandwidth |
|---|---:|---:|---:|---:|
| Healthy LAN | 0–0.1% | <2 ms | rare | ample |
| Mild congestion | 1% | 5–10 ms | low | 8–20 Mbps |
| Poor Wi-Fi | 3% | 20–40 ms | moderate | 3–8 Mbps |
| Recovery stress | 5% + bursts | 50+ ms | high | variable |

Expected behavior is quality degradation, frame drops and recovery—not device disconnect.

## 5. Session/display chaos

Exercise while media is active:

- Windows lock/unlock;
- user logoff/login;
- fast-user switch;
- console/RDP transition where supported;
- display resolution change;
- landscape/portrait rotation;
- primary monitor change;
- external monitor unplug/replug;
- display sleep/wake;
- machine sleep/resume;
- GPU/driver reset where reproducible.

The machine service remains alive. Media is allowed to enter `Suspended`/`Recovering`; control identity is not discarded.

## 6. Security tests

Before 1.0:

- malformed protocol lengths/types;
- oversized packet/message rejection;
- unauthorized discovery does not grant control;
- local IPC connection from an unexpected user/process is rejected;
- replay-sensitive commands are rejected/reconciled;
- fuzz media and control parsers;
- invalid update signature/digest rejection;
- multicast/unicast media cannot be joined/decrypted without authorized session material.

## 7. Performance regression gates

Track at least:

- capture FPS/p50/p95;
- GPU conversion p50/p95;
- encode FPS/p50/p95;
- sender queue age/drop count;
- bitrate/packets per second;
- RTT/loss/jitter/reorder;
- receiver queue age;
- decode FPS/p50/p95;
- render p50/p95;
- CPU/GPU usage;
- process memory/handles;
- recoveries by reason.

Changes that improve average quality while creating long p95 latency or queue buildup are regressions for interactive use.

## 8. Definition of a successful video test

A video test is successful only if the receiver is visually live **and** telemetry confirms:

- expected hardware backend;
- bounded queue depth/age;
- no hidden CPU bitmap path in teacher presentation;
- no steadily growing latency;
- appropriate frame drops under overload;
- recovery without terminating the device/control session.
