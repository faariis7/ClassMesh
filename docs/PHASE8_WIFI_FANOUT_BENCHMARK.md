# Phase 8 Wi-Fi Fan-Out Synthetic Baselines

These benchmarks exercise comparable one-rendition fan-out topologies before physical Wi-Fi testing.

They are intentionally **synthetic**. Green results prove bounded queue isolation and shared encoded-frame behavior in software. They do not prove Wi-Fi airtime, latency, RF behavior, access-point capacity, real Teacher uplink bitrate, or select UDP/QUIC/WebRTC/SFU.

## Direct baseline — Phase 8B

The direct baseline reuses the production `FrameDistributor`:

- one `SharedEncodedFrame` allocation is published to all receiver sinks;
- each receiver has its own bounded `SinkMode::Unicast` queue;
- healthy receivers drain every frame;
- one configured weak receiver drains less frequently;
- queue drops and maximum queue depth are reported per receiver;
- current-frame deliveries are checked with `Arc::ptr_eq` against the published allocation.

Run:

```powershell
.\classmesh-wifi-fanout-benchmark.exe --strategy direct-unicast --receivers 5 --frames 120
```

The synthetic topology reports `teacher_uplink_replication_factor=N` for N direct receiver paths. This is a topology factor, **not measured bitrate**.

## Relay baseline — Phase 8C

The relay baseline uses the same benchmark plan, frame generator, queue capacity and weak-receiver drain policy as the direct baseline, but models:

```text
Teacher -> one relay input -> bounded per-receiver relay fan-out
```

Run:

```powershell
.\classmesh-wifi-fanout-benchmark.exe --strategy relay --receivers 5 --frames 120
```

The relay report includes:

```text
mode=synthetic-relay-fanout
physical_wifi=false
strategy_selection=false
teacher_uplink_replication_factor=1
teacher_frames_to_relay=...
teacher_payload_bytes=...
relay_frames_published=...
shared_allocation_mismatches=0
receiver=student-01 delivered=... queue_dropped=... max_queued=... queued_at_end=...
```

This is a dependency-neutral relay topology model. It is deliberately **not** a LiveKit, WebRTC or other SFU integration. A real relay/SFU dependency should be introduced only if physical evidence shows that a relay path is worth the deployment and operational cost.

## Comparable synthetic invariants

For both strategies:

- supported receiver counts are 5, 10, 20 and 30;
- the intentionally weak receiver accumulates bounded drops;
- healthy receivers have zero queue drops in the default synthetic profile;
- no receiver exceeds its configured queue capacity;
- healthy receiver queues do not inherit the weak receiver backlog;
- one encoded payload allocation is reused inside the fan-out boundary.

For the relay baseline specifically:

- Teacher sends one synthetic frame into the relay per published frame;
- the relay fans that shared frame to bounded receiver queues;
- `shared_allocation_mismatches=0` verifies that the synthetic relay boundary does not create per-receiver encoded copies.

## What remains for Phase 8D

Physical Wi-Fi runs must still retain 5/10/20/30-client evidence where hardware allows, including:

- measured Teacher uplink bitrate;
- AP airtime/load where measurable;
- RTT/loss/jitter/reorder;
- queue age/depth/drop rate;
- end-to-end latency where measurable;
- CPU/GPU/memory/handles;
- weak-client recovery behavior;
- operational complexity and offline deployment requirements.

Do not select the final Wi-Fi fan-out strategy from these synthetic benchmarks or hosted CI.
