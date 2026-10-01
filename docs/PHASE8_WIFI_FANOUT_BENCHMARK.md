# Phase 8B Direct Wi-Fi Fan-Out Synthetic Baseline

This benchmark exercises the direct one-rendition fan-out boundary before physical Wi-Fi testing.

It is intentionally **synthetic**. A green result proves bounded queue isolation and shared encoded-frame allocation in software. It does not prove Wi-Fi airtime, latency, RF behavior, access-point capacity, or select UDP/QUIC/WebRTC/SFU.

## What it exercises

The benchmark reuses the production `FrameDistributor`:

- one `SharedEncodedFrame` allocation is published to all receiver sinks;
- each receiver has its own bounded `SinkMode::Unicast` queue;
- healthy receivers drain every frame;
- one configured weak receiver drains less frequently;
- queue drops and maximum queue depth are reported per receiver;
- current-frame deliveries are checked with `Arc::ptr_eq` against the published allocation.

Supported receiver counts match the Phase 8A evidence contract: 5, 10, 20 and 30.

## Run

```powershell
.\classmesh-wifi-fanout-benchmark.exe --receivers 5 --frames 120
```

Example output fields:

```text
mode=synthetic-direct-fanout
physical_wifi=false
strategy_selection=false
receivers=5
frames_published=120
shared_allocation_mismatches=0
receiver=student-01 delivered=... queue_dropped=... max_queued=... queued_at_end=...
```

## Expected synthetic behavior

For the default configuration:

- `shared_allocation_mismatches=0`;
- the intentionally weak receiver accumulates bounded drops;
- healthy receivers have zero queue drops;
- no receiver exceeds its configured queue capacity;
- healthy receiver queues are drained without inheriting the weak receiver backlog.

## What remains for Phase 8D

Physical Wi-Fi runs must still retain 5/10/20/30-client evidence where hardware allows, including Teacher uplink, AP airtime/load where measurable, RTT/loss/jitter, queue age/depth/drop rate, end-to-end latency where measurable, CPU/GPU/memory/handles, and weak-client recovery behavior.

Do not select the final Wi-Fi fan-out strategy from this synthetic benchmark or hosted CI.
