# ADR-0007: Dedicated Media Threads and Bounded Backpressure

Status: Accepted

## Context

Desktop Duplication, D3D11 immediate contexts, hardware encoders and renderers have thread-affinity/concurrency expectations. Allowing UI callbacks, network tasks and multiple capture requests to touch the same graphics state creates invalid-call races and makes latency unpredictable.

Real-time media also fails badly when producers are allowed to build unbounded queues. A 30 FPS capture source feeding a temporarily slower encoder must lose frames, not become seconds behind live.

## Decision

### Graphics ownership

Each active capture/encode pipeline has a dedicated media/graphics execution context. D3D11 immediate-context access is serialized by ownership rather than shared opportunistically across arbitrary async tasks.

Suggested logical stages:

```text
Capture/Graphics owner
        |
        v
bounded latest-frame handoff
        |
        v
GPU process / encoder owner
        |
        v
bounded encoded-frame distributor
        |
        +--> multicast sender
        +--> unicast sender(s)
        `--> optional SFU uplink
```

Receiver:

```text
network receive
      |
      v
bounded packet/frame window
      |
      v
decoder owner
      |
      v
bounded latest-decoded-frame handoff
      |
      v
GPU renderer
```

### Backpressure rule

No unbounded channel is permitted in a live media hot path.

Initial limits are intentionally small:

- capture → process/encode: ~2 frames;
- encoded distributor: ~2–3 frames;
- receiver incomplete-frame window: ~3 frames;
- retransmission cache: short count/time bound.

When full, old media is evicted. Control/file-transfer queues use different reliability rules and must not be implemented with the live-media drop policy.

### Timing

Frame pacing emits the newest appropriate frame. It never sends a burst of obsolete frames to compensate for missed deadlines.

## Consequences

- GPU APIs have deterministic owners.
- Invalid concurrent `AcquireNextFrame`/immediate-context usage is avoided by design.
- Overload is visible as drop counters rather than growing latency.
- UI responsiveness is independent from capture/encode loops.
- Transport fan-out consumes encoded frames but cannot block the encoder indefinitely.
