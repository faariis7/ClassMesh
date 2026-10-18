# Phase 10 — fresh receiver telemetry and per-client quality isolation

## Reproduced regression

The receiver quality controller verified increasing sequence numbers but allowed multiple accepted observations with an identical `observed_at_us`. A receiver could therefore advance recovery hysteresis with duplicate-time samples rather than three independent fresh observations, making an unhealthy stream appear recovered too soon.

## Change and guarantees

A valid observation now requires both a strictly increasing sequence number **and** an observation timestamp strictly later than the last accepted timestamp. Equal timestamps are classified as `NonMonotonicObservationTime`, do not advance the accepted sequence, and do not contribute toward healthy quality recovery. Other stale/invalid telemetry behavior remains fail-closed. The receiver-specific controller and tier hysteresis are unchanged.

Tests inject a severe renderer failure, then duplicate timestamps with new sequence numbers; require three genuinely fresh healthy samples after invalid attempts before recovery. A separate three-receiver cohort regression combines RTT 250 ms and packet loss 15% on receiver 3, confirms degradation respects the two-sample hysteresis, verifies the other two receivers stay High and distinct, and proves duplicated-time samples cannot prematurely rejoin High.

## Qualification limits

This is pure Rust scheduling and profile adaptation; it does not select real physical transport or qualify packet capture, on-wire congestion, measured 5/10/20/30-device network performance, or two physical Windows PCs. Native VM1/VM2 package tests, warnings-denied Clippy and exact-head hosted Portable Rust/Windows CI are required before merging.
