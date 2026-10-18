# Phase 10 — observed missing UDP sequence-ID counter

## Problem and source of truth

The live `UdpFrameReceiver` exposes `sequence_gaps_observed`, which counts **gap events**, not the number of sequence IDs skipped at those events. One gap skipping 100 packets and one gap skipping a single packet both incremented the old diagnostic by one. This was insufficient evidence for later per-receiver telemetry planning and could be misread as packet loss.

## Change

`UdpReceiverStats` now additionally carries saturating `missing_datagrams_observed` accumulated from `SequenceObservation::Gap { missing }`. The existing `sequence_gaps_observed` and `reordered_or_duplicate` counters remain unchanged. `UdpFrameReceiver::receive_once` records the three outcomes through one common helper. The existing `media_receiver` Windows diagnostic prints `sequence_missing_packets=` in both periodic and final lines while retaining all old fields. TDD RED verified absent counter/helper, GREEN verified a 4-packet and 2-packet gap produce two gap events and six observed missing sequence IDs, late packet does not erase a historical jump, and saturation at `u64::MAX` prevents wrapping. VM2 x64 full `classmesh-network` suite, `classmesh-worker` Clippy all-targets, rustfmt and exact-head hosted CI are required before merge.

## Correctness boundary

The number is a cumulative *observation of sequence-ID gaps*, **not** definitive network packet loss. Reordered packets can arrive later, a malicious sender may manipulate sequence IDs, and counts can include discontinuities from media stream restart. There is no validated RTT, accurate loss ratio, or authenticated per-student reporting channel in this change. Do not feed this counter as a precise loss percentage into `ReceiverQualityController`; transport and physical Wi-Fi qualification remain separate tasks. The change is Phase 10 only; no Phase 12 Service/security changes.
