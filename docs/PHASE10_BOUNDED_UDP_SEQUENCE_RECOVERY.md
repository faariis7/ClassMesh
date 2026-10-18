# Phase 10 — bounded UDP sequence-gap recovery memory

## Reproduced streaming reliability problem

`classmesh-network::reliability::SequenceTracker` previously inserted up to 4096 missing sequence IDs **per gap**, without removing older misses when `highest` advanced. A long-lived, lossy or adversarial UDP receiver could therefore accumulate unbounded `BTreeSet` entries. Large single jumps also tracked the oldest missing packets, even though later packets have a better chance of being recovered before the real-time deadline.

## Scoped correction

Retain only missing sequence IDs whose wrapping age from the most recently accepted highest sequence is in `1..=4096`. Evict expired gaps during both in-order advances and forward gap jumps. A large jump records the most recent 4096 missing sequence IDs, rather than the oldest 4096. Existing `SequenceObservation::{First,InOrder,Gap{missing},ReorderedOrDuplicate}` public semantics, packet/frame parsing, control protocol and user-facing media transport are unchanged. Packets arriving late within this finite window still clear missing entries, including across `u32::MAX` wrapping; older packets are classified as reordered/duplicate without retention.

## TDD and qualification

VM2 Windows x64 native RED demonstrated 8192 stored missing IDs after two consecutive 4096-packet gaps and an incorrectly old missing range after one >4096-packet jump. GREEN checks repeated 50 gaps, missing-ID memory bound, large jumps, late recovery across wraparound and eventual expiration under subsequent in-order traffic. The full `classmesh-network` Rust suite, rustfmt, and Clippy with warnings denied are required before merge; exact-head GitHub CI and review are additional gates.

This fixes memory growth in an existing production UDP media receiver; it **does not** create a live `ReceiverFeedback` sender or production per-client timer, nor qualify physical Wi-Fi scenarios. Actual network and GPU hardware tests remain open. No Phase 12 Service authorization/root/epoch changes.
