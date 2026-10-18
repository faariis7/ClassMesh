# Phase 9 — monitoring scheduler bounded fairness

## Reproduced defect

A continuously due `Visible` thumbnail takes precedence over every `Background` source, every poll. With a one-action budget, visible at 2 FPS and polls 500 ms apart, the previous scheduler never selected any background source. A regression demonstrated starvation even after 16 polls. This is a scheduler-level defect, not a GPU, network or UI benchmark claim.

## Scoped correction

Leave interactive promotion in the existing highest-priority pass. For the **thumbnail-only** remainder, preserve normal visible-first scheduling for the first three capacity-bearing polls where background work is due but not selected; on the fourth, reserve **at most one** background action before normal visible-first selection fills the remaining budget. Background candidates retain due-time/ID ordering, and the skipped-poll counter resets whenever any background thumbnail runs or none is due. Max actions per poll and FPS-based next-due logic remain unchanged. No network protocol, authorization or ClassMesh Service changes.

## Evidence / gates

- RED: visible source selected forever, failing the 4-poll progress and 16-poll rotation tests on VM1.
- GREEN: single-source priority, bounded background progress, multi-background rotation, high-load 40-device grid with budget 4, and precedence of interactive promotion.
- Native Rust package suite, format and Clippy plus GitHub hosted Portable/Windows checks required before merge.

## Not yet qualified

This scheduler policy cannot by itself prove 5/10/20/30-device real Wi-Fi performance, streaming-frame fairness on the wire, GPU effects, or physical two-machine behavior. Those require separate hardware evidence per the roadmap.
