# Phase 10 — measured receiver interval diagnostics

## Scope and data provenance

`UdpFrameReceiver::stats()` exposes cumulative transport counters from packets that its socket actually received and frames that its assembly window completed. The `UdpReceiverIntervalSampler` calculates the **difference** between two monotonic cumulative snapshots, never reusing a lifetime total as a per-second rate. It records elapsed microseconds, received datagrams, completed frames, sequence gap events, historically observed missing sequence IDs, and reordered/duplicate arrivals. Derived frames/sec and datagrams/sec use the observed interval duration.

`classmesh-media-receiver` now prints a separate `receiver measured interval` line for its existing roughly once-per-second diagnostic cycle, without changing its original cumulative lines. Shorter-than-100ms intervals are coalesced into the next report; equal timestamps do not emit fabricated intervals; a regressing clock or any decreased/reset counter drops that interval and rebaselines the next one. The sampler retains **one** snapshot, never a history of packets, and performs bounded work per snapshot.

## Tests and evidence

TDD RED: missing sampler type; GREEN on VM2 Windows x64. Regression coverage includes 1-second measured packet and frame rates, differing gap-event vs missing-sequence-ID totals, same-time/short-window coalescing, full reset of a receiver instance, clock regression, and a real UDP loopback sender/receiver delivering a packetized frame and observing exactly the sent packet count. Native `classmesh-network` suite 77/77, warnings-denied Clippy on network + worker, rustfmt and diagnostic binary smoke at --listen 127.0.0.1:0 --seconds 2 passed. Exact-head GitHub Portable Rust and Windows Build CI required before merge.

## Critical limits

This diagnostic source reflects **one explicitly instantiated receiver socket**, not an authenticated multi-student telemetry feed. The current media-receiver binary is a diagnostic utility, not the classroom-wide Service receiver controller. `missing_sequence_ids` are historical sequence jumps rather than confirmed irreversible packet loss. No authenticated per-client ID, measured RTT, reliable packet-loss percentage, GPU render FPS, or session-bound network telemetry channel is introduced or claimed. Real Service/Teacher periodic integration and physical Wi-Fi qualification still require a separate design and testing. No Phase 12 security/epoch/authorization changes.
