# Phase 10 — bound protected-media candidate receive statistics

## Target actual protected receivers

The Windows Student Worker instantiates `ProtectedUnicastFrameReceiver` and `ProtectedMulticastFrameReceiver`, each configured with the expected teacher sender and session stream ID by the Service. The shared `ProtectedMediaReceiveState` checks sender, protocol version, stream ID, ciphertext frame packet-count bound, disallowed retransmission/FEC flags, and assembler admission before returning a candidate ciphertext frame.

## New counters and limits

`ProtectedMediaReceiveStats` is a small, saturating, one-struct snapshot per *receiver instance*. It exposes `candidate_datagrams` after these structural admission checks, `rejected_datagrams` after a parsed datagram fails them or assembly, `assembled_ciphertext_frames` from the bounded assembly window, and `stale_frames_dropped` from both receive batches and periodic timeout ticks. Unicast and multicast state and socket receiver getters share identical logic through the existing common protected-media core. No new transport payloads or background tasks. It does not count malformed datagrams rejected at the socket parser before this state (those have a separate outcome), so the counts are NOT a complete on-wire traffic accounting.

**Security caveat:** candidate frames have NOT yet passed ciphertext authentication/decryption at this layer. A source IP and stream ID are not cryptographic identity. Never use `candidate_datagrams` or `assembled_ciphertext_frames` as trusted receiver quality evidence or grant them authority to reconfigure a stream. Downstream Worker crypto verification and session ownership are a separate integration/qualification gate.

## Tests and deployment scope

TDD RED: protected unicast state had no `stats` method. GREEN: unicast regression injects wrong stream and wrong sender, then reconstructs a three-datagram ciphertext frame; only admissible candidates count. Timer expiry of an incomplete frame counts as a stale frame, not a confirmed network packet loss. VM2 Windows x64 native full `classmesh-network` suite **78/78**, `classmesh-worker` unit/integration suites (75+4+3+23) and Clippy `-D warnings` for network and worker all targets succeeded. Exact-head hosted GitHub Portable/Windows CI required before merge. No test on separate physical Windows PCs yet, and no Service/Teacher new telemetry channel is claimed. No Astra Phase12 files touched.
