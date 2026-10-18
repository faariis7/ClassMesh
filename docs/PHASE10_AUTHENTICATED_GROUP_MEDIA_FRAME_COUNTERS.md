# Phase 10 — authenticated Worker media frame metrics

## Scope and trust boundary

The real Windows Student Worker receives encrypted presentation ciphertext through a per-session protected Unicast/Multicast receiver. Only `WorkerGroupMediaKeyState::open_frame` calls the configured `GroupMediaReceiver::open_bound_frame`, verifying the binding, AEAD tag, key epoch and replay rules. The new `WorkerGroupMediaAuthenticationStats` counts **successful cryptographic opens** separately from rejects at that same guarded step, not simply candidate ciphertext packets from the transport receiver. It does not imply H.264 decode or successful GPU presentation.

A snapshot is available only while a key is installed. Its saturating `opened_frames` and `rejected_frames` counters are scoped to the active presentation key epoch and reset on successful key installation/rotation or matching key clear. An unauthorized binding change or stale epoch install fails without resetting the installed receiver or accumulated metrics. An opening attempt without any installed key is not counted as having been authenticated or rejected under a key. No sensitive key bytes, plaintext, receiver identity or per-frame payloads are retained as telemetry.

## TDD / evidence

Test-first RED (missing authentication_stats method), followed by native Windows x64 GREEN. Regression generates real sealed ciphertext using GroupMediaSender, confirms exactly one verified open, rejects replay of that frame and ciphertext sealed under the wrong key, confirms subsequent valid frame still opens, then verifies key rotation resets epoch-scoped counts and matching key clear removes them. Full classmesh-worker native tests and Clippy all-targets `-D warnings` and GitHub exact-head Portable Rust / Windows Build CI are required before squash merge.

## Limits

Stats are local Worker evidence behind an already installed key, **not** yet a session-bound authenticated telemetry report sent to Teacher/Service. A separate, versioned authenticated channel with revocation/rate limits and per-receiver ownership is required before these metrics can drive adaptive stream policy. This change is Phase 10 only; it does not modify protocol, Windows Service policy authority, Astra Phase12 root trust or epoch persistence.
