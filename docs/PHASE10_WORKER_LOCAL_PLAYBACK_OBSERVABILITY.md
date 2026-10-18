# Phase 10 — local Worker playback observability

## Why this is required

Earlier Phase 10 work established three distinct evidence layers: UDP receive/assembly, structurally accepted protected ciphertext, and AEAD-verified Worker group-media frame opens. However, the actual Worker decoder/presenter path could not correlate its decoding, waiting-for-keyframe and render failures with authenticated frame counts. A successful AEAD open does not prove decoding or visible presentation.

## Bounded, session-scoped diagnostic

`PresentationDeliveryTelemetry` keeps constant-size, saturating counters for `PresentationDecodeStep::{Decoded, WaitingForKeyframe}`, decoder submission errors, and decoded/presented/presentation-error counts from real `PresentationDecodeBatch` outcomes. The existing Worker event loop records these outcomes only for frames admitted through the current presentation key binding. Every five monotonic seconds while exactly one protected presentation receiver and decoder remain active, it emits a **local diagnostic log line** combining this data with the existing `WorkerGroupMediaAuthenticationStats` and receiver event-queue drop count. The report includes only numeric presentation/stream/key-epoch IDs and aggregate counters; no frame content or key material. Decode and presentation counts never masquerade as authenticated frames, and encrypted frames never masquerade as displayed frames.

The tracker resets on a change of exact `PresentationKeyInstallBinding` (including key epoch), matching presentation key clear, receiver replacement, and media-local pipeline teardown. Nothing is persisted. The authentication snapshot belongs to the installed key epoch; the event queue drop counter belongs to the corresponding receiver runtime lifetime and is labeled `queue_drop_events_total`, not a per-epoch count. No control-plane payload, transmission, privilege, policy, or Phase 12 change is introduced.

## Tests / acceptance

Native Windows VM2 TDD RED for absent telemetry type, then GREEN with tests proving independent AEAD, decode, present, keyframe wait and errors; five-second rate-limit; key epoch change and clear isolation; and that a waiting-for-keyframe step cannot be counted as decoded/presented frames. The `classmesh-worker` native VM2 package passed 79 library tests and additional 4+3+23 binary/integration tests, and warnings-denied Clippy for all targets passed. `rustfmt` and exact-head hosted Portable Rust and Windows Build CI are merge gates.

## Remaining production gaps

This is **local process diagnostic evidence**, not yet a trusted per-student Worker→Service→Teacher telemetry protocol. Binding, sequence, replay defense, maximum report rate, receiver authorization, privacy and revocation of any future IPC/wire telemetry still need a separate reviewed design and physical two-host qualification. No RTT, authoritative loss ratio, 5/10/20/30-seat Wi-Fi throughput benchmark or GPU-render success is inferred from AEAD statistics alone.
