# Phase 10 — receiver playback telemetry admission gate

## Scope and trust boundary

This change adds a **pure Rust, constant-space admission gate** for later Worker→Service receiver playback telemetry. It does **not** create or activate a new IPC message, network sender, Teacher feed, authenticated credential, or adaptive-quality decision. It is intentionally independent of Astra's Phase 12 Windows trust, Registry anchor and IPC versioning work.

Before calling `ReceiverTelemetryGate::activate`, the eventual Service integration **must independently verify** its authenticated Worker pipe and current process, logon session, Worker generation, accepted presentation/stream ownership, installed key epoch and receiver-runtime generation. None of those can be asserted by a Worker-supplied report. A media report cannot activate its own binding. Exact binding change clears the previous baseline; identical activation preserves replay state. A matching clear revokes the gate; a stale clear cannot revoke a replacement.

`ReceiverTelemetryGate::observe` accepts only a nonzero monotonically increasing sequence from that exact binding and measures time on the Service's own monotonic clock. Reject replays, clock regression, malformed identity, counters decreasing and reports faster than 1 second, without advancing state. First sample, skipped sequences and time gaps above 30 seconds yield **Baseline**, never a fabricated valid quality interval. Contiguous, nonregressing counters yield separate authenticated AEAD opens, rejected opens, decoded frames, presented frames, errors, keyframe waits and receiver queue drop deltas. Memory remains O(1) per active gate; no content, keys or frame bytes are retained.

## Why this cannot yet drive automatic quality

Protected UDP sequence gaps are **observed ID discontinuities**, not definitive packet loss. AEAD-authenticated frames are **not** proof of decoding or display. Cumulative queue drops are **receiver-runtime-local**, not UDP loss. None of these local counters measures RTT or a true loss ratio; the gate deliberately returns neither synthetic RTT, packet-loss percentages nor a receiver health tier.

An **authenticated, version-negotiated Worker→Service telemetry IPC contract** is still required, including bounded sender rate, replay-resistant lifecycle, Service authorization, explicit drop behavior and revocation. Service→Teacher delivery needs its own mutually authenticated control-session correlation, bounded storage, independent per-receiver samples and safe adaptation policy. Phase 12 version changes must be coordinated before introducing message IDs. This feature stays passive until that integration and native Windows security qualification are complete.

## Worker-local monotonic sequence and read-only liveness

The real Worker `PresentationDeliveryTelemetry` diagnostic now stamps each eligible five-second report with a per-binding `sample_sequence`. Undue polls do not consume sequence IDs. The number starts at 1 after exact media binding/epoch reset or pipeline teardown; exhaustion stops emission instead of wrapping to a replayed ID. The Worker still logs **locally only**; no new privileged IPC write or wire contract was introduced.

The pure Service-side `ReceiverTelemetryGate::has_fresh_report(service_now)` checks whether a report has been accepted for the active binding within the bounded 30-second continuity window, using the Service monotonic clock. An invalid replay cannot refresh liveness; missing baseline, a cleared/replaced binding, a clock regression or expired report returns false. This is a **read-only liveness diagnostic**: it does not synthesize a media-quality sample, prove Worker truthfulness or change existing adaptation.

**Outstanding cadence mismatch:** the present Worker local diagnostic is emitted every 5 seconds while `ReceiverQualityPolicy::default().max_sample_age_us` is 2 seconds. Before wiring new metrics into automatic adaptation, align separately proven authenticated publisher cadence, bounded coalescing/backpressure, freshness expiry and independent network measurements; otherwise healthy devices may oscillate to Emergency between reports. Neither 30-second gate liveness nor a sequence number authorizes quality promotion, provides RTT, or turns UDP gaps into loss percentages. The phase-12-owned IPC version must not be changed here.

## Regression and CI

`cargo test -p classmesh-control --test receiver_telemetry_admission` covers exact binding, stale Worker/runtime generations, replay, non-monotonic clocks, nonregressing counters, duplicate activation, revocation, too-frequent reporting, missing sequences, stale gaps and independently recorded authenticated/decoded/presented deltas.

The Remote Desktop Commander monthly limit prevented an **independent current-turn Windows VM2 rerun**. Prior tests for the earlier Worker watch dog do not validate this module. Require Rustfmt, all-targets warnings-denied Clippy, exact-head Portable Rust and Windows Build hosted CI. Preserve separate physical two-PC and classroom-congestion qualification gates. Do not treat hosted CI as physical evidence.

## Passive byte ingress, still not an authenticated pipe

`ReceiverTelemetryIngress` composes the strict decoder and admission gate at a
single read-only boundary. The Service must call `activate_verified` using a
binding derived **independently** from its authenticated Worker IPC peer,
process/session/Worker generation, accepted presentation and currently active
receive-runtime generation. Decoded payload bytes never activate the gate.
Malformed, replayed, mismatched-epoch and counter-regressing frames cannot
advance its baseline. Exact lifecycle revocation clears the binding; stale
revocation cannot clear a replacement. No new message ID, live producer,
privileged channel, Worker→Service delivery or quality promotion is introduced.

`cargo test -p classmesh-control --test receiver_telemetry_ingress` checks
unauthorized bytes, wire errors, wrong epochs, replay, valid deltas and
replacement/revocation. Native authenticated transport integration and VM2 or
physical-machine qualification are still required before runtime use.
