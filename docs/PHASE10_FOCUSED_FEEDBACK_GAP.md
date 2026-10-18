# Phase 10 — focused live receiver feedback gap recovery

## Observed production path

`classmesh-service/src/control_runtime.rs` has a real authenticated `ReceiverFeedback` ingress for one focused interactive stream, with `Permission::ControlInput`, input/media owner checks, `FocusedAdaptationState` and existing `StreamReconfigure` request/reply dispatch. This is **different** from the classroom-wide `ReceiverCohortPlanner`, which is not yet wired into a live per-student telemetry channel.

## Defect and scoped correction

Prior to this fix, FocusedProfileController held the last High tier across arbitrarily long gaps without `ReceiverFeedback`; the first resumed healthy measurement could keep the stream at High even after feedback silence. An accepted, valid feedback timestamp now stays in `FocusedAdaptationState`. On a same-stream feedback gap strictly over two seconds, the resumed *authorized* feedback causes a profile-only Emergency reconfigure through the **existing request/reply path**. The timeout clears any pending recovery hysteresis; after the downgrade, normal five *fresh* healthy feedback observations are required for High. The first resumed feedback signals the downgrade and is not counted as recovery. A new stream resets the prior timer, and malformed feedback never extends it. An identical timeout interval is not a second loss event. No transport selection, permission widening or new wire payload was introduced.

## Evidence

Native Windows VM2 x64 test-first compile RED for missing `observe_at`/`expire_at`, then GREEN for timeout boundary, idempotent expiry, invalid metrics, new-stream isolation, and the first resumed message. The full `classmesh-service` package test suite (73 unit and its integration binaries) and warnings-denied Clippy passed locally. Exact-head GitHub Portable Rust and Windows Build CI are mandatory for merge.

## Open production dependency

This is *feedback-resumption safety*, not real-time no-feedback detection. A separate timer would need to initiate an unsolicited StreamReconfigure, whose receiver wire/request-correlation semantics and session authorization/revocation handling have not yet been verified. Do not enable unsolicited server sends until client compatibility, active-stream binding, ownership and physical streaming regression tests pass. Actual 5/10/20/30 classroom telemetry ingestion and per-receiver timer owner remain Phase 10G/physical gates.
