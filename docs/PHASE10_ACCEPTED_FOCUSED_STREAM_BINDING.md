# Phase 10 — bind focused feedback to accepted media streams

## Problem

The focused interactive video `ReceiverFeedback` path used a peer-supplied `stream_id` as its own adaptation state selector. An authenticated peer with ControlInput permission could supply unrelated stream identifiers and reset focused stream adaptation or attempt to dispatch a reconfigure unrelated to the accepted media stream. That is not proof of authority for a stream.

## Change

`FocusedAdaptationState::bind_stream` is invoked **only after** a valid interactive `StreamOffer` is accepted by the Service-owned media start channel. Its accepted stream ID is stored for the session, resetting the profile/time history when a *different* stream is accepted. Peer feedback is rejected with `control.feedback.stream_not_accepted` unless the stored ID exactly matches; it cannot create or switch authority. Existing per-envelope authorization remains, plus a live `media.is_owner(control_session_id)` check before dispatching accepted feedback to the worker. Presentation offers do not bind the focused state. Existing stream/profile transport restrictions and secured dispatch remain unchanged.

## Evidence and boundaries

TDD compiler RED for missing `bind_stream` method. Native Windows VM2 x64 full `classmesh-service` package and Clippy all-targets `-D warnings` passed. The new negative test confirms unaccepted/wrong stream feedback cannot change tier and that separately accepted media can reset stream state. Exact-head GitHub CI required before merge; live QUIC loopback/integration tests on two physical PCs remain outside this proof. This is not an implementation of a periodic no-feedback watchdog and does not touch Phase12 root/epoch or worker authorization policies.
