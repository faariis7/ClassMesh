# Phase 10: caller-owned Teacher playback session

This document describes a **reusable, opt-in library boundary**, not a
production Teacher GUI subscription, a new network quality signal, or physical
Phase 10G qualification.

## One authenticated control channel

The production caller first obtains an already-enrolled
ClientControlSession using a trusted TLS root/certificate policy and the
current LiveAuthorizationStore. A trusted enrollment/roster record must bind
one StudentDevice PrincipalId to one MonitoringSourceId and an exact
TeacherPlaybackBinding (control session, presentation, stream, epoch).
The selected UI device, hostname, IP or device label **cannot by itself
authenticate** this mapping. A reconnect requires a new session owner.

TeacherPlaybackSessionOwner::receive_next reads **one** envelope from that
existing QUIC session. It does not spawn another reader or build a second
connection. The underlying receive adapter re-samples live certificate
authorization and wall time both before and after network I/O, then checks
the negotiated Teacher role, current control session and optional v0.8
ReceiverPlaybackDiagnostics capability 18.

An authenticated non-playback envelope returns unchanged as OtherControl.
The single owning dispatcher must still perform its own per-command
authorization. An authenticated playback diagnostic is checked by the
source-bound replay/freshness ledger before entering the read-only counters.
No packet loss, RTT, bandwidth, quality vote, adaptive tier or topology
decision is derived from those counters.

## Session invalidation and replay

The owner tracks the **outer** ControlEnvelope.sequence across both playback
and non-playback messages. A zero, equal or regressing outer sequence fails
closed, retires the old owner, and hides its counters; neither a new inner
Worker sequence nor a change of control-message type permits replay. The
central dispatcher still independently authorizes each non-playback action.
A malformed playback report never replaces a valid diagnostic. Revoked
TLS credentials, policy changes, receive transport failure and control-session
mismatch retire the owner immediately. Exact source + presentation binding
is required for explicit retirement, so a stale disconnect cannot invalidate
a different source or replacement session.

Portable real-loopback QUIC tests cover successful dispatch, preservation
of other control messages, source-bound visibility, identity revocation,
wrong session before queue consumption, wrong epoch without overwriting
counters, and cross-type control sequence replay. Windows CI and Portable
Rust CI are required before any integration, on the exact HEAD being used.

## Still required for production and Phase 10G closure

The current classmesh-teacher-ui Windows eframe binary only launches the UI.
It **does not** currently load an enrolled endpoint, trusted roster mapping
or create the central authenticated QUIC session from a production profile.
A separately reviewed startup/configuration and UI-thread event delivery
path is needed before enabling a live subscription. Do not introduce a
second listener that steals unrelated control messages.

Real physical 5/10/20/30 receiver qualifications, their retained logs,
and a minimum 30-minute physical soak (Issue #288) remain open. Windows
VM smoke or synthetic GitHub CI cannot replace that evidence. The optional
Worker/Service native telemetry feature remains disabled by default.
