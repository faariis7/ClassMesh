# Phase 10 — Teacher playback diagnostics (optional)

The Worker reports authentic playback counters to the Service over the independently authenticated native Windows pipe. The Service only admits a matching protected receiver lifetime, checks report freshness, and distributes a single-slot read-only diagnostic to the enrolled presentation owner.

**Required gates:** The privileged Service must explicitly opt in using CLASSMESH_ENABLE_PHASE10_TELEMETRY=1, and its current Worker must advertise the v11 receiver-grant capability. A Teacher must negotiate optional capability 18 (ReceiverPlaybackDiagnostics) over protocol 0.8. Existing/older Teachers never receive the new payload 54. Delivery independently checks live TLS credential, PrincipalId, StartPresentation permission, current control session and presentation, and matching protected key; an expired sample is discarded.

The payload includes only actual authenticated/decoded/presented counts, errors, keyframe waits and local queue drops. It does not claim network RTT, packet loss, latency, topology, adaptive quality tier, or transport permissions. Worker and Teacher authority are never derived from report bytes.

The TeacherPlaybackDiagnosticLedger accepts the optional payload **only after a trusted QUIC client authenticates the Service**. It verifies session, media presentation, stream, key epoch, negotiated protocol, generation and monotonic sequence. Exact revocation clears its latest-only counters. The Teacher application currently lacks a complete live QUIC inbound integration for this optional payload; integrating this ledger with that client remains outstanding.

This does not qualify physical classrooms, change production defaults or activate the Service by default. Issue #288 still requires 5/10/20/30 actual receivers and 30-minute physical soak. The native Windows smoke bundle from PR #606 is a software OS-attestation gate, not classroom evidence.