# Phase 10: optional receiver telemetry grant on existing v11 control IPC

This is a separate, non-secret, Service→Worker **authorization context
record**, not a Worker credential, live diagnostics sender or production
Teacher channel. The Service may only issue it after successful Worker
authentication, protected key install and exact correlated receiver start.
The currently deployed Worker does not advertise the opt-in flag yet, and
Service does not emit the message by default. No production behavior changes.

The typed `ServiceReceiverTelemetryGrant` encodes 60 bytes in network order
and carries the authoritative Service PID, Worker PID and Windows session,
Worker incarnation generation, independently minted receiver generation,
control session, distinct stream-start request ID, presentation, stream and
key epoch. Every field must be nonzero. The decoder refuses wrong length,
zeroed identity, v10 downgrade and malformed payload before any transport
connection. A grant contains no secret key, ciphertext, media, clipboard
payload, network RTT/loss or privilege to send to Teacher.

**Important Phase 12 compatibility:** clipboard read-success has already
reserved IPC minor 12 and message type 33 for an exclusive zeroizing decoder
and challenge protocol. Do **not** bump the default IPC minor to 12 or reuse
message 33 for Phase 10 diagnostics. The optional grant uses **message type
34 on v11** and an explicitly advertised Worker capabilities bit
(`WORKER_CAP_TELEMETRY_GRANT_V11`). Workers without this capability must
never receive type 34; otherwise they will fail closed on unknown IPC,
rather than silently activating a peer. v12 sensitive decode remains
independently protected and tested.

This only lays down the bounded optional wire contract and capability.
Production integration must separately verify the current Service-owned
receiver against the original launched process HANDLE, schedule a background
OS-authenticated diagnostics pipe, prove revocation and backpressure under
native Windows testing, and only then activate the Worker flag and grant.
Any subsequent Teacher publication needs independently authorized
PrincipalId/session and must not invent RTT, network loss or readiness.

Real Phase 10G classroom 5/10/20/30 receiver and 30-minute soak gates in
Issue #288 remain open.
