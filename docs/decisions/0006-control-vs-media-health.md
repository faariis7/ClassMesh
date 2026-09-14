# ADR-0006: Device Presence Is Not Video Health

Status: Accepted

## Context

The previous ClassPilot implementation could make a student appear disconnected when a screen-capture/stream path failed. That couples unrelated failure domains and causes classroom-wide instability when high-motion video or a temporary GPU/network problem occurs.

ClassMesh needs a device to remain manageable while capture/encode/transport recovers.

## Decision

ClassMesh models these states independently:

- control connectivity/authentication;
- machine service health;
- interactive Worker health;
- capture health;
- encoder/decoder health;
- individual media-stream health.

A device is considered online when its authenticated control session/heartbeat is healthy. Video can independently be `Idle`, `Starting`, `Streaming`, `Degraded`, `Suspended`, `Recovering` or `Failed`.

### Examples

- `DXGI_ERROR_ACCESS_LOST`: device online; capture recovering.
- UAC secure desktop: device online; media suspended with an explicit reason.
- UDP packet loss: device online; media degraded/recovering.
- encoder reset: device online; presentation stream recovering.
- Worker crash: service online; Worker restarting; media recovering.
- control heartbeat timeout beyond policy: device offline regardless of the last video frame.

## Consequences

- Classroom UI must show presence and video health separately.
- Reconnect policy can restart only the failed subsystem.
- Administrative commands can continue during media degradation when security/session policy allows.
- A slow/broken receiver no longer causes group-stream teardown.
- Metrics and logs require session/stream/component identifiers so failure ownership is visible.
