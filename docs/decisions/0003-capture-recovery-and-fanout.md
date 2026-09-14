# ADR-0003: Capture Recovery and Classroom Fan-Out

Status: Accepted for prototype baseline

## Context

Review of classroom/remote-desktop projects and Windows capture failure reports highlights two recurring architectural risks:

1. desktop-capture objects become invalid after display/session/GPU changes and must be recreated; and
2. teacher-to-many delivery does not scale if every receiver creates independent upstream media work on the teacher host.

ClassMesh also needs different behavior on managed wired LANs and multicast-unfriendly Wi-Fi/routed networks.

## Decision: capture lifecycle

Capture resources are disposable and recoverable. The capture layer must not expose long-lived DXGI output/duplication handles as permanent device identity.

A display is represented by a ClassMesh display descriptor. On access loss, device reset/removal, resolution/rotation/topology change, monitor hot-plug or interactive-session transition, the backend:

1. stops publishing new frames;
2. releases duplication and dependent GPU resources;
3. re-enumerates adapters/outputs;
4. resolves the desired display again;
5. recreates the D3D/capture chain;
6. resumes into the same logical stream when safe.

Recovery uses bounded backoff and emits structured reason/attempt metrics. Capture failure never marks the device itself offline while the control plane remains healthy.

Protected/DRM content is treated as a distinct diagnostic condition where detectable and must not trigger an endless reconnect loop.

## Decision: classroom fan-out

There is no single global transport fallback for every receiver. ClassMesh distributes receivers into cohorts based on network capability and runtime health.

Preferred teacher-presentation paths:

1. **Encrypted UDP multicast** for managed wired LANs where multicast probes and runtime health are good.
2. **Real-time unicast** for isolated clients or environments where multicast is unsuitable.
3. **Optional local SFU/relay** for future WebRTC-heavy Wi-Fi, routed, browser or cross-platform deployments where P2P teacher fan-out would scale poorly.

The main presentation video is encoded once per quality/rendition, then distributed. A slow receiver cannot block the encoder or healthy receivers.

If an SFU is introduced, it should forward encoded media rather than decode/re-encode unless a deliberate transcoding profile requires it.

## Consequences

- More state-machine and telemetry work is required early.
- Display identity/re-enumeration must be tested before UI polish.
- Multicast remains valuable but is not assumed to work everywhere.
- WebRTC remains a candidate transport backend, not a mandatory core dependency for the first prototype.
- Large-class Wi-Fi testing must compare direct unicast against a local SFU/relay before production selection.
- Test plans must include topology change, reconnect storms, weak receivers, and virtualized/hardware-encoder-failure scenarios.
