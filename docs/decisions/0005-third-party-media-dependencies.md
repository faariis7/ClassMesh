# ADR-0005: Third-Party Media Dependencies Are Replaceable Backends

Status: Accepted for prototype baseline

## Context

ClassMesh can accelerate development by learning from or integrating mature projects such as Windows desktop-duplication wrappers, FFmpeg/GStreamer, WebRTC stacks or LiveKit. At the same time, the product must not accidentally make its core capture/session/network policy dependent on one external framework before measurements justify that choice.

The Windows hot path also has unusually strict requirements: user-session correctness, GPU-surface ownership, low latency, recovery after device/display transitions and predictable deployment in offline classrooms.

## Decision

Third-party media/network libraries are allowed when they satisfy all of the following:

1. license is compatible with the intended ClassMesh distribution model;
2. dependency is isolated behind a ClassMesh interface/backend;
3. the integration does not force CPU readback in the normal presentation path;
4. the dependency can expose enough diagnostic/recovery information for ClassMesh policy;
5. replacement cost is bounded because wire/policy/domain types are owned by ClassMesh;
6. version, security and maintenance risk are documented.

### Windows capture

A desktop-duplication wrapper may be used as a **development spike/reference** to get GPU textures quickly, but the stable API remains `CaptureBackend`. ClassMesh may replace the wrapper with direct `windows-rs`/Win32 implementation when required for lifecycle, metadata, HDR, performance or maintenance control.

### Encoding/decoding

Media Foundation/D3D11 remains the Windows-first baseline because it can keep Windows GPU surfaces native and avoids making FFmpeg a mandatory distribution dependency. FFmpeg remains a valuable diagnostic/fallback/backend candidate.

### WebRTC/SFU

WebRTC/LiveKit can be added as Wi-Fi/routed/browser fan-out backends. They do not own ClassMesh device identity, classroom policy, capture, codec capability probing or control semantics.

### Protocol libraries

Standards-based security and transports should be implemented through well-reviewed libraries rather than hand-written cryptography. ClassMesh can define message schemas and packet metadata, but must not invent a new cipher or unaudited authentication primitive.

## Consequences

- We can use open-source work to move faster without turning ClassMesh into a fork.
- Integration code lives at platform/backend boundaries.
- Benchmarking can compare multiple implementations with the same higher-level tests.
- Third-party updates do not dictate classroom/domain architecture.
- Dependency/license/security review becomes part of the 1.0 gate.
