# ADR-0004: Windows Session Workers, Encoder Validation, and Wi-Fi Fan-out

Status: Accepted for prototype baseline

## Context

ClassMesh must run reliably after installation as a Windows service while still capturing and controlling the interactive user's desktop. It must also avoid assuming that a reported hardware H.264 encoder is actually performant, and it must choose a teacher-presentation fan-out model appropriate to wired and wireless networks.

## Decision 1: service and interactive worker are separate processes

The Windows Service runs non-interactively and owns machine-level responsibilities:

- enrollment and machine identity;
- control-plane supervision;
- discovery and policy;
- updater/service lifecycle;
- Windows session tracking;
- launching and supervising per-session workers.

Desktop capture, GPU media work that depends on the user's desktop, rendering and interactive input run in a worker inside the active user session.

The service must use Windows Terminal Services/session APIs to identify the active session and launch the worker in that user's context. The implementation will evaluate `WTSQueryUserToken` / `CreateProcessAsUser` or an equivalent supported Windows process-launch sequence. The service must not attempt DXGI desktop capture directly from Session 0.

Service <-> worker communication uses authenticated local IPC with explicit protocol versioning and least-privilege ACLs. External clients communicate with the service/control endpoint, not directly with an unauthenticated worker.

Session transitions (logon, logoff, lock, unlock, fast-user switching, console/RDP changes where supported) are explicit state-machine events. Media may stop/recover while device/control state remains online.

## Decision 2: hardware encoder capability is measured, not trusted by name

ClassMesh enumerates Windows Media Foundation H.264 encoder candidates and records whether they advertise hardware/asynchronous capability. Enumeration alone is insufficient.

At first-run capability probing, and after relevant driver/GPU changes, ClassMesh performs a short bounded encode benchmark using representative 720p/1080p frames. The capability result records:

- selected MFT/vendor/backend;
- input/output formats;
- measured encode latency and sustainable FPS;
- whether low-latency configuration was accepted;
- whether GPU-native surfaces remain usable without CPU readback;
- reset/reconfigure behavior.

A candidate that advertises hardware acceleration but performs like a CPU path may be downgraded or rejected for presentation use.

Preferred Windows low-latency settings include Media Foundation pipeline low-latency configuration and encoder low-latency codec controls where supported. Unsupported controls are capability results, not fatal errors.

If no suitable hardware path is available, ClassMesh enters a declared compatibility mode with reduced resolution/FPS/bitrate rather than silently pretending the same quality target is achievable.

## Decision 3: Wi-Fi teacher broadcast does not use IP multicast as the normal path

IP multicast remains the preferred scale-out path for suitable managed wired LANs after capability probing.

For Wi-Fi clients, ClassMesh defaults to real-time unicast. Wireless multicast may be available on some managed WLANs with multicast-to-unicast conversion or vendor-specific optimizations, but ClassMesh must not depend on conventional 802.11 multicast behavior for the primary presentation path.

For larger wireless classes, ClassMesh will benchmark two fan-out models:

1. direct unicast from the teacher host using one encoded rendition and per-client packet delivery; and
2. an optional local SFU/relay receiving one teacher stream and forwarding to students.

The SFU is optional infrastructure, not a prerequisite for a local wired classroom. If WebRTC/SFU deployment is selected later, LiveKit and other self-hosted SFUs should be evaluated empirically for Windows/LAN deployment, resource use, offline operation, latency and operational complexity rather than chosen solely from feature lists.

## Decision 4: teacher authentication uses modern asymmetric identity

ClassMesh will not rely on a shared classroom password as the primary machine-control credential.

The security model uses device/teacher asymmetric identities established during enrollment. A challenge-response or mutually authenticated transport proves possession of the authorized private key. Ed25519 is a preferred signing primitive where it fits the selected TLS/QUIC and certificate model.

Private keys must be non-exportable where practical or protected using Windows key-storage facilities and ACLs. Public authorization material can be centrally distributed. Authentication, transport encryption and authorization policy remain separate concepts.

## Consequences

- Session/process supervision becomes a first-class subsystem before installer work.
- Capture tests must include real Windows-service installation, not only launching an executable from a logged-in desktop.
- Encoder selection requires runtime telemetry and a capability cache.
- Wi-Fi performance tests must include direct unicast and optional local relay/SFU scenarios.
- Multicast remains valuable on managed Ethernet but is never assumed from student count alone.
- Security design must support key rotation, revocation and enrollment rather than copying one long-lived secret everywhere.
