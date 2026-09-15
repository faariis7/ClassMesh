# Phase 4 Media Feedback Qualification

This test closes the one-to-one media recovery loop before the authenticated QUIC control plane is introduced.

The feedback payload is transport-neutral, but the current diagnostic carrier is a small UDP side channel. It is **Phase-4 test infrastructure only**: it is not authenticated or encrypted and must not be treated as the production control path. Run it only on a trusted test LAN. Phase 5 moves these semantics onto the authenticated QUIC/TLS control session.

## Topology

```text
Teacher                                             Student
DXGI -> GPU NV12 -> HW H.264 -> UDP media --------> reassembly -> HW decode -> D3D11
        ^                                              |
        |                                              |
        +---- keyframe request / NACK <--- UDP feedback+
```

The media stream and feedback stream remain separate. Feedback failure does not intentionally tear down healthy media or device/control state.

## Teacher

Replace `STUDENT_IP` with the student test machine address:

```powershell
.\classmesh-media-probe.exe `
  --seconds 300 `
  --udp-to STUDENT_IP:57000 `
  --feedback-listen 0.0.0.0:57001
```

Expected teacher diagnostics include:

- `feedback_rx` increasing when recovery feedback arrives;
- `retransmits` increasing when NACKs can be satisfied from the bounded live cache;
- `keyframe_grants` increasing for accepted keyframe requests;
- `keyframe_suppressed` increasing when duplicate requests are coalesced inside the 250 ms guard interval;
- `keyframe_forces` increasing when Media Foundation accepts the request to make the next encoder input a keyframe.

## Student

Replace `TEACHER_IP` with the teacher test machine address:

```powershell
.\classmesh-media-receiver.exe `
  --listen 0.0.0.0:57000 `
  --seconds 300 `
  --render `
  --feedback-to TEACHER_IP:57001
```

The receiver sends feedback only for recovery events produced by the media reassembly policy:

- `NeedNack` becomes a bounded packet-index NACK;
- `NeedKeyframe` becomes a stream-scoped keyframe request;
- malformed or failed feedback sends are counted/logged without deliberately terminating video.

## Recovery plus feedback

The deterministic GPU recovery switch can be combined with feedback testing:

```powershell
.\classmesh-media-receiver.exe `
  --listen 0.0.0.0:57000 `
  --seconds 300 `
  --render `
  --feedback-to TEACHER_IP:57001 `
  --recover-after-frames 90
```

This remains a resource-reconstruction test, not a synthetic GPU driver crash. A real device reset still requires physical Windows qualification.

## Pass criteria

A successful two-machine run should show all of the following:

1. media remains live for the full test interval without an ever-growing queue;
2. feedback traffic never blocks the capture/encode loop;
3. a recoverable missing-packet event can use the live retransmit cache while the frame is still useful;
4. a stale/lost frame can request a new keyframe without restarting the sender or receiver;
5. repeated keyframe requests are coalesced rather than causing an IDR storm;
6. the next encoder input after an accepted request is eligible to become an H.264 keyframe;
7. feedback errors do not mark the student device offline;
8. GPU reconstruction still preserves the student presentation HWND and resumes at a valid keyframe.

## Phase 5 migration

Do not extend the diagnostic UDP feedback carrier into enrollment, heartbeat, input control, file transfer, or privileged commands. Those belong to the Phase-5 authenticated QUIC/TLS control plane. The reusable pieces from this phase are the feedback message semantics, retransmit-cache behavior, keyframe coordinator, and encoder keyframe request API.
