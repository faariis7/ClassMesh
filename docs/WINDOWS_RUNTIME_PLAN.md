## Protected Teacher startup on Windows

[ADR-0009](decisions/0009-teacher-roster-trust.md) defines the signed roster,
protected issuer, Registry checkpoint and freshness contract. The
[Teacher native qualification procedure](../tools/classmesh-lab/WINDOWS_TEACHER_LIVE.md)
covers isolated fixture generation, enrollment, read-only candidate verification,
protected publication, ordinary-account `--check-live`, CLI/GUI negative outcomes,
explicit Message grant and operator acceptance. The control session can be
established before video. A verified startup probe is not a Worker result.
Test only with independently approved image signatures and temporary SCM scope.

## Unified RC physical trust qualification (2026-11-18)

Software compilation/tests do not supply an approved root, signer, roster verifier
or installation authority. See the current [RC checklist](WORK_PLAN.md). Once
those inputs and protected installation are independently approved, the authorized
operator runs the existing ACK probe from an ordinary interactive account:

```powershell
$probe = '.\tools\classmesh-lab\scripts\Invoke-ApprovedTeacherAck.ps1'
& $probe -TeacherExe $ApprovedTeacherExe -Identity $ApprovedTeacherIdentity `
  -ServiceName ClassMeshService -Connect $ApprovedEndpoint `
  -ServerName $ApprovedServerName -Message 'RC qualification message' `
  -Receipt $NewReceiptPath -TrustedSignerThumbprint $ApprovedImageSigner `
  -TimeoutSeconds 35
```

Each variable must come from the approved lab configuration; the receipt path
must be new under an existing protected local parent. The probe never provisions,
starts or installs Service/Worker. A GUI human-click command must additionally
reach correlated Worker `Completed` in that same approved trust/session topology.
Record exact source/image hashes, SCM LocalSystem PID/session, ordinary Teacher
token/session, Worker incarnation, correlated request/result, unauthorized/replay
rejections, key clear, Stop/restart and no surviving test-owned processes. A missing
roster verifier remains an explicit blocker; never add an allow path to obtain PASS.
The disposable SCM script's `-Mode Plan` is safe preparation; `-Mode Run` remains
a separate approved, exclusive lab operation. No VM2 or persistent policy changes.

# Windows Runtime Validation Plan

This plan converts architectural assumptions into executable tests before ClassMesh grows a large UI or feature surface.

## 1. Session/runtime matrix

Validate the Agent/Worker model in these states:

- cold boot before user logon;
- first interactive logon;
- lock/unlock;
- logoff/logon;
- fast user switching;
- console session changes;
- optional RDP session interaction;
- sleep/resume;
- GPU/display driver reset where reproducible.

Pass condition: the Windows Service remains healthy, the correct user-session worker is supervised, and media can recover without treating the device as offline.

## 2. Display topology matrix

Test:

- one monitor;
- dual monitor;
- primary monitor change;
- monitor hot-plug/unplug;
- resolution change;
- orientation/rotation change;
- DPI scaling differences;
- display sleep/wake.

Pass condition: ClassMesh re-enumerates the intended logical display and rebuilds stale capture resources automatically.

## 3. Encoder capability benchmark

For every candidate H.264 encoder:

1. enumerate Media Foundation MFT metadata;
2. configure low-latency mode where supported;
3. feed representative GPU-native 720p and 1080p surfaces;
4. measure p50/p95 encode latency and sustainable FPS;
5. request IDR and dynamic bitrate changes;
6. reset/reconfigure the encoder;
7. record whether any CPU readback was required.

A presentation-capable encoder should sustain 1080p30 with useful headroom on target hardware. Hardware advertisement alone does not qualify a backend.

## 4. Teacher-presentation topology tests

### Wired LAN

Compare:

- UDP unicast to N clients;
- encrypted UDP multicast to a healthy cohort;
- mixed multicast + unicast outliers.

Collect teacher outbound bitrate, CPU/GPU usage, packet loss, per-client latency and recovery behavior.

### Wi-Fi

Do not assume IP multicast as baseline. Compare:

- direct real-time unicast;
- WebRTC-style unicast if/when available;
- optional local SFU/relay fan-out.

Test at 1, 5, 10, 20 and 30 receivers when hardware is available.

## 5. Motion-content validation

The primary media test is not a static desktop. Play high-motion 1080p content on the teacher device and verify:

- 30 FPS target where hardware/network allow;
- bounded queue age;
- no monotonically growing delay;
- keyframe recovery after induced loss;
- one weak receiver does not stall others.

## 6. Protected-content behavior

Some protected surfaces may intentionally be unavailable to desktop capture. The product should distinguish this from an ordinary capture crash where possible and surface a useful diagnostic instead of entering an endless recovery loop.

## 7. Required telemetry

Every test records at minimum:

- capture FPS and latency;
- capture recovery count/reason;
- GPU processing latency;
- encoder name/backend and encode p50/p95;
- bitrate and keyframe count;
- queue age/depth/drop count;
- RTT, loss, jitter and reorder rate;
- decode FPS/latency;
- render latency;
- current transport/cohort;
- session/worker lifecycle transitions.

## 8. Promotion gates

ClassMesh should not move to broad classroom UI development until:

- service + interactive worker lifecycle survives the session matrix;
- DXGI recovery survives display topology tests;
- at least one hardware H.264 path passes 1080p30 motion validation;
- one-to-one streaming stays below the initial <100 ms healthy-LAN target without accumulating delay;
- multi-client fan-out has measured evidence for the selected wired and Wi-Fi strategies.
