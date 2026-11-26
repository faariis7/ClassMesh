## Protected Teacher startup on Windows

[ADR-0009](decisions/0009-teacher-roster-trust.md) defines the signed roster,
protected issuer, Registry checkpoint and freshness contract. The
[Teacher native qualification procedure](../tools/classmesh-lab/WINDOWS_TEACHER_LIVE.md)
covers isolated fixture generation, enrollment, read-only candidate verification,
protected publication, ordinary-account `--check-live`, CLI/GUI negative outcomes,
explicit Message grant and operator acceptance. The control session can be
established before video. A verified startup probe is not a Worker result.
Test only with independently approved image signatures and temporary SCM scope.

Issue the Student leaf with `--student-server-name <DNS-or-IP>` from the
approved endpoint and use that value as the protected Teacher
`student.server_name`. Capture native Authenticode results, rollback scope,
existing protected resources and the ordinary interactive session before
SCM Apply.

## Protected VM1 run — 2026-11-26

Signed image source `353c38a89c461429c493e2ddffe0b3428e12404c`, Windows 11
24H2 ARM64 with x64 emulation, ordinary Teacher in Session 1. The signed ZIP
SHA-256 was `8b16d4c1979029aee4029a5a5cbeb8b2c2dc78c03fc219b28f5dc8329ac20952`.
The [artifact integrity review](https://github.com/faariis7/ClassMesh/pull/776#pullrequestreview-6069185984)
and [custody and recovery review](https://github.com/faariis7/ClassMesh/pull/776#pullrequestreview-6069711087)
cover the disposable scope. Recovery snapshot `42F98268-4829-4D26-9C86-EA074D69A3F3`
was verified before provisioning and after cleanup.

- All 13 exact binaries were native Authenticode `Valid` with signer
  `DE9A7C005CD4C989E548CB65C207345FB9720059` under temporary `CurrentUser\Root`
  trust. The isolated NTFS volume held the installation. Teacher and
  StudentDevice used distinct non-exportable CNG keys, a run-owned enrollment
  CA and a separate ES256 roster authority. Plan preceded Service epoch 1 and
  Teacher epoch 2 publication. `SendTeacherMessage` was the only lab grant.
- Under Windows PowerShell 5.1, `sc.exe create` dropped the image-path quotes
  and the guard halted before start. `New-Service -BinaryPathName` stored the
  expected quoted path. Four guarded runs then reached pinned LocalSystem
  Service in Session 0. The last PID was `10044`.
- `classmesh-teacher-ui.exe --check-live` ran against `127.0.0.1:5151` as a
  non-elevated Session 1 user. The `NotNegotiated` rejection occurs after
  verified roster, enrolled mTLS, QUIC Hello and the Student identity check.
  The probe and the normal GUI invocation both exited 3. The Service launched
  eight Worker processes in Session 1 after unlock in the traced window.
  No authenticated Worker or visible Message was observed. M2 `Completed`,
  unauthorized command denial, replay and revocation were unmeasured on this
  protected route.
- The ordinary Session 1 probe received Win32 error 5 opening the live
  LocalSystem Service with both `PROCESS_QUERY_LIMITED_INFORMATION` and that
  right plus `PROCESS_SYNCHRONIZE`. For a live same-account child, the original
  mask opened the process but a zero-time wait failed with error 5. The
  corrected mask returned `WAIT_TIMEOUT` and the subsequent SID check still
  denied the child. The focused Worker tests went from 3/4 to 4/4 on VM1.
  The remaining positive regression must prove the exact live LocalSystem
  pipe server from the ordinary Worker without broadening process or token
  rights. Then rebuild, independently review and pin the matching images,
  and rerun guarded M2 with a human Student operator.
- M3 rendering remains unmeasured. M4 evidence covers real lock/unlock,
  repeated Service start/stop and final Worker disappearance. Authenticated
  recovery and revocation remain open. M5 evidence covers protected staging,
  provisioning, guarded registration and teardown. Fresh-machine package
  installation, repair and a connected start remain open.
- Cleanup verified at `2026-11-26T07:15:32Z`. The disposable SCM registration,
  Worker processes, UDP listener, two protected policy anchors, enrollment CNG
  keys, enrollment CA key, exact signing certificates, owned VHD and staging
  paths were absent. The recovery snapshot remains available.

### Worker authentication acceptance on the next signed candidate

The Service owns the sole primary named-pipe server instance as `LocalSystem`.
Its DACL grants the selected user client I/O and descriptor read; only SYSTEM
can create instances or control the descriptor. The Service checks the
connected client's PID and session against the retained live Worker process
handle before sending a fixed pre-Hello proof. It delegates a Service process
handle with limited query and synchronize access and a primary token handle
with `TOKEN_QUERY`, only into that Worker. The Worker reads the connected
pipe's owner and DACL, checks the kernel server PID and Session 0 against the
delegated process, checks that process is still alive, and reads `TokenUser`
from the delegated token. It repeats the PID, session, liveness and SID checks
after `ServiceReady`. The two handles close before the Worker starts dispatch.
Neither the Service process nor its token security descriptor is changed. A
mismatched old Worker or Service fails the local bootstrap, so deploy a
matching pair. The QUIC wire protocol is unchanged.

Under the approved guarded SCM window, record the exact signed Service,
Worker and Teacher hashes and the Service Session 0 PID. Trigger an
interactive Worker launch and use the ordinary Teacher session to run:

```powershell
$result = @(& $ApprovedTeacherUi --check-live 2>&1)
if ($LASTEXITCODE -ne 0 -or $result -cnotcontains 'TeacherMessage negotiated: true') {
    throw ('Native enrolled Worker qualification failed: ' + ($result -join ' '))
}
$result
```

This is the positive native regression with the actual LocalSystem Service.
Capture the Worker PID, its Service parent and ordinary session. The Service
advertises `TeacherMessage` only after the live Worker handshake; broad
authorization still cannot be inferred from capability negotiation. Repeat
before Worker authentication and expect the Teacher command capability to be
absent, then perform the real Message and capture its correlated `Completed`
after the authorized operator acknowledges it. Use the documented guarded
teardown and verify cleanup. The positive result requires exact-asset review
and a new VM run.

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
rejections, key clear, Stop/restart and no surviving test-owned processes.
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
