# Installed Windows recovery qualification

Use the exact M4 Draft PR source and matching Teacher, Service and Worker
images in an independently approved disposable Windows x64 lab. Use the M2
protected enrollment, ordinary Teacher, LocalSystem Service, interactive
Student Worker and rollback procedures. Use a separate machine pair for this
run. Both transports need the M3 H.264/D3D11 test topology.
[Teacher provisioning and guarded SCM](../tools/classmesh-lab/WINDOWS_TEACHER_LIVE.md) ·
[Two-host presentation setup](M3_INSTALLED_PRESENTATION_QUALIFICATION.md) ·
[Product acceptance #688](https://github.com/faariis7/ClassMesh/issues/688)

## Capture the baseline

Record source revision, signed-image hashes, signer, Windows build and boot
time, policy checkpoint, both network addresses, GPU/driver, ordinary
Teacher identity and session, and the Service Session 0 PID. Record the
authenticated Worker PID, ordinary login session and Service Worker
generation. Start a harmless Message and have the real Student operator
acknowledge it. Record the matching Completed result. Start presentation
and record changing Student output.

These read-only commands help compare the same processes before and after a
fault. Use the Event Log, application diagnostics and visible windows as
separate observations. Record exit times and timestamps as well as PIDs.

```powershell
Get-CimInstance Win32_Service -Filter "Name='ClassMeshService'" |
    Select-Object Name, State, StartName, ProcessId
Get-Process -Name classmesh-teacher-ui,classmesh-service,classmesh-worker -ErrorAction SilentlyContinue |
    Select-Object Id, SessionId, StartTime, HandleCount, WorkingSet64, PrivateMemorySize64
Get-NetUDPEndpoint | Where-Object OwningProcess -In (
    Get-Process -Name classmesh-teacher-ui,classmesh-service,classmesh-worker -ErrorAction SilentlyContinue
).Id
```

## Run the matrix for Unicast and Multicast

| Fault and action | Acceptance evidence |
| --- | --- |
| Disconnect Teacher Ethernet during an active presentation. Restore the same lab path within ten seconds. Repeat three times with at least 15 seconds of stable control between cycles. | Each retired session stops sending and clears the active UI. Teacher shows reconnecting and restores controls only after fresh enrolled Hello. Click Start again and capture new presentation/stream and fresh key acknowledgement before any displayed frames. |
| Keep the path unavailable throughout the recovery window. Close Teacher during the connection attempt and repeat during backoff. | Record retry count, delay, final error and exit time. One recovery episode has at most eight attempts and 40 seconds. Window close cancels the recovery wait. Record that no Teacher process or UDP endpoint survives exit. |
| Interrupt Start while the key ack is pending, repeat while the Worker start result is pending, then interrupt Stop before the remote confirmation. | Capture the old request, its owner and cleanup. Confirm the old receiver, renderer and key retire. A new session must not inherit an old result or automatically start broadcasting. A fresh authorized Start succeeds once ownership is free. |
| Restart the approved Service through the guarded SCM procedure while Teacher is running. | The retired PID and Worker are gone. Teacher reconnects to a fresh authenticated connection after Worker readiness; the Service may reuse a numeric wire session ID. The old queued Start or Message must not execute. |
| Terminate only the lab-owned authenticated Worker identified in the baseline. Repeat while a Message awaits operator confirmation and during presentation. | Observe one replacement generation after old process exit. A pending Message stays unconfirmed unless its real matching terminal event was delivered before retirement. Record key, renderer and receiver retirement and new Worker/Session binding. |
| Lock the Student desktop, unlock, then repeat sleep/wake with the desktop first unlocked and then locked. Repeat with Worker startup overlapping lock. | Suspend removes the active receiver, key and window and blocks new grants. A power resume while locked does not re-enable media. Unlock can restore media capability on the same Worker. Start a new presentation and capture visible fresh frames. Include SCM power/WTS notification timestamps. |
| In a separate approved run expire the Teacher roster during the outage, then test an advanced protected checkpoint and server-side enrollment revocation. | No reconnect can grant a UI action or distribute keys under expired or replaced policy. Server-side denial is terminal. A protected checkpoint change requires relaunch and full verification of the new policy. Capture denial code and absence of media. |

Sender or loopback evidence does not measure GPU rendering. Save the native
Teacher status, Student display and exact correlated request/response. Record
the old/new session, Worker PID/generation, presentation and stream IDs and
non-secret key epoch. Use the approved lab's trace gates to identify old
datagram rejection and verify no old pictures appear. Keep payloads, keys
and private operator data out of logs.

After warmup, sample handle counts, private bytes, Worker count, presentation
windows and UDP socket owners over the repeated cycles and again after
cleanup. Investigate sustained growth and orphaned windows or endpoints.
Record physical hardware, separate VM observations and hosted fixture
results with their own scope. Use guarded teardown and verify the
run-owned processes, sockets, policies, CNG keys and certificates are absent.

## Automated scope

The reconnect policy allows typed transport loss and the explicit Service
retirement code. TLS/protocol and policy denial are terminal. One local
generation binds queued GUI actions to one connection even when a Service
restart reuses a numeric control ID. Replacement waits for the old sender
to exit. Both transports need a new user Start, reauthorized reservation,
Worker key ACK and accepted stream offer; previous pictures and commands
remain retired. The Service uses the existing Worker supervisor, exact
incarnation fencing and bounded pending-worker operations.

Tests exercise repeated QUIC replacement, backoff exhaustion, terminal
errors, stale UI generations, Worker-transition retirement, suspend/key
clear and lock versus wake. Physical restart, sleep/wake, leak and rendered
video evidence for this revision require the matrix above. Windows services
receive power notifications through the existing SCM handler.
[Microsoft service power notification contract](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status)
