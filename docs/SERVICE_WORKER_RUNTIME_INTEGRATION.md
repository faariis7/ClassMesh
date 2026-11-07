# Service / Worker runtime integration (#688, Draft #713)

Base: #710 `4c08347131ff70080163ef45970609e08009c01b`.
#700 already supplies guarded SCM registration, #708 the Worker native peer
checks, and #712 fail-closed Service capability-reader activation. Reuse them.

## Missing behavior and implementation

The Worker opened the Service process with `PROCESS_QUERY_LIMITED_INFORMATION`
then used `WaitForSingleObject`, which requires `SYNCHRONIZE`. Negative-only
tests accepted this universal rejection. The new native live-peer regression
failed first on Windows run **42421890847**, commit `b2f05fc`: 36 passed,
1 failed, actual error "pipe server process exited or liveness is unverified"
instead of the real non-LocalSystem SID rejection. The fix requests precisely
query + synchronization rights, retains that process object across the IPC
lifetime and checks it before media and event dispatch. No debug privilege,
token/ACL change, SID fallback or change to cryptography.

Reference: [Microsoft WaitForSingleObject access requirement](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject).

An **opt-in metadata-only** observer exists only in the existing
`experimental-trusted-policy` Service build, activated by the guarded runner.
It uses a separate outbound pipe, SYSTEM/intended-user DACL, remote-client
rejection, first-instance ownership, exact kernel-observed observer PID/session,
128-byte maximum, bounded connect/write and cancellation/drain on a dedicated
thread. It receives **no commands**. The primary protocol is unchanged.
Metadata is sampled after observer attestation, directly from the Service's
decoded WorkerCapabilities state; activation alone, restart, stale generation
and reader EOF cannot produce a positive report. GPU capability flags may all
be false; IPC success never claims GPU success.

## Approved Windows integration execution

Do not run until **actual independently recorded CA/enrollment/security review,
protected installation and exclusive disposable VM approval** exist. Switches
inherited from #700 only acknowledge those external approvals; they do not
create them. This change has not obtained them and has not touched VM1/VM2.

Build matching executables from the reviewed revision:

```powershell
cargo build -p classmesh-service --features experimental-trusted-policy
cargo build -p classmesh-win32 --features experimental-trusted-policy --bin classmesh-trusted-provision
cargo build -p classmesh-worker --bin classmesh-worker
```

Use the existing reviewed installer/enrollment sequence; never copy unsigned or
unreviewed state into ProgramData or relax executable ACLs. The pinned Worker
must be next to Service and executable by the intended signed-in user. From an
elevated **interactive, non-SYSTEM** operator in that user's active session,
invoke `scripts/mvp-service-scm-guarded.ps1 -Mode Run` with its existing approved
Service/provision paths and exact SHA256 pins, adding `-QualifyWorkerIpc` and
`-ExpectedWorkerSha256 <reviewed exact Worker SHA256>`. Supply the existing
approval acknowledgments only after the external approvals are recorded.

The runner registers only its own disposable service, validates SCM/image/hash/
actual SYSTEM SID/Session 0, then requires a real decoded Worker message after
the existing Hello/Ready exchange. It verifies Worker PID, parent, interactive
SID/session/image/hash and exactly one Service-owned Worker. It terminates that
exact Worker to exercise the production watchdog, requires a new generation and
PID with another decoded report, then intentionally kills its retained Service
process and requires Worker exit within five seconds. The existing ownership-
checked `finally` removes only its own service. Enrollment state remains
intentionally retained. Capture stdout JSON and errors with executable hashes,
source revision, operator/VM and external approval references. A failed run
does not emit success JSON. Failure cleanup must be inspected; never terminate
an unrelated process or delete a replacement service by name alone.

## Evidence boundaries and remaining blockers

- macOS workspace tests, Clippy, formatting and PowerShell nonmutating Plan /
  approval rejection are local checks; see #713 for final exact-head results.
- Hosted Windows tests exercise real process handles, actual Worker rejection
  of an untrusted native server **before any Hello bytes**, real observer PID/
  session admission and decoded-report generation/EOF state. They do **not**
  register a Service or establish a protected LocalSystem installation.
- **Actual LocalSystem SCM Service ↔ interactive Worker IPC: NOT PROVEN.**
  The protected positive/restart/Service-loss runner has not been run because
  independent review, approved enrollment/install and exclusive VM authority
  are absent. Do not infer cross-account process/token query rights from the
  same-account hosted test. The positive run must qualify those rights without
  granting debug privilege or weakening process/token DACLs.
- The primary accept + Hello/Ready sequence now shares a five-second logical
  deadline on a dedicated thread, cancelled with `CancelSynchronousIo` and
  joined before any pipe/buffer is released. Late completion never activates
  Worker. Portable RED/GREEN covers deadline/cancel/drain semantics; native
  tests cover absent client, stalled Hello and actual bytes. A faulty driver
  can delay the required cancellation drain beyond the logical deadline;
  freeing live kernel I/O memory or terminating a Rust thread is unsafe.
- New observer/unsafe Win32 code needs independent qualified security review.
  Physical #288/#411, Teacher UI and deployed QUIC/video remain separate gates.
  No merge, production installation or rollout is authorized by this report.
