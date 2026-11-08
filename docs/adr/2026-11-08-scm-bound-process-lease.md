# Candidate: SCM-bound read-only Service process lease

Status: DESIGN/PROTOTYPE ONLY. Implements the conditional decision in
[#713 comment](https://github.com/faariis7/ClassMesh/pull/713#issuecomment-6720452154).
Base: integration `c141df23caf07e58dffd4dffe2dad208dad4818e`.
No production authentication, installer, CA/enrollment, ACL or VM authority is granted.

## Alternatives and changed trust boundary

| Approach | Benefit | Limitation / decision |
| --- | --- | --- |
| A: Worker opens Service process and primary token | Worker independently checks the token associated with that kernel process | Cross-account `OpenProcessToken` is not an established unprivileged capability; Microsoft documents a debug-privilege requirement. Keep current production path unchanged and fail closed. |
| B: Service duplicates only its process QUERY_LIMITED_INFORMATION + SYNCHRONIZE handle; Worker independently binds SCM, pipe and approved image | Retains the process object and observes its death without exposing a token | Candidate only. LocalSystem identity now relies on independently read SCM configuration and reviewed installed image, rather than independently opening the process token. This delegates access; it is a security-model change even without a DACL edit. |
| C: additionally duplicate TOKEN_QUERY | Can inspect a SYSTEM SID without opening the token cross-account | Rejected for this prototype: independent SCM binding may make it unnecessary; a token handle by itself does not prove which process owns it. Adds token exposure without resolving association. |

No SeDebugPrivilege, impersonation, token adjustment, process mutation, remote
handle duplication right in Worker, or permission relaxation is acceptable.
The Service alone would need PROCESS_DUP_HANDLE on the original launched Worker
object. The Worker receives only `0x00101000` (QUERY_LIMITED_INFORMATION |
SYNCHRONIZE), noninheritable, never DUPLICATE_SAME_ACCESS. Read-only handles do
not prevent an already compromised recipient from duplicating/forwarding its
own handle; that adversary is not made safe by this design.

## Ordering proposed for future review, not activated here

1. Read a fixed local `ClassMeshService` SCM object using CONNECT and only
   QUERY_CONFIG/QUERY_STATUS. Require own-process, Running, nonzero PID,
   LocalSystem account and exact registered executable/arguments. No shell,
   environment expansion, unquoted-path resolution or service-name input from
   a pipe. Ambiguous paths/configuration are rejection conditions.
2. Obtain pipe server PID/session directly from the connected kernel pipe,
   before reading any bootstrap bytes. Require the SCM PID and Session 0.
3. Independently open/retain that process with minimum query/synchronize
   rights, if OS policy permits. Query its executable path and creation time.
   Independently resolve and retain the reviewed protected executable and
   ancestry, verify the external release authority/signature and exact hash,
   match registered/running file identity. Re-read SCM and pipe observations
   around acquisition. A path string or an unsigned hash supplied by Service
   cannot supply trust. If this independent acquisition is denied, STOP:
   accepting a Service-supplied handle to bootstrap Service identity is circular.
4. Only after step 3 could a separately reviewed bootstrap transfer be consumed.
   Service must attest the primary and bootstrap OS client PID/session against
   its original live launched Worker handle, independently check intended user
   token SID, and bind a fresh random challenge to that generation, process
   creation time and endpoints. No globally reusable bootstrap capability.
5. Worker would compare the delegated object against the already retained
   independent Service object (PID, creation time, image identity, liveness),
   inspect granted rights and inheritance, recheck SCM/pipe/image, and retain
   the object throughout the session. Wrong rights/object/epoch, partial reads,
   EOF, unexpected extra bytes or any recheck failure closes the session with
   no Hello/Ready or capability report. No fallback to path A or unsigned IPC.
6. Every restart gets new retained process objects/challenge/generation. Service
   death invalidates the session; Worker must stop and close its owned copies.
   After ambiguous transfer the Service retires its exact launched Worker and
   confirms exit. Never close a target numeric handle remotely after the
   recipient might have reused that number. Future I/O must use bounded
   overlapped operations with cancellation and drain before freeing buffers.

Steps 3 and 5 expose a useful design question: if the Worker can independently
retain the exact minimum-right process object, it may need **no delegation at
all**. This prototype measures that prerequisite; it does not assume a handle
transfer solves a denied independent acquisition. A reviewed noncircular
alternative is required before implementing any actual bootstrap channel.

## Threats and rejection criteria

| Attacker/action | Required response |
| --- | --- |
| Local attacker squats pipe / lies about PID/SID | Ignore claims; OS pipe PID/session must equal independently queried SCM. |
| PID reused or retained process dies | Compare creation identity and retain original object; no reopen-by-PID after admission; stop on signaled/failed wait. |
| SCM PID/config/image substituted | Requery same SCM object; reject configuration/epoch/image changes; admin/SYSTEM compromise is outside this candidate threat model, not solved by SCM. |
| Unknown signature/pin or file modified | Deny. A caller-provided digest is lab comparison only, not installed trust. Retain reviewed file/ancestry in any future implementation. |
| Wrong account/recipient | Service must compare OS token SID/session of original launched Worker before transfer; test same-account mechanics separately from SYSTEM. |
| Substituted token/handle, pseudo handle, excessive rights/inheritance | No token transfer. Reject nonprocess, wrong creation identity, signaled object, wrong granted mask or inheritable copy. |
| Replay/stale generation/Worker restart | Challenge and retained objects belong to one generation; no reuse after EOF/restart. |
| Service loss, broken pipe, partial/cancelled I/O | Terminal rejection and owned-resource cleanup; no proof emitted from incomplete observations. |

## Bounded executable prototype

Off-by-default `experimental-service-peer-probe` in `classmesh-win32` only.
Neither application enables or calls it. It contains (1) an explicitly
synthetic rejection model with terminal invalidation, (2) native read-only
SCM/pipe/process observation with retained process lifetime, and (3) native
unprivileged tests of minimum-right duplication into an owned child. Native
observations NEVER authorize IPC and do not implement a bootstrap listener or
parse remote numeric handles. Model success is named `NeedsQualifiedReview`.
No token handle is sent anywhere. No signing certificates, trust pins or
protected state are created. No SCM mutation APIs are used.

The native collector does not implement external signed authority, protected
ancestry pinning or a complete image-to-process identity lease. Therefore it
cannot produce an authenticated Service session even when observations match.
This is an explicit refusal to cross the unresolved trust boundary. Native
child/stdin tests prove mechanisms only; they do not simulate a security approval.

## Acceptance / evidence boundary

- TDD: forged owner, wrong PID/session/account, unknown/changed image, rights,
  substituted object/creation time, replay/restart/epoch, EOF/partial transfer,
  Service death, terminal rejection.
- Native hosted Windows: actual pipe owner/closed pipe, process object rights,
  noninheritance, wrong object, retained process death and owned-child cleanup;
  read-only SCM absence/error path. No service registration or privilege use.
- Local rustfmt, workspace tests/Clippy and opt-in feature tests/Clippy; exact
  head hosted Windows/Portable + CodeQL/Gitleaks; independent source review.
- Qualified trust-model, CA/enrollment, ACL/path policy and installation review
  remain REQUIRED. Real exclusive disposable-lab authority and approved
  signed/hash-pinned artifacts are additionally required for a protected run.
- Actual cross-account LocalSystem IPC, protected SCM runtime and physical
  hardware evidence remain NOT PROVEN. Automated review is not qualified approval.

## Primary sources checked 2026-11-08

- [OpenProcessToken cross-account remarks](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
- [DuplicateHandle destination, masks and inheritance](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle)
- [Process access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [SCM and service access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
