# Phase 12E18c — Service-to-Worker v12 key bootstrap qualification

## Experimental findings consolidated — 2026-10-14 (no approved bootstrap)

- #477 **hard security FAIL (still open/red)**: read-only requested HANDLE into actual child did NOT guarantee section object integrity because the child could duplicate the HANDLE with `FILE_MAP_WRITE` and map a writable view of the original `PAGE_READWRITE` object. Never loosen this assertion. [#479](https://github.com/faariis7/ClassMesh/issues/479).
- #481 **GREEN comparative evidence:** `PAGE_READONLY` **object at creation** denies write-mapping even when same-session child attempts handle escalation. It contains only zero-filled public bytes; does NOT solve securely populating an unpredictable fresh key in protected memory.
- #482 **GREEN negative design evidence:** `VirtualProtect(PAGE_READONLY)` changes one mapped view, NOT the underlying original `PAGE_READWRITE` section maximum; another write-capable view remained possible after desired-rights handle duplication. Therefore *post-population view protection alone is not a remedy*.
- Do **not** infer privileged Session-0→interactive Worker identity, key secrecy, cross-user exploit or transferable signed capabilities from these same-session/inert tests. Section option A remains BLOCKED. Independently evaluate trusted outbound v12 Service→Worker delivery with OS-attested Service identity, current Worker process HANDLE + SID/session, live Service capability/ReadClipboard grants, exact six-field bound request, strictly one-time HMAC key/nonce/expiry and safe cancellation/zeroization. Neither new outbound nor existing inbound-only v12 is authenticated key bootstrap yet. Generic IPC v11 must remain free of secrets.

Microsoft APIs: [DuplicateHandle](https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-duplicatehandle), [MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile), [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect).

**Status:** security design and test plan only (no code or production activation).
**Tracking:** [#465](https://github.com/faariis7/ClassMesh/issues/465),
[#328](https://github.com/faariis7/ClassMesh/issues/328).
**Dependency:** Phase 12E18b inactive per-request HMAC proof in PR #468.
**Release gates:** IPC minor 11 ClipboardRead remains failure-only; physical and
native clipboard E2E qualification remain OPEN.

## Live qualification evidence — 2026-10-14 (post-#474)

- `main=bdcc88b1f01f836d9c6e1d2a3f02de1c0d63e8eb`, no open PRs. #470 proved a **same-session** inert event HANDLE can be duplicated into a separate child. #473 added a **read-only** anonymous pagefile-backed mapping with an inert public marker, duplicated to the **actual target-child PROCESS HANDLE**; child reads marker but cannot obtain a writable view. #474 added a separate **wrong-target child** that fails to map the target's duplicated HANDLE number. Both #473/#474 passed exact-head hosted Portable Rust AND complete Windows Build CI.
- This qualifies only the Windows HANDLE mechanics in the **same session with inert data**. It does **NOT** prove service account LocalSystem / Session 0 privilege boundaries, other-user SID/session target denial, remote handle revocation/teardown, Worker reincarnation/PID reuse, key-secret isolation, no leak by privileged processes or successful production v12 bootstrap. No secret has been transported.
- **Next qualification gate:** on a resource-safe privileged native Windows environment, prove actual Service→interactive launched Worker `CreateProcessAsUserW` target PROCESS HANDLE with harmless marker, cross-session POSITIVE + wrong-process/wrong-session NEGATIVE + owned target/local HANDLE cleanup/kill+wait/timeout/revocation and live Service grants/control. Independently security-review before choosing a production key channel. Do not use inbound-only sensitive pipe or legacy v11 for key delivery.
- **Resource gate:** Mac Data ~13 GiB available (97% used); VM2 56.7 GB used vs 56 GB disk cap and suspended. Do not resume VM2, expand its disk or delete VMPal snapshots until non-destructive storage remediation. Keep native E2E and physical two-PC/GPU/classroom/accessibility gates OPEN.

## STOP — read-only HANDLE assumption failed native security qualification (2026-10-14)

In [PR #477](https://github.com/faariis7/ClassMesh/pull/477), hosted Windows Build run `38594235925` failed the security assertion, while Portable Rust succeeded. The actual same-session child received a read-only HANDLE (requested `FILE_MAP_READ`) to a parent-created `PAGE_READWRITE` pagefile section holding **only fixed public inert bytes**. `MapViewOfFile(FILE_MAP_WRITE)` directly on that HANDLE failed, but child-side `DuplicateHandle` asking for `FILE_MAP_WRITE` minted a HANDLE that permitted a writable `MapViewOfFile`. **Option A below is BLOCKED as specified.** Requested HANDLE rights and closing a remote HANDLE alone do not guarantee a section is immutable. Do not weaken the failing test, transfer a real HMAC key, or claim a cross-user/Session-0 exploit from same-session evidence. Any actually read-only-at-creation section would still need a safe, non-persistent means of populating fresh secret data; it is not an approved alternative by assumption. Evaluate independently authenticated, narrow outbound v12 bootstrap with robust Service identity and exact launched-Worker process HANDLE, current grants/control, nonce/deadline/replay checks and native cross-session negative/positive evidence. See [#479](https://github.com/faariis7/ClassMesh/issues/479) and [#465](https://github.com/faariis7/ClassMesh/issues/465).

## Requirement and current boundary

A valid OS-attested native named-pipe client, an alive Worker process HANDLE,
and a still-current six-field control binding do **not** establish knowledge
of a Service-issued v12 secret. HMAC challenge verification needs a fresh,
unpredictable 256-bit per-request key delivered only to the exact launched
Worker, without trusting its own asserted PID, session, generation, control
sequence, or request ID.

The current future-v12 `SensitivePipeListener` is **inbound-only**. The
Service cannot send its challenge or key over that handle. Its
`wait_for_bound_worker` is an inactive admission preflight, not a
bidirectional authenticated channel. Existing generic IPC v11 is production
failure-only and **must never carry key bytes or a transferable bearer
credential**. The future-v12 proof primitive is also inactive and does not
by itself authorize clipboard bytes.

## Options to qualify before choosing a design

**A. Direct targeted handle duplication:** Service allocates a short-lived,
non-inheritable, uniquely owned memory section holding one per-request key,
then uses Windows `DuplicateHandle` with the **already owned** process HANDLE
from `CreateProcessAsUserW` to place an exact handle into the launched Worker.
Only after OS peer attestation can the Service communicate the nonsecret
destination handle identifier through an **independently authenticated**
Service→Worker control channel. A raw handle number is potentially a
bearer capability within that process; neither it nor a key goes on generic
v11. Investigate required `PROCESS_DUP_HANDLE` access and cross-session
behavior, and prove that cancellation closes **both** local and remote
mapping handles, unmaps views, and wipes the key. Do not log handles.

**B. Dedicated outbound v12 bootstrap channel:** Allocate a separate
ACL-restricted, local-only Service→Worker channel with explicit OS
PID/session + owned live Worker process HANDLE admission, one-use control
binding and fresh deadline. Verify the Service identity to the Worker
through a strong separately provisioned mechanism; a pipe name or merely
matching current PID is NOT authentication. Until mutual trust can be
demonstrated, this path must not release keys. A general-purpose duplex
upgrade of the existing inbound-only listener is out of scope and may
weaken existing invariants.

**Rejected shortcuts:** inheriting a handle directly from a Session-0
Service to an interactive-session Worker; writing the key in argv,
environment, registry, disk, generic v11 frames, filenames or logs;
using predictable nonce/PID/session as the secret; accepting untrusted
Worker-provided identity; broadening ACL to all interactive users.

## Mandatory test-first evidence before creating a transport

1. Verify on **native Windows** whether duplication into the actual
   `CreateProcessAsUserW` Worker process works across sessions.
   An ordinary same-process `DuplicateHandle` unit test is insufficient.
2. Prove that the destination handle's object maps **only** in the intended
   launched process and that a different process with the same user SID
   cannot obtain or use it.
3. Reject stale/mismatched Worker generation, Windows OS-reported PID and
   session; reject a process that died after first admission (recheck the
   original owned HANDLE before key release).
4. Reject changed authenticated Teacher control session, sequence or
   request ID before duplication, after OS connection, and before any
   key-consumption acknowledgment.
5. Reject missing or revoked Service-owned ClipboardText capability and
   ReadClipboard permission at every exposure/consumption transition.
6. Reject wrong v12 major/minor, absent/fabricated HMAC proof, reused
   nonce/key/challenge, reordered message, clock regression and expiry.
7. Exhaust cancellation/timeout/disconnect races. Close remote/local
   handles and wipe unexposed key material **after** any outstanding OS
   I/O completes; a logical timeout alone does not free an in-flight
   `OVERLAPPED` buffer.
8. A second Worker process after the first exits must never inherit its
   predecessor's session key or request capability, even if Windows
   later reuses the PID.
9. Test multiple simultaneous authorized requests and negative
   cross-request replay without reusing a handle or key.
10. Reject malformed or oversized metadata; keep all operations and
    outstanding states strictly bounded.
11. Confirm zero production v11 wire changes and zero plaintext,
    challenge key or bearer capability in logs, crash artifacts and
    captured generic IPC frames.
12. Run Rustfmt, Clippy `-D warnings`, complete workspace tests, native
    VM1/VM2 Windows positive/negative tests when their storage is safe,
    and exact-HEAD hosted Portable Rust + Windows Build CI before merging
    any code.

## Implementation split — no broad one-shot PR

- **12E18c1** (test-only exploratory): Windows cross-session process/
  HANDLE qualification using transient test processes and inert bytes;
  no secret or control/clipboard APIs.
- **12E18c2** (if c1 passes security review): narrow owned, RAII,
  worker-bound bootstrap section/channel with secure key lifetime;
  still no Service→Teacher data.
- **12E18c3:** attach negotiated challenge/response to verified native
  v12 OS peer and live Service control/grants with deterministic replay,
  denial, disconnect and cancellation tests.
- Later independent work: cancellation-safe native OVERLAPPED payload
  `ReadFile`, zeroizing ingester and one trusted Teacher result.

## Resource/qualification note

Two Windows ARM64 VMPal VMs exist, but VM2 currently reports a disk quota
error (56.7 GB used vs 56 GB configured), and the Mac has roughly 14 GiB
free. Do not resume VM2, expand it, remove snapshots or assert cross-VM
evidence until storage is diagnosed. Hosted Windows CI is useful for
Windows APIs but is not cross-session physical two-PC classroom acceptance.

**Decision:** Keep both bootstrap options **unselected** until native,
cross-session negative and positive evidence plus independent security
review establishes that the chosen path cannot deliver a key to the wrong
process or to a revoked request.
