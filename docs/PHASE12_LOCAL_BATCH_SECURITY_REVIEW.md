# Phase 12 local-first policy-origin security review — 2026-10-16

**Status: preliminary Windows-native qualification only, NOT production acceptance.**
**Branch:** `batch/phase12-policy-origin-qualification` — intentionally unpushed.

## Actual trust boundary and proof

The isolated Windows-only Rust policy opener opens the file once with
`FILE_FLAG_OPEN_REPARSE_POINT` and exclusive sharing and retains the exact HANDLE.
`GetFileInformationByHandle` rejects leaf directories, reparse points and multiple
hardlinks. `GetSecurityInfo` is called on the same live HANDLE; the SYSTEM and
Administrators allowed ACEs must EACH grant READ_DATA/LIST_DIRECTORY and
READ_CONTROL (or mapped GENERIC_READ/ALL), not merely mention those SIDs.
A RED native Windows regression proved a SYSTEM write-only ACE was previously
accepted despite the trusted-SID name; after the bounded mask fix both leaf
and ancestor write-only regressions pass on VM1/VM2, including SCM LocalSystem.
A NULL DACL,
untrusted owner or trustee, non-allow ACE, unknown flags, truncated or invalid
SID, missing SYSTEM/Administrators allowance, or excessive ACE count is denied.

`PinnedPolicyCandidate` retains the ClassMesh application directory and state
directory handles together with the policy leaf. A separate, stricter
`PinnedProgramDataCandidate` also pins a **test** ProgramData prefix.
`GetFinalPathNameByHandleW` verifies direct-child path relationships using those
already-open handles; `GetFileInformationByHandle` additionally requires
matching volume serial numbers and different file IDs at every pinned parent/
child edge. Native positive fixture plus synthetic mismatched-volume and
same-file-ID negative tests pass on VM1/VM2. This does NOT authenticate the
volume root, mount manager or prior-open races. Lexical UNC/traversal and
reparse paths are denied.
The bounded `DurableAuthorizationState::parse_primary_from_open_file` consumes a
clone of the same trusted candidate HANDLE in the isolated Service-package
integration tests; no pathname reopen is required to parse those fixtures.

### Observed Windows evidence

- VM1 ARM64: **seven Rust file-origin unit tests PASS** in an actual disposable
  SCM own-process LocalSystem Service (SID S-1-5-18, session 0).
- VM2 Windows ARM64 running Windows x64-emulated test binaries: **seven Rust
  unit tests PASS** in the same genuine SCM LocalSystem configuration.
- VM2: **three `classmesh-service` package integration tests PASS**
  under SCM LocalSystem, including pinned ProgramData→ClassMesh→state→leaf
  path and bounded parser, and denial of an untrusted Users-modify parent.
- Standalone disposable read-ACE native Windows tests passed on VM1 and VM2.
- Temporary SCM services and test directories are created with unique names
  and deleted. Final independent resource scan is required before batch PR.

## Blocking security gaps (DO NOT enable production reload)

1. The real **C:\\ProgramData** on VM1 was read without mutation: owner
   `NT AUTHORITY\SYSTEM`, with `BUILTIN\Users` `ReadAndExecute` (OI,CI)
   and **Write (ContainerInherit)** explicit allowed ACEs, plus
   `CREATOR OWNER` (InheritOnly) and SYSTEM/Admin FullControl. The Users
   Write ACE is therefore not just an ambiguous formatting artifact. The strict experimental ProgramData gate correctly
   fails closed for extra trustees. Do **not** weaken it or alter Windows global
   permissions to make tests pass; design an installer-verified app-root bootstrap
   and account for Windows directory-specific create vs delete-child rights.
2. No root-of-volume/mount-point or fully atomic NT native relative-directory
   HANDLE walk. `GetFinalPathNameByHandleW` is a useful consistency check but
   not a proof against all adversarial prior-open HANDLE, mount or race cases.
3. Windows Administrator is trusted by the current owner/DACL model. A
   previously issued writable HANDLE cannot be revoked by acquiring an
   exclusive read HANDLE; this failure mode remains outside current proof.
4. No independent protected on-disk monotonic generation anchor; pure
   `verify_next_policy_epoch` is only a decision helper. No recovery/bootstrap
   or attested atomic durable commit exists.
5. `LiveAuthorizationStore` already has in-process compare-and-publish and
   envelope-time revocation checks, but **no trusted authenticated durable
   publisher/reloader**, and no proof of canceling every already-running
   Teacher/Worker action on policy revocation.
6. Tests are virtual Windows evidence, not Phase 4 physical two-PC end-to-end
   qualification. Full hosted Windows Build and Portable Rust CI is required
   on the eventual exact PR HEAD.

**Deliberately unchanged:** `load_control_state()` production legacy loader,
protocol v11 ClipboardRead failure-only, Issue #477 physical acceptance and
Issue #479 prohibition of Section HANDLE secret bootstrap.
