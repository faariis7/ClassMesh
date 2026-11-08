# Service/Worker identity: qualified security acceptance packet

Status: engineering candidate, **NOT APPROVED**. Qualified reviewer, release
authority, installer authority and exclusive Windows-lab reservation references:
**MISSING**. No person, signature, CA or lab approval is supplied by this file.
Scope: user task and [#716 review](https://github.com/faariis7/ClassMesh/pull/716#issuecomment-6721249865).
Base c141df23; #713/#716/#710 are not merged/imported. #717 ownership is unchanged.

## Executable engineering delivered

Off-default `experimental-service-identity-evidence` builds
`classmesh-service-identity-evidence.exe`. Neither product application enables
it. `--self-audit` reads the actual existing caller token; `--observe-existing-service`
first performs that audit, then MAY attempt read-only access to the already
running local Windows `DcomLaunch` SCM process. It creates no service/account,
does not connect to any product pipe and never changes a token, privilege or ACL.

Eligibility is deliberately strict: unchanged primary token, no impersonation,
no administrator SID (even deny-only/filtered), not elevated, default elevation
type, medium integrity, interactive session, no restrictions/AppContainer/UIAccess,
no debug assignment and only the ordinary Windows-user privilege allowlist.
Unknown facts refuse before target access. `TokenElevationTypeDefault` alone
does not establish an ordinary account. Native token ID/modified ID bracket the
audit; a full audit is repeated after measurement. No synthetic caller is fed
into the native public entry point.

The target attempt is exactly `0x00101000` (QUERY_LIMITED_INFORMATION |
SYNCHRONIZE), noninheritable, no larger-right retry or delegated fallback.
Success records actual granted mask, original process object PID/creation time,
session and final liveness. Optional `OpenProcessToken(TOKEN_QUERY)` on that same
object can independently observe its current SID; a denial is recorded, never
replaced by an SCM-config or executable-name guess. The sampled existing Windows
service is NOT ClassMesh and does not prove ClassMesh's eventual process DACL.

`scripts/tests/service_identity_evidence.ps1` retains the original measurement
child, imposes a 20-second result deadline and bounded cleanup/drain, and writes
a fresh reviewer record including exact EXE hash, revision, timestamp and native
JSON. The underlying synchronous SCM/token metadata calls have no in-process
wall-time guarantee; the whole child is the isolation/cancellation boundary.
Driver-level inability to terminate/confirm exit is failure, never evidence.

All JSON and this packet are review material, not authority. Every report has
`authenticated_service_worker=false`, and signed loaded-image trust is always
`UNVERIFIED`. A passing CI refusal test does not mean ordinary-account access
was measured. A filtered/restricted admin experiment is not substituted for it.

## Independent claim/source/binding and refusal matrix

| Claim | Independent source and object binding | Required ordering / refusal | Evidence / responsible owner |
| --- | --- | --- | --- |
| Caller really ordinary | OS primary token user/groups/privileges/integrity/elevation/restrictions, plus thread-token absence; retained token ID/modified ID | Audit before ANY target query and after; unknown/admin/filtered/restricted/debug/impersonating/changed => NOT_MEASURED_CALLER_CONTEXT or INVALIDATED | Native self-audit/refusal in CI. Actual ordinary-account run pending if runner is administrative. Lab operator supplies unchanged account context. |
| Minimum process access possible | OS OpenProcess exact mask; NtQueryObject actual granted mask, inheritance flags | One attempt only; denied => preserve numeric OS error, no retry with more rights | Executable measurement path implemented; outcome depends on a qualifying real context. Does not establish target account. |
| Same running process object | Retained original process HANDLE, PID and creation time; kernel pipe peer PID/session and independently queried fixed SCM PID | No reopen after acquisition; compare before/after slow work; signaled/failed wait, changed SCM PID, mismatch => terminal rejection | New generation/refusal unit tests are synthetic. Native #716 race repair below uses real owned-child death; protected ClassMesh binding pending. |
| Target currently SYSTEM | OS primary TokenUser on EXACT retained process, or separately qualified independent OS/current-account witness bound to that PID/creation object | SCM LocalSystem string, owner DACL, Session 0, parent name and a Service-supplied SID are insufficient. Unknown witness => reject identity | Native optional query implemented; cross-account ordinary-context result pending. Broker/launch-attestation alternative requires NEW qualified trust decision, not self-attestation. |
| SCM identity consistent | Local fixed service object QUERY_STATUS/QUERY_CONFIG plus protected service configuration / reviewed activation witness | QueryServiceConfig may describe NEXT start. Never use it as current token evidence. Reject changes during acquisition; an observed unchanged sample is not an exclusive config lease | Existing #716 source observations only. Reviewer must approve current-account proof and activation/update invariant. |
| Running executable is approved signed image | Independently provisioned release authority/pin; verified signature chain/revocation/time policy; exact hash and retained file identity; independently justified binding to the running image section or qualified startup witness | Matching path strings or hashing a newly opened file at that path do not prove loaded bytes. Missing section/startup binding => reject even if signature valid | NOT IMPLEMENTED/NOT PROVEN. Qualified reviewer and release authority must specify acceptable proof before auth code is added. |
| Protected installation path | Trusted local volume identity, original retained ancestry and leaf file IDs; effective owner/DACL policy; no reparse/mapped-drive/namespace/ADS ambiguity or writable replace/delete route | Hold reviewed ancestry/file leases through session; reject uncertainty. Account for directory child-creation vs mutation of the specific entry and INHERIT_ONLY ACE semantics; do not change root ACLs to pass | Installer/path-policy reviewer must approve exact policy. #700 strict gate remains unchanged; #716 lab ImageSample is not this proof. |
| Disconnect/restart/epoch | Kernel endpoint, original process objects, new independently bound generation/challenge; command protocol only AFTER admission | EOF/partial transfer/cancellation/Service death => close session; restart cannot revive old epoch; cleanup only exact owned Worker, never reopened PID/remote reused numeric handle | Existing #713 runtime work stays gated. New/716 synthetic refusal is not protected restart qualification. Real handshake/loss/restart tests pending external lab. |
| I/O safety | Owned I/O state and buffers, reviewed deadline/cancel/drain and retained-object final check | Timeout/incomplete acquisition => no authority; never detach borrowed buffers or claim byte bound is wall-time bound | New measurement uses process isolation. Production auth needs separately reviewed runtime cancellation design. |
| Qualified approval | Named independent reviewer with relevant Windows/token/SCM/image-signing/path-policy expertise, exact source SHA and signed artifacts | No author/bot/automated source review substitutes approval. Missing/excluded scope => remain Draft and fail closed | MISSING: reviewer, CA/enrollment, installer ACL/path and lab references. Coordinator records actual external evidence. |

## Concrete #716 defect and reviewable repair

At exact d546360, `check_observations` checks retained-process liveness before
its final file hash. The process can exit during that work and success can still
be returned. This is an observation-consistency defect, not a product auth bypass.

`patches/service-identity-evidence/716-race-red.patch` extracts that existing
ordering without fixing it and adds two deterministic native tests. An owned
child actually dies inside the controlled slow observation callback; RED must
fail with the exact `IDENTITY_EVIDENCE_RACE` assertion (not compile/environment
failure). A second test preserves the original observation error.
`716-race-green.patch` adds the final wait on the SAME retained object after
successful slow work. Errors still propagate unchanged.

The patches are tested only on a disposable detached exact #716 checkout by
`scripts/tests/service_identity_race_patch.ps1`. They do not import #716 into
this branch, modify its remote source branch, or merge it. Adoption into #716
remains a separate reviewed change under its existing gates. No old 14-test
result is rerun as new product proof; only the two changed-behavior regressions
and patched-source static checks are requested.

## What the qualified reviewer must decide

1. Current-account proof: direct OS token observation under the ordinary caller,
   or precisely identified independent OS provider/launch witness. Define its
   permissions, replay/liveness binding, machine trust and failure semantics.
   A Service-supplied process/token handle cannot establish its own provenance.
2. Loaded-image proof: which kernel binding or externally authenticated startup
   invariant establishes that the retained running process loaded these exact
   reviewed bytes. If none is defensible with permitted rights, reject this
   approach. Do not weaken checks or silently switch authentication strategy.
3. Image authority: actual organization release identity, chain/EKU, digest
   policy, validity/timestamp/revocation handling, protected pin origin and
   rollback/version policy. The signer pin MUST originate outside the bundle.
   Disposable test certificates, a JSON approval field and a self-signed fixture
   are not release/enrollment authority.
   Machine enrollment is a separate authority: approved StudentDevice role,
   stable PrincipalId, real issuer chain/expiry/EKU and active authorization,
   matching nonexportable machine CNG key, protected control configuration and
   Registry/file-bound policy lease. Reuse the existing StudentDevice staging
   and guarded installation tools; do not replace them with a Teacher fixture
   or treat a release code-signing certificate as machine enrollment.
4. Installer/path policy: approve exact owners/effective ACE semantics, local
   volume/ancestry leases, replacement/update serialization, no running hot
   image substitution, configuration-change behavior, cleanup and rollback.
   No Windows/root ACL modification is authorized by this candidate.
5. Runtime admission/revocation: confirm acquisition ordering, all final rechecks,
   deadline behavior, Service/Worker generations, reconnect, unauthorized peers
   and no Hello/Ready/commands before completed independent proof. Production
   authentication remains unchanged until separately approved implementation.

## Authorized-lab prerequisites and first real steps

Lab owner supplies a real exclusive disposable target reservation and authority
reference; named operator, OS/build/architecture, account/session, snapshot and
cleanup/rollback scope, time window and resource budget. VM1/VM2 are forbidden
until those references and explicit permission identify the target. This packet
does not reserve a machine, enable a scheduled task or authorize installation.

1. **First executable prerequisite:** in the authorized existing ordinary user
   session, run the exact hashed evidence EXE using the bounded script above.
   Keep its native refusal/OS result. Obtain independent current-account witness
   for the same retained target object if its token cannot be queried. This
   still does not run ClassMesh or prove its protected Service DACL.
2. Obtain qualified decisions 1–5 and independently enrolled CA/release pins.
   Prepare exact matching signed/hash-pinned Service/Worker artifacts and the
   reviewed protected installation/launch plan, including process-object and
   loaded-image binding evidence. No synthetic approvals or production keys.
3. **First joint Service/Worker run:** only after external authorization, execute
   the already guarded #713 SCM qualification route for those exact artifacts,
   with actual approval references, expected hashes, protected path and cleanup.
   Record SCM LocalSystem process identity, intended ordinary Worker PID/token/
   session, native pipe peer checks, real Hello/Ready + capability message,
   unauthorized-process refusal, restart, Service loss and zero orphan children.
   Every missing check remains open. No merge/install is authorized here.

## Primary sources

- [Process access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [Cross-account OpenProcessToken remarks](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
- [Primary/impersonation token membership distinction](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-checktokenmembership)
- [SCM config may describe next start](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfigw)
- [CreateProcessAsUser can enable privileges temporarily](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw)

Exact new code/CI results and reviewer disposition are recorded in this Draft
PR, separately from qualified security approval and actual protected runtime.
