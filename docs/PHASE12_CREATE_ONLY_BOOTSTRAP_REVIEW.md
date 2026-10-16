# Phase 12 experimental protected app-root creation — Windows security review

**Status:** isolated Windows API + disposable test fixtures; **NOT** called from production installer or Service. This code must not be used on the real OS ProgramData path without further qualification.

## Behavior

- Accepts an absolute local-drive path with final component exactly `ProgramData` and no parent traversal; pins the existing directory with a non-reparse, exclusive-share HANDLE (its owner/ACL and OS identity are **not** authenticated).
- Uses `CreateDirectoryW` **create-only**, passing an explicit SDDL owner and protected DACL: `O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`. `D:P` blocks inherited Users ACEs. The new root is reopened and strictly attested with the existing SYSTEM/Administrators owner+DACL verifier, no reparse, same-volume distinct file identity and held-HANDLE immediate-child path equality. The parent and root remain held through the returned object.
- Precreated `ClassMesh` roots are rejected with `AlreadyExists`, not adopted, modified, deleted, or repaired. Any post-create attestation failure leaves a suspicious orphan for investigation rather than attempting unsafe automatic cleanup.
- Native Windows tests use **sandboxed** `Temp/ProgramData`, including a Users-inheritable writable parent, a precreated attacker marker and invalid/remote paths. No test modifies the ACL of real `C:\ProgramData`.

## Security gaps — HIGH RISK

1. The caller-supplied `ProgramData` path is not authenticated against the OS Known Folder and volume root. `CreateDirectoryW` accepts path traversal through ancestors before creation; the pinned parent is not a trusted root. A hostile parent with preexisting handles/rename permissions or reparse ancestors remains a TOCTOU risk. No NT relative-open or `CreateDirectory2W` disallow-redirection+returned-HANDLE atomic chain is established.
2. `CreateDirectoryW` creates then separately opens a HANDLE, leaving a possible window; the `SECURITY_ATTRIBUTES` are applied only to a *new* object and do not attest trusted ancestry. A successful sandbox test does not qualify real ProgramData deployment.
3. No durable directory-entry flush or power-loss test, protected checkpoint CAS/anti-rollback, installer migration, service reload/revocation, physical two-PC proof, or production activation. A failed post-create attestation leaves an orphan.
4. Requires an appropriately privileged Windows caller. Do not weaken Windows-wide ACLs or run this against the actual machine's ClassMesh directory as a test.

## Primary Windows API references

- Microsoft `CreateDirectoryW`: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createdirectoryw
- Microsoft `ConvertStringSecurityDescriptorToSecurityDescriptorW`: https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertstringsecuritydescriptortosecuritydescriptorw
- Microsoft file security/access rights: https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights

**Next:** OS-resolved ProgramData/volume root identity, no-redirect relative directory creation with a retained handle, preexisting handle race testing and secure installer integration, then independently durable V2 checkpoint and crash recovery.
