# Windows volume authority and relative policy opens

Status: **experimental, compiled only into Win32 unit tests**. No production Service or installer activation.

## Boundary and design

The old chain started from a drive chosen by Known Folder text. Matching it against another open of that text was not an independent origin check. The new `system_volume` path cross-checks the shared Windows directory API, the kernel Object Manager `\SystemRoot` link (with one explicitly bounded `\Device\BootDevice` indirection), and the global drive link `\GLOBAL??\X:`. It accepts only agreement on a direct local `\Device\HarddiskVolumeN` device and the Windows suffix. It then opens that device's root with `OBJ_DONT_REPARSE` and traverses each Windows component and the fixed ProgramData child using retained parent HANDLEs. No environment, local DOS mapping, caller path, recursive alias resolution, or weaker open fallback chooses the root.

This assumes a trusted kernel, Object Manager namespace and machine administrator. It is not a defense against a compromised administrator/kernel or offline disk rollback. The native link-query APIs are documented but carry Microsoft's future-availability caveat: missing exports, access denial and unsupported namespace layouts fail closed. BootDevice query required elevation on VM1. Windows residing directly at a drive root, redirected ProgramData and other device layouts are deliberately unsupported in this experiment.

Known Folder discovery remains a compatibility check, not authority. A poisoned child environment caused SHGetKnownFolderPath to fail with 0x80070002; the root-authority test succeeds independently of that resolver, and ProgramData admission retains fail-closed behavior. Do not advertise the Known Folder API as environment-independent.

Relative opens retain no-follow flags and enforce same-volume/distinct full 128-bit file identities using FileIdInfo. Protected subtree nodes reuse the existing SYSTEM/Administrators owner+DACL attestor before exposing a file for reading. They request READ_CONTROL and READ_DATA / LIST_DIRECTORY with read sharing only. Regular policy files must have exactly one hard link. No ACL predicates were weakened.

## Native findings and tests

- RED: independent-root API refused all calls before implementation.
- RED: metadata-only protected directory handles allowed rename despite omitted delete sharing. Added LIST_DIRECTORY; the same rename-denial regression passed on VM2.
- RED: protected relative policy opener refused the positive fixture before implementation; GREEN checks exact bytes, ACL rejection, hardlinks, existing writers, writable sections after closing their originating file HANDLE, and subsequent write/rename denial.
- Real directory junction (mount-point reparse tag), symlink and retained-parent pathname-substitution regressions are exercised in disposable temp fixtures.
- Disagreement between kernel Windows target/global drive, redirected Known Folder and hostile child-process environment are covered.
- Read-only OS discovery never changes real Windows/ProgramData contents or ACLs. Fixture ACL changes affect only test-owned temporary paths; existing SCM harness uses its own GUID subtree/service.

See ASTRA WORK HANDOFF in `AGENT_HANDOFF.md` for exact current verification status.

## Security review and remaining gates

Unsafe boundary review: repr(C) native structures, bounded UTF-16 sizes, exact system-ABI exports, synchronous calls, initialized output buffers, one owning HANDLE wrapper, no inherited handles, explicit close on failure. NtCreateFile success must be exact STATUS_SUCCESS. Allocation, export lookup, native status and full file-ID failures deny admission. Existing pathname-based APIs remain unchanged; their existence is not production qualification.

**Not solved:** owner/DACL and concurrent metadata-change qualification of the actual shared volume/Windows/ProgramData directories; authentic installed ClassMesh subtree bootstrap; a single opaque retained chain through bounded digest/parser admission; non-NTFS/filesystem-filter compatibility; independently durable monotonic epoch storage and power-loss recovery; live Service publish/revoke integration; physical two-PC qualification. Default ProgramData grants Users creation and attribute rights, so simply applying the existing strict app-directory ACL predicate to ProgramData cannot qualify a normal machine. No system ACL changes are authorized or implemented to hide this mismatch.

Next: design/test the ancestor permission predicate and post-open mutation invariants against disposable replicas of actual root/ProgramData ACLs, including preexisting attribute-write handles. Keep fixed-origin root discovery separate from policy authentication. Only then combine the retained chain with the existing V2 bounded digest reader. Phase A must separately define its rollback attacker model and independent anchor authority; a second ordinary file or an unkeyed digest is not that authority.

## Primary contracts

- [Shared Windows directory](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemwindowsdirectoryw)
- [Object namespaces](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-names) and [local/global DOS devices](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/local-and-global-ms-dos-device-names)
- [NtOpenSymbolicLinkObject](https://learn.microsoft.com/en-us/windows/win32/devnotes/ntopensymboliclinkobject), [NtQuerySymbolicLinkObject](https://learn.microsoft.com/en-us/windows/win32/devnotes/ntquerysymboliclinkobject)
- [NtCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile), [sharing and mappings](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew), [full file identity](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_id_info)
- [Reparse mutation contract](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/4aeefef8-92c3-4abc-af7a-a610caf8a165)

## Atomic relative bootstrap follow-up

`create_relative_protected_directory` is test-only and accepts a retained parent and a single validated child name. It passes fixed protected SYSTEM/Administrators SDDL in OBJECT_ATTRIBUTES and FILE_CREATE to the same native open path, requiring FILE_CREATED and then checking the returned HANDLE's identity, type, attributes and owner/DACL. No pathname reopen, FILE_OPEN_IF adoption, ACL repair, or production installer switch is introduced. This closes the old create/reopen gap for the new primitive; it does not authenticate a caller-supplied parent or establish crash durability. A failed post-create check can leave an orphan, deliberately not removed through a potentially replaced path.

The mutation fixture uses a preexisting FILE_WRITE_ATTRIBUTES HANDLE to install a mount-point REPARSE_DATA_BUFFER after the parent has been retained. Its ordinary-path positive control reaches the attacker's target while NT-relative open and create refuse it on VM1 (0xc0000280). This is native evidence for that Windows/filesystem profile, not proof for all reparse tags or filesystem filters. A separate bootstrap fixture swaps the parent's pathname, grants inheritable Users access to the fixture parent, and verifies protected new descendants, exact one-winner concurrent FILE_CREATE behavior and preservation of existing entries.

Unsafe review: fixed descriptor converted by Windows and freed with LocalFree; descriptor lives through synchronous NtCreateFile; returned File owns the handle before every post-create check. The mutation buffer uses checked u16 sizes, explicit little-endian fields and a synchronous DeviceIoControl lifetime. The helper remains under cfg(all(windows,test)); no untrusted policy bytes reach Service publication.

Follow-up validation: VM1 package fmt/Clippy/84 tests and SCM LocalSystem 2/2; VM2 full workspace fmt/Clippy/tests, independently rebuilt package 84/84 and SCM 2/2. All passed. Exact-head hosted CI remains required before merge. No blocking defect found in the structured review of this test-only scope.

## Shared-ancestor descriptor follow-up

The test-only root walk now obtains READ_CONTROL and checks each volume/Windows/ProgramData directory's descriptor through its retained HANDLE. A separate predicate leaves private-policy restrictions unchanged. The supported machine profile trusts SYSTEM, BUILTIN Administrators and the fixed TrustedInstaller service SID observed on both VMs, never a caller-provided account/name. The owner must be one of these; SYSTEM and Administrators must each have applicable read/list rights. Only structurally bounded ACCESS_ALLOWED ACEs with known inheritance flags are accepted. Inherit-only ACEs do not apply to the current directory; each child is independently checked. Null/empty/unsupported descriptors fail closed.

Windows MapGenericMask uses the documented file mappings. Unknown principals may list/traverse/read, create children and write directory attributes/EAs, matching the observed ProgramData profile; they may not DELETE_CHILD, DELETE, WRITE_DAC or WRITE_OWNER. Unknown access bits and ACE types are rejected. This is not a general Windows effective-access engine: conservative rejection of deny/object/callback ACEs is deliberate. Existing application-root FILE_CREATE and strict private-child checks prevent treating an untrusted newly created child as policy authority.

This snapshot does not revoke preexisting handles, authenticate historical ACLs, or prove behavior of all filesystem filters/EAs. The kernel/administrator/TrustedInstaller remain trusted; malicious prior administrative ACL grants and offline rollback are not solved. Attribute-handle junction attack evidence is limited to the tested profile. A production capability must retain the entire chain through bounded parsing and separately qualify mutation/read stability and durable epoch installation.

Native tests first failed against a denying stub. VM1 now passes actual read-only C:/Windows/ProgramData descriptors and disposable replicas rejecting untrusted destructive/security rights and owner; 86 package tests plus SCM ACL 2/2 and root 5/5 pass. VM2 full workspace fmt/Clippy/tests, 86 unit tests and SCM ACL 2/2 + root 5/5 also passed with cleanup; hosted gate pending. No system ACL changes. Bounded GetSecurityInfo/GetAce/SID parsing is extracted into the shared Windows module file_security_descriptor. The existing production leaf attestor uses it with unchanged acceptance rules; the new shared-ancestor predicate remains test-only. This removes duplicate unsafe parsing without sharing the two acceptance policies.

Primary contracts: [file security and generic mappings](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights), [file access constants](https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants). Structured review checked owner-implied WRITE_DAC, inherit-only handling, unknown rights, generic expansion, bounded ACE/SID reads and descriptor/HANDLE lifetimes; remaining gates above are explicit.

Independent read-only Astra review after extraction found no blocking regression in strict leaf rules, bounds/lifetimes, shared masks or retained-handle integration. It did not rerun native tests. VM1 post-extraction fmt/Clippy/86 tests and SCM 2+5 passed; VM2 post-extraction workspace fmt/Clippy/tests (86 Win32) and SCM 2+5 also passed with cleanup. Exact-head hosted CI is required before merging.
