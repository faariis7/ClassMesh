# Phase 12: isolated create-only protected state child

**Status:** experimental Windows-only API and disposable test fixtures. Production installer and Service remain unchanged.

## Behavior and tests

- `create_new_protected_state_child(&CreatedAppRoot)` can only be called with a retained object from the **successful create-only** ClassMesh app-root bootstrap. It does not accept arbitrary parent paths or previously opened app-root handles.
- The `CreatedAppRoot` stores its own created path and keeps its original app-root HANDLE alive. `CreatedStateChild<'_>` borrows that object and retains the new `state` HANDLE; the borrow prevents dropping the app-root HANDLE while the state child is used.
- `CreateDirectoryW` creates `state` only if absent, using the same explicit protected SYSTEM/Administrators SDDL as the root. A preexisting `state` (including a hostile marker) fails `AlreadyExists` without adoption, deletion, repair or overwrite.
- After creation, the new state HANDLE is independently attested with the strict owner/DACL, non-reparse, same-volume distinct file identity and immediate-child name under the held app-root HANDLE. Failed post-create attestation leaves an orphan for investigation.
- Native tests cover success, retained-HANDLE rename denial, strict ACL, refusal to recreate and preservation of attacker-precreated marker. Existing root bootstrap tests remain.

## Critical security gaps — unchanged

1. **Untrusted origin:** `ProgramData` argument and volume-root ancestors are not proven to be the OS-resolved Known Folder or opened through an NT relative-HANDLE chain. Concurrent privileged or preexisting-handle directory substitution is not fully excluded.
2. **Non-atomic creation:** `CreateDirectoryW` then separate open is not an atomic create-and-return-HANDLE operation. No directory-entry metadata fsync, power-loss proof or actual Windows installer integration.
3. **No trusted durable policy epoch:** V2 checkpoint, independent monotonic anchor, atomic commit and fail-closed recovery still require separate qualification. No production Service policy loading, authenticated reload, Worker cancellation or physical two-PC E2E.
4. Do **not** modify real `C:\ProgramData` ACLs or test by creating a live `ClassMesh` installation. Tests use disposable `%TEMP%/ProgramData` fixtures only.

**Next:** qualify OS Known Folder and its volume/ancestor chain, native relative HANDLE opens and creation, durable anchor CAS/crash recovery, then gated Service integration.
