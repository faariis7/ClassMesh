# Phase 12 isolated Windows epoch-scoped protected policy leaf

**Status:** experimental native Windows preflight and test integration; not connected to production `classmesh-service`.

## What is proven by this batch

- The caller supplies a numeric, nonzero epoch; the Windows opener constructs only `policy-{epoch:016x}.json` under an absolute, drive-local `ClassMesh/state` subtree. It rejects relative, UNC, parent-traversal and non-ClassMesh app-root paths. No caller-supplied filename, `.bak`, or fallback selection is accepted.
- The opener retains separate Windows HANDLEs to `ClassMesh`, `state`, and the selected leaf throughout parsing. It requires SYSTEM/Administrators owner and strict DACL on each, denies leaf reparse/hardlinks/directories, validates same-volume distinct file IDs, and checks that the held state/leaf resolved paths are immediate named children of the held parents.
- Windows native VM1 ARM64 and VM2 x64 tests exercise protected positive, pinned rename denial, wrong epoch, invalid epoch/path, Users ACL injection on state, and hardlink negative. A Windows Service-package integration test uses the **same pinned leaf HANDLE** to validate exact V2 checkpoint policy-byte digest, rejecting a same-epoch wrong digest and a missing epoch.
- Native SCM LocalSystem and hosted Windows CI are separate qualifications and must be recorded only after actual execution.

## Remaining HIGH-risk gates (not fixed here)

1. The `app_root: &Path` argument is not an authenticated OS root. The drive root, `ProgramData` ancestor and mount/reparse ancestry are **not** qualified by an NT relative-HANDLE chain. The strict experimental `open_protected_policy_in_program_data` still rejects default Windows `ProgramData` ACLs; **do not change system-wide ACLs or relax them to make tests pass**.
2. Path-based opens before parent-handle checks are not a complete TOCTOU proof; preexisting attacker handles and privileged concurrent mutation are not fully excluded.
3. Neither the V2 test checkpoint nor this file opener proves independently protected, monotonic, atomically committed durable epoch, file/directory metadata durability after power loss, or secure first-install bootstrap.
4. Production `load_control_state`, authenticated reload, Worker cancellation, and physical two-PC gates remain unchanged and blocked. Do not advertise production policy hardening as complete.

**Next:** trusted installer-created ProgramData app root, OS-validated parent directory-HANDLE relative opens, independently durable V2 checkpoint and crash recovery, then gated Service startup/reload and revocation. Keep all new APIs isolated until the chain is proven.
