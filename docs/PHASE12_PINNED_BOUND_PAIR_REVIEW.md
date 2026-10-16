# Phase 12 — experimental pinned V2 checkpoint and policy HANDLE pair

**Status:** isolated Windows-only native file preflight and Windows Service-package integration test. No production Service startup/reload changes.

## Scope

- `open_protected_bound_policy_pair_in_app_root(app_root, epoch)` derives `policy-{epoch:016x}.json` and a **fixed experimental** `policy-checkpoint.v2` leaf. It validates nonzero epoch and absolute local-drive `ClassMesh` root, retains two file HANDLEs and the `ClassMesh/state` ancestor HANDLEs for the full `with_files` callback, and never opens a `.bak` or chooses an alternate epoch.
- Both files require the same strict SYSTEM/Administrators owner/DACL qualification, no reparse, no hardlinks, no directory masquerade. Parent/child resolved names must match immediate children, and all HANDLE identities must share a volume with distinct file IDs.
- Windows unit tests reject checkpoint Users ACL, checkpoint hardlink, missing epoch and zero epoch, and prove held checkpoint/blob rename denial. Service-package integration verifies exact V2 bound checkpoint+policy bytes from the **same two pinned HANDLEs**, with startup epoch equality and negative mismatch.

## Trust boundaries still OPEN

- **Not a trusted origin**: the caller-supplied `app_root` and `epoch` are not independently authenticated. No volume-root or default `C:\ProgramData` ancestry proof, no NT relative-open chain, no installer bootstrap, and no guarantee against all concurrent privileged or preexisting-handle races.
- **Not a durable trust anchor**: `policy-checkpoint.v2` is only an experimental fixture filename. This API does not create, atomically commit, fsync, recover or independently protect a monotonic anchor. Unkeyed SHA-256 alone does not authenticate a checkpoint.
- **Not production**: `classmesh-service::load_control_state()` is unchanged. No authenticated reload, Worker cancellation, power-loss test, physical two-PC E2E or security-gate closure. Default Windows ProgramData ACLs must not be modified or silently weakened.

**Next:** secure installer-controlled subtree under the actual OS-resolved ProgramData prefix, pinned volume/NT relative directory opens, durable checkpoint CAS and power-loss qualification; only then gated Service activation.
