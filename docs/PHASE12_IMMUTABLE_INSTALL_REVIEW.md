> 2026-10-18: [Independent Windows-volume authority experiment](PHASE12_SYSTEM_VOLUME_AUTHORITY_REVIEW.md) adds kernel/global-device cross-checks and protected NT-relative opens. It does not qualify the shared-ancestor ACLs, durable anchor or production integration.

# Phase 12 immutable policy-first install ordering — isolated review

**Status:** Portable contract and fault-injection tests only; not a Windows durable writer, not wired into Service, and not production-qualified.

## Why immutable blobs

The previous epoch-first ordering can strand a valid old policy after the anchor advances. A safer future protocol must never overwrite the currently referenced policy file. Instead, store immutable versioned blobs and commit a separately trusted anchor **last**, only after the candidate blob and directory metadata have been durably flushed. A restart must resolve the exact blob referenced by the anchor and verify its epoch plus SHA-256 binding; it must never silently choose an older `.bak` or another blob. A crash before anchor commit still selects the old blob; a crash after anchor commit selects the new blob. Missing or modified committed blobs fail closed.

## Qualified now

- `stage_then_commit_bound_policy` validates the strictly newer nonzero epoch and the candidate V2 digest before invoking storage callbacks; rejects empty or oversized candidates before side effects.
- A caller-supplied `stage_immutable_and_flush` callback must succeed **before** `commit_trusted_checkpoint`; no receipt is returned on either failure. Publication is caller-owned and must occur only after receipt.
- Unit tests inject invalid epochs, stage failure, checkpoint failure, and crash points; an in-memory immutable-blob model verifies startup selects the exact committed version and rejects missing/mutated content without falling back.
- Windows VM2 x64 Rust on ARM: 19/19 policy-epoch tests and `clippy -D warnings` green.

## Still blocked

The callbacks are **not** trusted storage implementations: neither fsync nor atomic rename nor root-of-volume and ProgramData ancestry, Windows ACL/owner attestation, untrusted existing blobs, preexisting writable handles, directory hardlinks/junctions, cross-process races, independent anti-rollback trust, installer bootstrap, crash durability nor garbage collection are proven. The V2 hash is unkeyed. The old `commit_policy_epoch` helper remains available for isolated callers and must not be mistaken for a crash-safe install. A real implementation must use OS-qualified native retained handles and verify durable commit semantics, including power-loss fault injection, before Service integration. Existing physical and protocol gates remain open.

## Post-commit qualified checkpoint readback (experimental)

`stage_commit_verify_bound_policy` adds a mandatory caller-provided *qualified* checkpoint readback after successful stage/commit callbacks. Only an exact V2 epoch+SHA-256 record match returns `CommittedBoundPolicy`; stale, missing, unreadable, mismatched, or error results fail closed without a receipt. Native Rust tests inject a dishonest success callback, readback failure, and stage failure, and assert stage→commit→readback ordering. **This contract does not implement the independent durable writer, trusted storage origin, fsync, ACL, anti-rollback or production publishing.**


## Independent Registry anchor and reader binding (2026-10-18)

The approved attacker model protects against policy-file rollback within trusted Windows, excluding compromised administrators/kernel and complete disk/snapshot restoration. A test-only machine Registry anchor is independent of replaceable policy files. It creates a new protected key transactionally, never adopts an existing key, checks retained key/parent descriptors, uses the 64-bit view, opens registry links without following them, and accepts one exact 48-byte REG_BINARY V2 record.

A real negative test disproved read-then-write transaction isolation as a monotonicity guarantee: stale 8 overwrote committed 9. The implementation now writes a transaction-unique reservation value before rereading and comparing the entire prior record. Both same-process and separate-process competitors reject; older/equal epochs and stale expected hashes fail closed. Commit, explicit RegFlushKey and exact readback must all succeed before a result is returned. Errors after commit may have advanced storage but never authorize publication; recovery must read/flush/revalidate the current record and must not retry an older expected transition.

The rooted reader consumes the Registry record as epoch+digest authority, opens only that epoch's blob relative to retained state, and parses the canonical verified bytes while the reservation is held. It returns the candidate only after final commit/flush/readback. It does not need a local checkpoint and never falls back to an older blob. This is not a live publication lease; Service install/publication serialization must prevent advancement-after-check from publishing stale policy.

Native targeted evidence covers actual Registry symbolic-link redirection, partial/wrong-type records, OS write denial, unsafe DACL rejection, concurrency, callback error/unwind, and process termination before/after commit. Five registered Registry tests include the child-process entry point. Machine-power interruption, production provisioning/file staging and Service activation remain open. Shared bounded descriptor parsing is generalized to registry objects without changing existing file acceptance. Final VM/SCM/hosted qualification is recorded in AGENT_HANDOFF, not inferred here.

Contracts: [RegOpenKeyTransacted](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeytransactedw), [CreateTransaction rollback on last-handle closure](https://learn.microsoft.com/en-us/windows/win32/api/ktmw32/nf-ktmw32-createtransaction), [RegFlushKey persistence and hive-wide cost](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regflushkey), [Registry rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights). Context7 windows-rs guidance and installed windows-sys0.61.2 bindings were checked; no custom cryptography or transaction emulation.
