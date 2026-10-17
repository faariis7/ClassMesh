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
