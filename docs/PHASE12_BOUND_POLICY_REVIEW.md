# Phase 12 V2 epoch-bound policy checkpoint — security review

**Scope:** Isolated parser, checkpoint codec and disposable Windows tests only. **No production Service wiring.** Builds on the V1 monotonic epoch transition contract.

## What is qualified

- V2 record: `CMPBND02` (8 bytes) + nonzero little-endian u64 epoch + SHA-256 digest (32 bytes), exactly 48 bytes. V1 16-byte epoch-only records are intentionally rejected by the V2 loader.
- A bounded reader (maximum 4 MiB policy, one-byte over-limit check) rejects missing, empty, truncated, overlong or wrong-magic checkpoints; rejects altered policy bytes **even at the same epoch**. Short-read readers work.
- The verified bytes are retained in memory and parsed directly into the existing `PersistedState` parser. The candidate parser never reopens the policy pathname, never falls back to `.bak`, and checks exact epoch equality against a supplied trusted epoch. A changed-but-valid JSON file is rejected before parsing.
- Windows VM2 x64 Rust under ARM emulation: 60/60 `classmesh-security` tests, 1/1 disposable Windows Service-package dual protected leaf HANDLE integration, native Rustfmt and Clippy `-D warnings` pass.

## Non-negotiable limitations

- SHA-256 here is **unkeyed**, not a MAC or signature. An attacker who can rewrite the checkpoint can recompute the hash. Its value depends entirely on the independently verified, immutable-to-untrusted-users origin of the checkpoint and the policy.
- Both files in the Windows test use separately protected leaves, not an independently trusted protected *durable* epoch anchor or a trusted full ProgramData/volume ancestor walk. The `trusted_epoch` argument is caller-supplied and not authenticated by this module. No atomic two-file transaction or durable fsync/write protocol has been implemented.
- The parser is not an authorization capability and has not been connected to `classmesh-service` production startup, reload or active-session cancellation. Existing legacy `.load()` still permits `.bak` recovery and remains unchanged; do not use it as a security qualification.
- Current fail-closed commit-first order can leave the Service unavailable if a crash occurs between checkpoint and policy publication. Recovery/rollback-resistance and trusted Windows bootstrap remain blocked, as do physical two-PC, #477/#479 and v11 ClipboardRead gates.

**Next gate:** design and test a protected Windows anchor and atomic crash-recovery protocol; prove real ProgramData/root ancestry and LocalSystem SCM behavior before any production activation. No system-wide ACL relaxation.
