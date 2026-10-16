# Phase 12 experimental create-only policy blob stage — security review

**Status:** A filesystem stage primitive only. It is **not** a trusted durable Windows policy store and is **not wired to production Service**.

## What this changes

- `classmesh-security::policy_blob_stage::stage_new_policy_blob` validates a nonzero epoch and a nonempty, maximum-4-MiB candidate **before** opening files. The filename is derived exclusively from the epoch (`policy-<16 hex digits>.json`), not caller-controlled path fragments.
- `OpenOptions::create_new(true)` atomically rejects preexisting targets instead of truncating/reusing old files. `write_all` and `File::sync_all` flush the newly created file; a retained read/write `File` HANDLE is read back and SHA-256 checked without reopening its pathname. The retained handle and staged path are returned to the caller.
- Errors after file creation can leave an **orphan**. No automatic deletion, overwrite, rename, reuse or fallback occurs. Tests confirm duplicate epoch, precreated attacker content, hardlink alias, torn/orphan target, malformed candidate and post-stage tampering are rejected or detected.
- Windows VM2 x64 Rust on ARM: 6/6 targeted tests and `clippy -D warnings` passed.

## Explicit trust and durability gaps

1. **No parent directory durability:** `File::sync_all` does not prove that creation of the directory entry survives sudden power loss. No Windows `FlushFileBuffers` on a pinned directory or atomic checkpoint commit is implemented. No power-loss test performed.
2. **No immutable ACL guarantee:** `create_new` prevents *this call* from overwriting an existing file, but a privileged or untrusted writer with rights on the directory/file could still modify, rename or delete it after staging. A retained read/write HANDLE is not a read-only immutable object. The caller must independently protect/attest the leaf and all ancestors, reject reparse/mount traversal, and prevent preexisting attacker handles before trusting any file.
3. **No path authority:** The `trusted_directory: &Path` argument is an **unverified assumption**, not a trust token. Path substitution, junctions, ACL inheritance, owner and full `ProgramData`/volume ancestor attestation remain open. Do not call this primitive from an untrusted directory or treat its returned path as authenticated.
4. **No trusted anchor or recovery:** No anti-rollback, atomic two-object commit, persistent independently protected epoch source, crash recovery or garbage collection. Orphans must not be reused; an old blob must not be silently chosen if the trusted anchor references a missing newer blob. The V2 SHA-256 digest is unkeyed and is not authentication by itself.
5. **No runtime activation:** The production `classmesh-service` loader, reload, revocation and Teacher/Worker cancellation remain untouched. Windows SCM LocalSystem, actual installer, real ProgramData bootstrap and physical two-PC gates remain pending.

**Next:** OS-qualified Windows directory-HANDLE and file-HANDLE writer, protected leaf owner/DACL, directory-entry flush/commit semantics, trusted checkpoint CAS + recovery; only then wire startup/reload. Do not weaken the OS-wide ProgramData ACL.
