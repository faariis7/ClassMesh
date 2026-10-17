# Phase 12 — OS Known Folder ProgramData resolver (read-only)

**Status:** experimental, Windows-only read-only discovery. No production installer/Service wiring; no filesystem mutation.

## Implemented

- Uses `CoInitializeEx`/`CoUninitialize` with balanced per-thread COM scope, calls `SHGetKnownFolderPath(FOLDERID_ProgramData)` with no mutable environment-string fallback, frees returned string with `CoTaskMemFree` on success or failure, and rejects COM/HRESULT errors.
- Bounds the returned UTF-16 string to 32,767 units and rejects zero length, missing NUL, malformed surrogate encoding, relative/UNC/non-drive paths, traversal and non-`ProgramData` leaf.
- Native Windows tests resolve the OS Known Folder twice, require identical absolute local path, existing directory and no temporary fixture redirection. Both interactive elevated and disposable SCM LocalSystem contexts must be tested independently. **No test writes to or changes the ACL of real ProgramData.**

## Still NOT qualified for production

- A Known Folder path is OS-selected text, **not** a pinned/attested directory HANDLE or volume root. Registry/OS folder redirection, ancestor junctions/reparse, mount points and concurrent changes still require explicit OS-handle identity and trust checks.
- This resolver is **not yet used** by `create_new_protected_classmesh_app_root`, which remains a sandboxed test-only helper accepting a caller path. Do not combine the two and claim trusted bootstrap without full ancestry, no-redirect create+open and race proof.
- No independent durable checkpoint, atomic commit, power-loss testing, production Service reload/revocation or physical two-PC validation.

## Primary Microsoft API references

- `SHGetKnownFolderPath`: https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath
- Known Folders and COM initialization requirements: https://learn.microsoft.com/en-us/windows/win32/shell/known-folders

**Next:** bind the OS-selected root to a pinned, no-reparse, identity-attested HANDLE and verify volume-root/ancestor chain before allowing any installer creation. No system-wide ACL changes.

## Follow-up: raw path spelling validation (isolated)

Before `PathBuf` parsing, reject dot and parent segments, duplicate/mixed separators and embedded NUL. This is a read-only defense against lexically ambiguous Known Folder text, not OS-backed root attestation. This additional hardening does not authorize real ProgramData writes or activation. Native Windows tests and exact-head CI remain required before merge.
