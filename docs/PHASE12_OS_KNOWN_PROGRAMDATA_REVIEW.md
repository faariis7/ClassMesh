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

Graphify advisory resolved: raw lexical checks preserve Windows verbatim local-drive paths (`\\?\C:\ProgramData`) while continuing to reject UNC and ambiguous descendant components.

## Read-only HANDLE candidate follow-up

`pin_os_program_data_candidate()` now opens the real OS Known Folder location as a retained, read-only directory HANDLE with normal Windows sharing and `FILE_FLAG_OPEN_REPARSE_POINT`. It rejects a non-directory or reparse-point leaf by HANDLE attributes. This is **not** a trusted ancestry proof: disk/volume root, intermediate junctions/mount points, redirected Known Folder identity, owner ACLs and TOCTOU require independent validation. Do not wire it to installer, policy admission, or production Service. No mutations to real ProgramData.

## Read-only ancestor HANDLE diagnostic

`pin_os_program_data_ancestor_candidates()` now retains read-only file HANDLEs for each absolute path ancestor from volume root to the OS-selected ProgramData directory and rejects reparse leaves, non-directories, and volume-serial changes. Native tests include an elevated symlink fixture and the real Known Folder. **Still not trusted for production**: the opens are separate pathname lookups, not NT relative opens under a verified parent; parent-child identity, actual OS/system-volume authority, registry redirection and TOCTOU remain unqualified. This diagnostic never writes to or alters ACLs on ProgramData.

## Retained directory identity adjacency (experimental)

The read-only `pin_nonreparse_ancestor_chain` diagnostic now checks each retained child's same-volume, distinct-file-ID and immediate-parent **HANDLE-resolved path** relation using the existing `attest_immediate_child` predicate. It also validates raw local drive-rooted input *before* Windows path normalization, rejecting UNC, slash/duplicate separators, and dot traversal. A native negative test swaps the expected child HANDLE with an unrelated, equally valid directory on the same volume and confirms fail-closed rejection; symlink tests remain. **Do not treat this as a trusted root:** the initial volume identity is not authenticated independently, the opens still use mutable pathnames rather than NT root-relative operations, and the independently opened handles cannot exclude a race across opens. Never wire to service/installer policy admission, and do not write or change ACLs in system ProgramData.

## Test-only native root-relative directory open (experimental)

The Windows `nt_relative_directory` test module prototypes `NtCreateFile` with a retained `RootDirectory` HANDLE and a **single validated relative component**, no write or create disposition, `OBJ_DONT_REPARSE`, `FILE_OPEN_REPARSE_POINT`, and a read-only directory HANDLE. In native Windows tests it rejects a symlink and continues opening the original directory after the pathname of its pinned parent was renamed and replaced. This is deliberately `#[cfg(test)]`: it is NOT exported to production or used by the installer or privileged Service. The parent HANDLE has no independently attested system-root authority, and exact NT API behavior, ACL constraints, Windows-version compatibility, mount-point semantics, failure recovery, and physical qualification remain open. See Microsoft `NtCreateFile` and `OBJECT_ATTRIBUTES` documentation before future production use.
