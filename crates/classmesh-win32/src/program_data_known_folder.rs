//! Read-only Windows OS Known Folder discovery, NOT an attested trust root.
//! Never resolve security-critical ProgramData from mutable environment text.
use std::io;
use std::path::{Component, PathBuf, Prefix};

use windows_sys::Win32::System::Com::{
    COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};

struct ComScope;
impl Drop for ComScope {
    fn drop(&mut self) {
        // Safety: this guard is constructed only after successful CoInitializeEx
        // (including S_FALSE), and balanced on the SAME thread.
        unsafe { CoUninitialize() };
    }
}

struct TaskMem(*mut u16);
impl Drop for TaskMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // Safety: SHGetKnownFolderPath returns CoTaskMem-allocated PWSTR.
            unsafe { CoTaskMemFree(self.0.cast()) };
        }
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unqualified OS ProgramData path",
    )
}

/// Validate the raw spelling before Path normalization can hide dot segments,
/// duplicate separators or mixed separators. This remains only a text check;
/// it does not authenticate filesystem ancestry or a directory HANDLE.
fn valid_os_program_data_path(text: &str) -> bool {
    if text.contains('/') || text.contains('\0') || text.len() < 3 {
        return false;
    }
    // Windows verbatim drive paths have a legitimate \\\\?\\ prefix.
    // Validate the drive-rooted remainder without treating prefix delimiters
    // as duplicate path separators. UNC verbatim paths still fail below.
    let raw_segments = text.strip_prefix(r"\\?\").unwrap_or(text);
    let parts: Vec<_> = raw_segments.split('\\').collect();
    if parts
        .iter()
        .skip(1)
        .any(|segment| segment.is_empty() || *segment == "." || *segment == "..")
    {
        return false;
    }
    let path = PathBuf::from(text);
    path.is_absolute()
        && matches!(path.components().next(), Some(Component::Prefix(p))
            if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        && path.file_name() == Some(std::ffi::OsStr::new("ProgramData"))
        && !path.components().any(|c| matches!(c, Component::ParentDir))
}

/// Read the machine's actual Windows Known Folder ID for common ProgramData.
/// No environment-variable fallback, no alternate directory, no writes.
/// The returned PATH is not an authenticated/pinned directory HANDLE, and
/// neither the volume root nor ancestors are attested. This must not be used
/// alone as an authorization decision or production bootstrap trust token.
pub fn resolve_os_program_data_path() -> io::Result<PathBuf> {
    // Safety: null reserved pointer and documented COM apartment flag.
    let hr = unsafe { CoInitializeEx(std::ptr::null(), COINIT_MULTITHREADED as u32) };
    if hr < 0 {
        return Err(io::Error::other(format!("COM init failed: {hr:#x}")));
    }
    let _com = ComScope;
    let mut raw: *mut u16 = std::ptr::null_mut();
    // Safety: known GUID, initialized output pointer, and null user token.
    let folder_id = FOLDERID_ProgramData;
    let hr = unsafe {
        SHGetKnownFolderPath(&raw const folder_id, 0, std::ptr::null_mut(), &raw mut raw)
    };
    let _owned = TaskMem(raw);
    if hr < 0 || raw.is_null() {
        return Err(io::Error::other(format!(
            "ProgramData Known Folder failed: {hr:#x}"
        )));
    }
    // Safety: Windows returns a NUL-terminated PWSTR. Cap reads at the Windows
    // long-path limit; fail rather than accept an unterminated oversized path.
    let mut len = 0usize;
    while len < 32_767 && unsafe { *raw.add(len) } != 0 {
        len += 1;
    }
    if len == 0 || len >= 32_767 {
        return Err(invalid());
    }
    // Safety: the first `len` UTF-16 units were read above and remain live.
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, len) })
        .map_err(|_| invalid())?;
    if !valid_os_program_data_path(&text) {
        return Err(invalid());
    }
    let path = PathBuf::from(text);
    Ok(path)
}

/// Read-only candidate: pin the OS-selected ProgramData directory by HANDLE.
/// Only the leaf reparse/directory attributes are checked here. This DOES NOT
/// prove trusted volume-root ancestry or authorize production bootstrap.
pub fn pin_os_program_data_candidate() -> io::Result<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        GetFileInformationByHandle,
    };
    let path = resolve_os_program_data_path()?;
    // Open the reparse leaf itself. Keep normal OS sharing on the system-wide
    // directory: never block other applications or assume exclusive ancestry.
    let held = OpenOptions::new()
        .read(true)
        .share_mode(0x0000_0001 | 0x0000_0002 | 0x0000_0004)
        .custom_flags(0x0020_0000 | 0x0200_0000)
        .open(path)?;
    let mut info = BY_HANDLE_FILE_INFORMATION {
        dwFileAttributes: 0,
        ftCreationTime: Default::default(),
        ftLastAccessTime: Default::default(),
        ftLastWriteTime: Default::default(),
        dwVolumeSerialNumber: 0,
        nFileSizeHigh: 0,
        nFileSizeLow: 0,
        nNumberOfLinks: 0,
        nFileIndexHigh: 0,
        nFileIndexLow: 0,
    };
    // Safety: retained valid owned File and initialized mutable OS output.
    if unsafe { GetFileInformationByHandle(held.as_raw_handle(), &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(invalid());
    }
    Ok(held)
}

/// Reject raw ambiguous or remote paths before std::path normalization.
/// Still only a lexical preflight, never trusted root authorization.
fn valid_local_ancestor_spelling(path: &std::path::Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    if text.contains('/') || text.contains('\0') {
        return false;
    }
    let raw = text.strip_prefix(r"\\?\").unwrap_or(text);
    if raw
        .split('\\')
        .skip(1)
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return false;
    }
    path.is_absolute()
        && matches!(path.components().next(),
        Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
}

/// Check that every held child is the named immediate child of the held
/// parent. This attests the identities *observed* by separately opened
/// path HANDLEs; it does not make their creation atomic or establish a
/// system-authoritative trust root.
fn attest_ancestor_handle_chain(path: &std::path::Path, held: &[std::fs::File]) -> io::Result<()> {
    let mut ancestors: Vec<_> = path.ancestors().filter(|p| p.is_absolute()).collect();
    ancestors.reverse();
    if held.len() != ancestors.len() || held.is_empty() {
        return Err(invalid());
    }
    for idx in 1..held.len() {
        let child_name = ancestors[idx]
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(invalid)?;
        super::policy_file_origin::attest_immediate_child(&held[idx - 1], &held[idx], child_name)?;
    }
    Ok(())
}

/// Diagnostic only: retain a HANDLE for each pathname ancestor, including
/// the volume root. Refuses leaf reparse points or cross-volume changes.
/// Opens remain pathname-based: this is NOT an atomic relative HANDLE chain.
fn pin_nonreparse_ancestor_chain(path: &std::path::Path) -> io::Result<Vec<std::fs::File>> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        GetFileInformationByHandle,
    };
    if !valid_local_ancestor_spelling(path) {
        return Err(invalid());
    }
    let mut ancestors: Vec<_> = path.ancestors().filter(|p| p.is_absolute()).collect();
    ancestors.reverse();
    let mut held = Vec::with_capacity(ancestors.len());
    let mut volume = None;
    for ancestor in ancestors {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001 | 0x0000_0002 | 0x0000_0004)
            .custom_flags(0x0020_0000 | 0x0200_0000)
            .open(ancestor)?;
        let mut info = BY_HANDLE_FILE_INFORMATION {
            dwFileAttributes: 0,
            ftCreationTime: Default::default(),
            ftLastAccessTime: Default::default(),
            ftLastWriteTime: Default::default(),
            dwVolumeSerialNumber: 0,
            nFileSizeHigh: 0,
            nFileSizeLow: 0,
            nNumberOfLinks: 0,
            nFileIndexHigh: 0,
            nFileIndexLow: 0,
        };
        // Safety: file is owned and live; output is initialized/writable.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || volume.is_some_and(|v| v != info.dwVolumeSerialNumber)
        {
            return Err(invalid());
        }
        volume.get_or_insert(info.dwVolumeSerialNumber);
        held.push(file);
    }
    if held.is_empty() {
        return Err(invalid());
    }
    attest_ancestor_handle_chain(path, &held)?;
    Ok(held)
}

/// Read-only ancestry diagnostic. Callers must not treat this vector of
/// path-opened HANDLEs as a trusted bootstrapping or authorization chain.
pub fn pin_os_program_data_ancestor_candidates() -> io::Result<Vec<std::fs::File>> {
    pin_nonreparse_ancestor_chain(&resolve_os_program_data_path()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancestor_walk_rejects_reparse_leaves_and_retains_regular_handles() {
        let fixture =
            std::env::temp_dir().join(format!("classmesh-programdata-walk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir_all(fixture.join("regular")).unwrap();
        let handles = pin_nonreparse_ancestor_chain(&fixture.join("regular")).unwrap();
        assert!(!handles.is_empty());
        assert!(handles.last().unwrap().metadata().unwrap().is_dir());
        std::os::windows::fs::symlink_dir(fixture.join("regular"), fixture.join("redirect"))
            .expect("elevated native Windows symlink fixture");
        assert_eq!(
            pin_nonreparse_ancestor_chain(&fixture.join("redirect"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(handles);
        std::fs::remove_dir_all(&fixture).unwrap();
    }

    #[test]
    fn generic_ancestor_walk_refuses_normalized_traversal_and_remote_roots() {
        for raw in [
            r"C:\sandbox\..\ProgramData",
            r"C:\sandbox\.\ProgramData",
            r"C:\sandbox\\ProgramData",
            r"C:\sandbox/ProgramData",
            r"\\server\share\ProgramData",
            r"\\?\UNC\server\share\ProgramData",
            r"C:ProgramData",
        ] {
            assert!(
                !valid_local_ancestor_spelling(std::path::Path::new(raw)),
                "accepted {raw}"
            );
        }
        assert!(valid_local_ancestor_spelling(std::path::Path::new(
            r"C:\ProgramData"
        )));
        assert!(valid_local_ancestor_spelling(std::path::Path::new(
            r"\\?\C:\ProgramData"
        )));
    }

    #[test]
    fn ancestry_attestation_rejects_substituted_same_volume_child_handle() {
        let fixture = std::env::temp_dir().join(format!(
            "classmesh-ancestor-identity-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir_all(fixture.join("expected")).unwrap();
        std::fs::create_dir_all(fixture.join("decoy")).unwrap();
        let expected = fixture.join("expected");
        let mut legitimate = pin_nonreparse_ancestor_chain(&expected).unwrap();
        attest_ancestor_handle_chain(&expected, &legitimate).unwrap();
        let decoy = pin_nonreparse_ancestor_chain(&fixture.join("decoy")).unwrap();
        *legitimate.last_mut().unwrap() = decoy.last().unwrap().try_clone().unwrap();
        assert_eq!(
            attest_ancestor_handle_chain(&expected, &legitimate)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(legitimate);
        drop(decoy);
        std::fs::remove_dir_all(&fixture).unwrap();
    }

    #[test]
    fn actual_os_known_folder_ancestor_candidates_are_live_directories() {
        let held = pin_os_program_data_ancestor_candidates().expect("nonreparse OS path");
        assert!(held.len() >= 2, "volume root and ProgramData must be held");
        assert!(held.iter().all(|dir| dir.metadata().unwrap().is_dir()));
    }

    #[test]
    fn held_os_known_folder_is_readonly_directory_candidate() {
        let held = pin_os_program_data_candidate().expect("must pin actual OS ProgramData");
        assert!(held.metadata().unwrap().is_dir());
    }

    #[test]
    fn os_known_folder_is_absolute_local_programdata_not_test_fixture() {
        let path = resolve_os_program_data_path().unwrap();
        assert!(path.is_absolute());
        assert_eq!(path.file_name(), Some(std::ffi::OsStr::new("ProgramData")));
        assert!(path.is_dir());
        assert!(!path.starts_with(std::env::temp_dir()));
    }

    #[test]
    fn rejects_noncanonical_dot_segments_and_ambiguous_separators() {
        for path in [
            r"C:\temp\.\ProgramData",
            r"C:\temp\..\ProgramData",
            r"C:\temp//ProgramData",
            r"C:\temp\\ProgramData",
            r"C:\temp/ProgramData",
        ] {
            assert!(!valid_os_program_data_path(path), "accepted: {path}");
        }
        assert!(valid_os_program_data_path(r"C:\ProgramData"));
        assert!(valid_os_program_data_path(r"\\?\C:\ProgramData"));
        assert!(!valid_os_program_data_path(
            r"\\?\UNC\server\share\ProgramData"
        ));
        assert!(valid_os_program_data_path(r"D:\SystemData\ProgramData"));
    }

    #[test]
    fn repeated_resolution_returns_same_os_selected_location() {
        let first = resolve_os_program_data_path().unwrap();
        let second = resolve_os_program_data_path().unwrap();
        assert_eq!(first, second);
    }
}
