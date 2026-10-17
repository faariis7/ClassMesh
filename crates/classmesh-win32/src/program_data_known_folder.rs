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

#[cfg(test)]
mod tests {
    use super::*;

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
