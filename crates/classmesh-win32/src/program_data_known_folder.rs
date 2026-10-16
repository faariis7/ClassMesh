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
    let path = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(raw, len)
    }));
    let drive = matches!(path.components().next(), Some(Component::Prefix(p))
        if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)));
    if !path.is_absolute()
        || !drive
        || path.file_name() != Some(std::ffi::OsStr::new("ProgramData"))
        || path.components().any(|c| matches!(c, Component::ParentDir))
    {
        return Err(invalid());
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_known_folder_is_absolute_local_programdata_not_test_fixture() {
        let path = resolve_os_program_data_path().unwrap();
        assert!(path.is_absolute());
        assert_eq!(path.file_name(), Some(std::ffi::OsStr::new("ProgramData")));
        assert!(path.is_dir());
        assert!(!path.starts_with(std::env::temp_dir()));
    }

    #[test]
    fn repeated_resolution_returns_same_os_selected_location() {
        let first = resolve_os_program_data_path().unwrap();
        let second = resolve_os_program_data_path().unwrap();
        assert_eq!(first, second);
    }
}
