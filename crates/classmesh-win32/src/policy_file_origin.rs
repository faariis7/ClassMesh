//! Windows policy file *leaf* preflight, not an authorization trust decision.
//! A production publisher must additionally pin and attest every ancestor,
//! validate trusted owner/DACL, and anchor a persistent monotonic epoch.
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    GetFileInformationByHandle,
};

const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// Retain the originally opened Windows HANDLE and fail closed on leaf reparse,
/// directories and multiple NTFS hardlinks. This does NOT establish trust in
/// the file owner, DACL or canonical parent directories.
pub fn open_single_link_policy_leaf(path: &Path) -> io::Result<File> {
    // Exclusive sharing prevents subsequent pathname write/delete while this
    // handle is held, but cannot prove the ancestors were trusted on open.
    let file = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
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
    // Safety: file is a live owned File, output points to initialized writable
    // data, and the File is retained on success.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut info) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "policy leaf must be a regular, non-reparse single-link file",
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn rejects_hardlink_and_retains_original_file() {
        let dir = std::env::temp_dir().join(format!(
            "classmesh-win32-policy-leaf-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let original = dir.join("authorization.json");
        let alias = dir.join("alias.json");
        assert!(open_single_link_policy_leaf(&dir).is_err());
        assert_eq!(
            open_single_link_policy_leaf(&original).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        fs::write(&original, b"fixed inert fixture").unwrap();
        {
            let file = open_single_link_policy_leaf(&original).unwrap();
            assert_eq!(file.metadata().unwrap().len(), 19);
        }
        fs::hard_link(&original, &alias).unwrap();
        assert_eq!(
            open_single_link_policy_leaf(&original).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_file(&alias).unwrap();
        let handle = open_single_link_policy_leaf(&original).unwrap();
        assert_eq!(handle.metadata().unwrap().len(), 19);
        drop(handle);
        fs::remove_dir_all(dir).unwrap();
    }
}
