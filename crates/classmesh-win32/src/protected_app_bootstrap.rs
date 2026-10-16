//! Experimental create-only Windows ClassMesh app-root bootstrap. NOT a
//! production installer: caller-provided ProgramData ancestry is untrusted.
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, Prefix};

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, GetFileInformationByHandle,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
};

const OPEN_REPARSE: u32 = 0x0020_0000;
const BACKUP_SEMANTICS: u32 = 0x0200_0000;

fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "unqualified ClassMesh bootstrap root")
}

fn valid_program_data_path(path: &Path) -> bool {
    path.is_absolute()
        && matches!(path.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        && path.file_name() == Some(std::ffi::OsStr::new("ProgramData"))
        && !path.components().any(|c| matches!(c, Component::ParentDir))
}

fn info(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut result = BY_HANDLE_FILE_INFORMATION {
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
    // Safety: live HANDLE and initialized writable output structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut result) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result)
}

fn hold_non_reparse_directory(path: &Path) -> io::Result<File> {
    let dir = OpenOptions::new().read(true).share_mode(0)
        .custom_flags(OPEN_REPARSE | BACKUP_SEMANTICS).open(path)?;
    let metadata = info(&dir)?;
    if metadata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || metadata.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(denied());
    }
    Ok(dir)
}

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // Safety: SDDL conversion returns a LocalAlloc-owned descriptor.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// Pins the parent and the newly created root. Parent trust and OS-selected
/// ProgramData identity remain UNPROVEN; this is NOT a production trust token.
#[derive(Debug)]
pub struct CreatedAppRoot {
    root: File,
    _parent: File,
}

impl CreatedAppRoot {
    pub fn with_root<T>(&self, action: impl FnOnce(&File) -> T) -> T {
        action(&self.root)
    }
}

/// Create-only protected directory with a DACL that refuses inherited Users
/// ACEs. A preexisting ClassMesh directory is ALWAYS rejected, never repaired,
/// deleted, adopted or overwritten. If post-create attestation fails, the
/// orphan remains for manual investigation (no unsafe automatic cleanup).
/// This does not guarantee parent path authenticity, metadata fsync, atomic
/// create+open, or privileged concurrent mutation protection.
pub fn create_new_protected_classmesh_app_root(program_data: &Path) -> io::Result<CreatedAppRoot> {
    if !valid_program_data_path(program_data) {
        return Err(denied());
    }
    let parent = hold_non_reparse_directory(program_data)?;
    let path = program_data.join("ClassMesh");
    // D:P disables parent ACL inheritance. O:BA sets Administrators as owner;
    // only SYSTEM and Administrators may access the directory or descendants.
    let sddl: Vec<u16> = std::ffi::OsStr::new(
        "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
    ).encode_wide().chain(std::iter::once(0)).collect();
    let mut raw: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // Safety: NUL-terminated immutable UTF-16 SDDL and valid output pointer.
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl.as_ptr(), SDDL_REVISION_1, &raw mut raw, std::ptr::null_mut(),
    ) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let descriptor = Descriptor(raw);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0.cast::<c_void>(),
        bInheritHandle: 0,
    };
    let path_wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    // Safety: pointers refer to live UTF-16 and SECURITY_ATTRIBUTES buffers.
    // CreateDirectoryW refuses preexisting directory without modifying it.
    if unsafe { CreateDirectoryW(path_wide.as_ptr(), &raw const attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // The existing strict ACL verifier is used for post-create qualification.
    // Parent and child HANDLEs are both retained, but parent trust is unproven.
    let root = super::policy_file_origin::open_protected_directory_for_bootstrap(&path)?;
    let parent_info = info(&parent)?;
    let child_info = info(&root)?;
    if parent_info.dwVolumeSerialNumber != child_info.dwVolumeSerialNumber
        || (parent_info.nFileIndexHigh == child_info.nFileIndexHigh
            && parent_info.nFileIndexLow == child_info.nFileIndexLow) {
        return Err(denied());
    }
    Ok(CreatedAppRoot { root, _parent: parent })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    #[test]
    fn create_only_protected_root_excludes_inherited_users_and_refuses_recreate() {
        let fixture = std::env::temp_dir().join(format!("classmesh-bootstrap-{}", std::process::id()));
        let program_data = fixture.join("ProgramData");
        fs::create_dir_all(&program_data).unwrap();
        // A writable parent is an intentional hostile inheritance fixture;
        // never modify the actual Windows ProgramData ACL.
        assert!(Command::new("icacls.exe").arg(&program_data)
            .args(["/grant", "*S-1-5-32-545:(OI)(CI)M"]).status().unwrap().success());
        let created = create_new_protected_classmesh_app_root(&program_data).unwrap();
        assert!(created.with_root(|f| f.metadata().unwrap().is_dir()));
        assert!(fs::rename(program_data.join("ClassMesh"), program_data.join("renamed")).is_err());
        drop(created);
        assert_eq!(create_new_protected_classmesh_app_root(&program_data).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        let root = program_data.join("ClassMesh");
        assert!(super::super::policy_file_origin::open_protected_directory_for_bootstrap(&root).is_ok());
        fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn precreated_untrusted_root_is_never_adopted_or_modified() {
        let fixture = std::env::temp_dir().join(format!("classmesh-bootstrap-precreated-{}", std::process::id()));
        let program_data = fixture.join("ProgramData");
        let root = program_data.join("ClassMesh");
        fs::create_dir_all(&root).unwrap();
        let marker = root.join("attacker.txt");
        fs::write(&marker, b"original").unwrap();
        assert_eq!(create_new_protected_classmesh_app_root(&program_data).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(marker).unwrap(), b"original");
        fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn refuses_non_programdata_ambiguous_and_remote_paths() {
        for path in [
            r"C:\ProgramData\..\ProgramData",
            r"\\host\share\ProgramData",
            r"C:\NotProgramData",
            "ProgramData",
        ] {
            assert_eq!(create_new_protected_classmesh_app_root(Path::new(path)).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        }
    }
}
