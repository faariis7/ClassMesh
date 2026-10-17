//! Experimental read-only relative directory HANDLE acquisition.
//! Root authority is NOT attested. Never enable production Service use here.
use std::fs::File;
use std::io;

use std::ffi::c_void;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    GetFileInformationByHandle,
};

#[repr(C)]
struct NativeUnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct NativeObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *mut NativeUnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
struct NativeIoStatusBlock {
    status_or_pointer: usize,
    information: usize,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    #[link_name = "NtCreateFile"]
    fn nt_create_file(
        file_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut NativeObjectAttributes,
        io_status_block: *mut NativeIoStatusBlock,
        allocation_size: *mut i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *mut c_void,
        ea_length: u32,
    ) -> i32;
}

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "unqualified relative directory HANDLE",
    )
}

/// Experimental read-only, root-relative one-component directory open.
/// The parent HANDLE must be independently authenticated by the caller;
/// this method does NOT establish its authority or production eligibility.
pub(crate) fn open_relative_readonly_directory(parent: &File, leaf: &str) -> io::Result<File> {
    if !super::policy_file_origin::safe_child_leaf(leaf) {
        return Err(denied());
    }
    let mut utf16: Vec<u16> = leaf.encode_utf16().collect();
    if utf16.is_empty() || utf16.len() > 255 {
        return Err(denied());
    }
    let length = u16::try_from(utf16.len() * 2).map_err(|_| denied())?;
    let mut name = NativeUnicodeString {
        length,
        maximum_length: length,
        buffer: utf16.as_mut_ptr(),
    };
    let mut object = NativeObjectAttributes {
        length: std::mem::size_of::<NativeObjectAttributes>() as u32,
        root_directory: parent.as_raw_handle(),
        object_name: &raw mut name,
        // OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
        attributes: 0x0040 | 0x1000,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut status_block = NativeIoStatusBlock {
        status_or_pointer: 0,
        information: 0,
    };
    let mut handle: HANDLE = std::ptr::null_mut();
    // Safety: input objects point to live writable ABI-correct buffers for
    // the synchronous call. The parent File remains owned through the call.
    let status = unsafe {
        nt_create_file(
            &raw mut handle,
            0x0010_0080, // SYNCHRONIZE | FILE_READ_ATTRIBUTES
            &raw mut object,
            &raw mut status_block,
            std::ptr::null_mut(),
            0,
            0x0000_0001 | 0x0000_0002 | 0x0000_0004,
            1,                                       // FILE_OPEN, never create/write
            0x0000_0001 | 0x0000_0020 | 0x0020_0000, // DIRECTORY | synchronous | OPEN_REPARSE_POINT
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 || handle.is_null() || handle == INVALID_HANDLE_VALUE {
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            // Safety: a non-null NT-issued HANDLE must be released on error.
            unsafe { CloseHandle(handle) };
        }
        return Err(denied());
    }
    // Safety: successful NtCreateFile gave an owned real HANDLE exactly once.
    let file = unsafe { File::from_raw_handle(handle) };
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
    // Safety: live File owns HANDLE and output is initialized and writable.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(denied());
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    #[test]
    fn retained_parent_handle_survives_pathname_substitution() {
        let fixture = std::env::temp_dir().join(format!(
            "classmesh-nt-relative-rename-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir_all(fixture.join("anchor").join("original")).unwrap();
        let fixture = std::fs::canonicalize(fixture).unwrap();
        let held_parent = OpenOptions::new()
            .read(true)
            .share_mode(7)
            .custom_flags(0x0220_0000)
            .open(fixture.join("anchor"))
            .unwrap();
        std::fs::rename(fixture.join("anchor"), fixture.join("moved")).unwrap();
        std::fs::create_dir_all(fixture.join("anchor").join("attacker")).unwrap();
        let child = open_relative_readonly_directory(&held_parent, "original").unwrap();
        assert!(child.metadata().unwrap().is_dir());
        assert!(open_relative_readonly_directory(&held_parent, "attacker").is_err());
        drop(child);
        drop(held_parent);
        std::fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn directory_relative_nt_open_refuses_leaf_symlink() {
        let fixture =
            std::env::temp_dir().join(format!("classmesh-nt-relative-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir_all(fixture.join("real")).unwrap();
        let fixture = std::fs::canonicalize(fixture).unwrap();
        std::os::windows::fs::symlink_dir(fixture.join("real"), fixture.join("link"))
            .expect("elevated Windows test requires link privilege");
        let parent = OpenOptions::new()
            .read(true)
            .share_mode(7)
            .custom_flags(0x0220_0000)
            .open(&fixture)
            .unwrap();
        assert!(open_relative_readonly_directory(&parent, "link").is_err());
        assert!(open_relative_readonly_directory(&parent, "real").is_ok());
        drop(parent);
        std::fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn opens_one_direct_child_from_retained_parent_handle() {
        let fixture =
            std::env::temp_dir().join(format!("classmesh-nt-relative-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir_all(fixture.join("child")).unwrap();
        let fixture = std::fs::canonicalize(fixture).unwrap();
        let parent = OpenOptions::new()
            .read(true)
            .share_mode(7)
            .custom_flags(0x0220_0000)
            .open(&fixture)
            .unwrap();
        let child = open_relative_readonly_directory(&parent, "child").unwrap();
        assert!(child.metadata().unwrap().is_dir());
        assert!(open_relative_readonly_directory(&parent, "missing").is_err());
        for bad in ["..", r"other\child", "child:stream", "COM¹"] {
            assert!(open_relative_readonly_directory(&parent, bad).is_err());
        }
        drop(child);
        drop(parent);
        std::fs::remove_dir_all(fixture).unwrap();
    }
}
