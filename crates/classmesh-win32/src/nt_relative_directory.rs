//! Internal NT-relative operations; callers must retain an independently trusted parent.
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

/// Query an Object Manager symbolic link itself, without following it through
/// the filesystem. Only fixed OS namespace names are accepted by callers.
pub(crate) fn query_object_link(name: &str) -> io::Result<String> {
    use std::os::windows::io::OwnedHandle;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    type OpenLink = unsafe extern "system" fn(*mut HANDLE, u32, *mut NativeObjectAttributes) -> i32;
    type QueryLink = unsafe extern "system" fn(HANDLE, *mut NativeUnicodeString, *mut u32) -> i32;
    let module_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    // Safety: ntdll is loaded for this process lifetime; bounded NUL-terminated name.
    let module = unsafe { GetModuleHandleW(module_name.as_ptr()) };
    if module.is_null() {
        return Err(io::Error::last_os_error());
    }
    // Safety: exact exported names and documented system ABI signatures. Missing
    // exports fail closed; no fallback to ordinary pathname opens.
    let open: OpenLink = unsafe {
        std::mem::transmute(
            GetProcAddress(module, c"NtOpenSymbolicLinkObject".as_ptr().cast())
                .ok_or_else(denied)?,
        )
    };
    let query: QueryLink = unsafe {
        std::mem::transmute(
            GetProcAddress(module, c"NtQuerySymbolicLinkObject".as_ptr().cast())
                .ok_or_else(denied)?,
        )
    };
    let mut source: Vec<u16> = name.encode_utf16().collect();
    let length = u16::try_from(source.len() * 2).map_err(|_| denied())?;
    let mut input = NativeUnicodeString {
        length,
        maximum_length: length,
        buffer: source.as_mut_ptr(),
    };
    let mut attributes = NativeObjectAttributes {
        length: std::mem::size_of::<NativeObjectAttributes>() as u32,
        root_directory: std::ptr::null_mut(),
        object_name: &raw mut input,
        attributes: 0x40,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut raw = std::ptr::null_mut();
    // Safety: initialized ABI buffers remain alive for synchronous call.
    let status = unsafe { open(&raw mut raw, 1, &raw mut attributes) }; // SYMBOLIC_LINK_QUERY
    if status != 0 || raw.is_null() || raw == INVALID_HANDLE_VALUE {
        if !raw.is_null() && raw != INVALID_HANDLE_VALUE {
            // Safety: release returned handle on the failure path.
            unsafe { CloseHandle(raw) };
        }
        return Err(io::Error::other(format!(
            "Open object link {name}: {status:#010x}"
        )));
    }
    // Safety: single owner of the successfully returned native handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut buffer = vec![0u16; 32767];
    let mut output = NativeUnicodeString {
        length: 0,
        maximum_length: 65534,
        buffer: buffer.as_mut_ptr(),
    };
    // Safety: retained link and writable UTF-16 storage sized by MaximumLength.
    if unsafe {
        query(
            handle.as_raw_handle(),
            &raw mut output,
            std::ptr::null_mut(),
        )
    } != 0
        || output.length == 0
        || output.length % 2 != 0
        || output.length > output.maximum_length
    {
        return Err(denied());
    }
    String::from_utf16(&buffer[..usize::from(output.length / 2)]).map_err(|_| denied())
}

/// Compare the live OS volume and file IDs of two pinned directory objects.
/// Equality is object identity, not proof that the objects are OS-trusted.
#[cfg(test)]
pub(crate) fn same_native_file_identity(left: &File, right: &File) -> io::Result<bool> {
    Ok(native_file_identity(left)? == native_file_identity(right)?)
}

fn native_file_identity(file: &File) -> io::Result<(u64, [u8; 16])> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_128, FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };
    let mut info = FILE_ID_INFO {
        VolumeSerialNumber: 0,
        FileId: FILE_ID_128 {
            Identifier: [0; 16],
        },
    };
    // Safety: live retained HANDLE and exactly sized writable OS output. No
    // truncated 64-bit fallback: failure to obtain full identity fails closed.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut info).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((info.VolumeSerialNumber, info.FileId.Identifier))
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
    if !super::policy_file_origin::safe_child_leaf(leaf) || leaf.encode_utf16().count() > 255 {
        return Err(denied());
    }
    open_native_readonly_directory(Some(parent), leaf)
}

/// Internal NT object-name entry point. Absolute names must come from the OS
/// authority module, never from a policy or remote caller.
pub(crate) fn open_native_readonly_directory(
    parent: Option<&File>,
    name: &str,
) -> io::Result<File> {
    open_native_node(parent, name, true, false, None, false)
}

fn open_native_node(
    parent: Option<&File>,
    name: &str,
    directory: bool,
    protected: bool,
    creation: Option<&NewDirectoryDescriptor>,
    exclusive: bool,
) -> io::Result<File> {
    let writing = creation.is_some() && !directory;
    let mut utf16: Vec<u16> = name.encode_utf16().collect();
    if utf16.is_empty() || utf16.len() > 32766 || name.contains('\0') {
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
        root_directory: parent.map_or(std::ptr::null_mut(), AsRawHandle::as_raw_handle),
        object_name: &raw mut name,
        // OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE
        attributes: 0x0040 | 0x1000,
        security_descriptor: creation.map_or(std::ptr::null_mut(), |d| d.0),
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
            // Protected directories need LIST_DIRECTORY (same bit as READ_DATA)
            // so Windows enforces sharing against rename/delete opens. Metadata-only
            // directory handles do not provide that sharing exclusion.
            0x0012_0080 | if protected { 1 } else { 0 } | if writing { 2 } else { 0 },
            &raw mut object,
            &raw mut status_block,
            std::ptr::null_mut(),
            0,
            // Protected subtree refuses existing/future data writers or deleters.
            if exclusive || writing {
                0
            } else if protected {
                1
            } else {
                7
            },
            if creation.is_some() { 2 } else { 1 }, // FILE_CREATE or FILE_OPEN
            (if directory { 1 } else { 0x40 }) | 0x20 | 0x0020_0000 | if writing { 2 } else { 0 }, // type | synchronous | no-follow
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 || handle.is_null() || handle == INVALID_HANDLE_VALUE {
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            // Safety: a non-null NT-issued HANDLE must be released on error.
            unsafe { CloseHandle(handle) };
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("NT directory open failed: {status:#010x}"),
        ));
    }
    // Safety: successful NtCreateFile gave an owned real HANDLE exactly once.
    let file = unsafe { File::from_raw_handle(handle) };
    if creation.is_some() && status_block.information != 2 {
        return Err(denied()); // FILE_CREATED required; never adopt existing.
    }
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
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(denied());
    }
    if let Some(parent) = parent {
        let parent_id = native_file_identity(parent)?;
        let child_id = native_file_identity(&file)?;
        if parent_id.0 != child_id.0 || parent_id.1 == child_id.1 {
            return Err(denied());
        }
    }
    if protected {
        crate::policy_file_origin::attest_restricted_owner_acl(&file, directory)?;
    }
    Ok(file)
}

pub(crate) fn open_relative_protected_node(
    parent: &File,
    leaf: &str,
    directory: bool,
) -> io::Result<File> {
    if !crate::policy_file_origin::safe_child_leaf(leaf) || leaf.encode_utf16().count() > 255 {
        return Err(denied());
    }
    open_native_node(Some(parent), leaf, directory, true, None, false)
}

struct NewDirectoryDescriptor(*mut c_void);

impl NewDirectoryDescriptor {
    fn new(directory: bool) -> io::Result<Self> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        let sddl: Vec<u16> = (if directory {
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)\0"
        } else {
            "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)\0"
        })
        .encode_utf16()
        .collect();
        let mut raw = std::ptr::null_mut();
        // Safety: fixed NUL-terminated SDDL and initialized writable output.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut raw,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if raw.is_null() {
            return Err(denied());
        }
        Ok(Self(raw))
    }
}

impl Drop for NewDirectoryDescriptor {
    fn drop(&mut self) {
        // Safety: exactly one owner of the successful LocalAlloc result.
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(self.0);
        }
    }
}

/// Experimental atomic create-only bootstrap beneath a retained parent.
/// Parent authority and crash durability are separate, still-open gates.
pub(crate) fn create_relative_protected_directory(parent: &File, leaf: &str) -> io::Result<File> {
    if !crate::policy_file_origin::safe_child_leaf(leaf) || leaf.encode_utf16().count() > 255 {
        return Err(denied());
    }
    let descriptor = NewDirectoryDescriptor::new(true)?;
    open_native_node(Some(parent), leaf, true, true, Some(&descriptor), false)
}

/// Create only, protected at creation, exclusive READ/WRITE, write-through.
/// Never adopts an orphan. The caller must flush and verify before committing.
pub(crate) fn create_relative_protected_file(parent: &File, leaf: &str) -> io::Result<File> {
    if !crate::policy_file_origin::safe_child_leaf(leaf) || leaf.encode_utf16().count() > 255 {
        return Err(denied());
    }
    let descriptor = NewDirectoryDescriptor::new(false)?;
    open_native_node(Some(parent), leaf, false, true, Some(&descriptor), true)
}

/// Existing stable lock object; no create/recovery/rename and no sharing.
pub(crate) fn open_relative_exclusive_file(parent: &File, leaf: &str) -> io::Result<File> {
    if !crate::policy_file_origin::safe_child_leaf(leaf) || leaf.encode_utf16().count() > 255 {
        return Err(denied());
    }
    open_native_node(Some(parent), leaf, false, true, None, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;

    #[test]
    fn root_relative_walk_reaches_identical_os_programdata_directory() {
        let path = crate::program_data_known_folder::resolve_os_program_data_path().unwrap();
        let pathname_candidates =
            crate::program_data_known_folder::pin_os_program_data_ancestor_candidates().unwrap();
        let mut ancestors: Vec<_> = path.ancestors().filter(|p| p.is_absolute()).collect();
        ancestors.reverse();
        assert_eq!(pathname_candidates.len(), ancestors.len());
        let mut rooted = vec![pathname_candidates[0].try_clone().unwrap()];
        for ancestor in ancestors.iter().skip(1) {
            let leaf = ancestor.file_name().unwrap().to_str().unwrap();
            let child = open_relative_readonly_directory(rooted.last().unwrap(), leaf).unwrap();
            crate::policy_file_origin::attest_immediate_child(rooted.last().unwrap(), &child, leaf)
                .unwrap();
            rooted.push(child);
        }
        assert!(
            same_native_file_identity(rooted.last().unwrap(), pathname_candidates.last().unwrap())
                .unwrap()
        );
        let independently_opened =
            crate::program_data_known_folder::pin_os_program_data_candidate().unwrap();
        assert!(same_native_file_identity(rooted.last().unwrap(), &independently_opened).unwrap());
        assert!(
            !same_native_file_identity(rooted.first().unwrap(), &independently_opened).unwrap()
        );
    }

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
    fn relative_open_refuses_mount_point_junction() {
        let fixture =
            std::env::temp_dir().join(format!("classmesh-nt-junction-{}", std::process::id()));
        std::fs::create_dir(&fixture).unwrap();
        std::fs::create_dir(fixture.join("target")).unwrap();
        let result = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(fixture.join("junction"))
            .arg(fixture.join("target"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let parent = OpenOptions::new()
            .read(true)
            .share_mode(7)
            .custom_flags(0x0220_0000)
            .open(&fixture)
            .unwrap();
        assert!(open_relative_readonly_directory(&parent, "junction").is_err());
        assert!(open_relative_readonly_directory(&parent, "target").is_ok());
        drop(parent);
        std::fs::remove_dir(fixture.join("junction")).unwrap();
        std::fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn protected_relative_leaf_checks_acl_hardlinks_and_existing_writers() {
        use std::io::Read;
        let fixture =
            std::env::temp_dir().join(format!("classmesh-nt-policy-{}", std::process::id()));
        std::fs::create_dir(&fixture).unwrap();
        let path = fixture.join("policy");
        std::fs::write(&path, b"verified bytes").unwrap();
        let acl = |path: &std::path::Path, args: &[&str]| {
            let result = std::process::Command::new("icacls.exe")
                .arg(path)
                .args(args)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        };
        // Remove any explicit creator ACE carried by the temporary directory.
        acl(&path, &["/reset"]);
        acl(
            &path,
            &[
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:F",
                "*S-1-5-32-544:F",
            ],
        );
        acl(&path, &["/setowner", "*S-1-5-32-544"]);
        let parent = OpenOptions::new()
            .read(true)
            .share_mode(7)
            .custom_flags(0x0220_0000)
            .open(&fixture)
            .unwrap();
        let mut pinned =
            open_relative_protected_node(&parent, "policy", false).expect("secure relative file");
        let mut bytes = Vec::new();
        pinned.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"verified bytes");
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        assert!(std::fs::rename(&path, fixture.join("moved")).is_err());
        drop(pinned);
        let writer = OpenOptions::new()
            .write(true)
            .share_mode(7)
            .open(&path)
            .unwrap();
        assert!(open_relative_protected_node(&parent, "policy", false).is_err());
        drop(writer);
        // A writable section can outlive its original file HANDLE. Sharing
        // exclusion must reject it too, not just ordinary open writers.
        {
            use std::os::windows::io::OwnedHandle;
            use windows_sys::Win32::System::Memory::{
                CreateFileMappingW, FILE_MAP_WRITE, MapViewOfFile, PAGE_READWRITE, UnmapViewOfFile,
            };
            let writer = OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(7)
                .open(&path)
                .unwrap();
            // Safety: live regular file, no name, existing nonzero file length.
            let mapping = unsafe {
                CreateFileMappingW(
                    writer.as_raw_handle(),
                    std::ptr::null(),
                    PAGE_READWRITE,
                    0,
                    0,
                    std::ptr::null(),
                )
            };
            assert!(!mapping.is_null());
            // Safety: own the successful mapping handle exactly once.
            let mapping = unsafe { OwnedHandle::from_raw_handle(mapping) };
            drop(writer);
            assert!(
                open_relative_protected_node(&parent, "policy", false).is_err(),
                "writable section must prevent policy admission"
            );
            // A view also survives BOTH original handles being closed. Test
            // this separately from merely retaining a section handle.
            // Safety: owned live mapping; one writable byte inside the file.
            let view = unsafe { MapViewOfFile(mapping.as_raw_handle(), FILE_MAP_WRITE, 0, 0, 1) };
            assert!(!view.Value.is_null());
            drop(mapping);
            // Safety: successful writable view still owns its mapping reference.
            unsafe { view.Value.cast::<u8>().write_volatile(b'V') };
            let view_only_open = open_relative_protected_node(&parent, "policy", false);
            // Safety: the exact live view is released once, before assertions.
            assert_ne!(unsafe { UnmapViewOfFile(view) }, 0);
            assert!(
                view_only_open.is_err(),
                "view-only writable mapping must prevent admission"
            );
            assert!(
                open_relative_protected_node(&parent, "policy", false).is_ok(),
                "unmapping the last writable view restores admission"
            );
        }
        std::fs::hard_link(&path, fixture.join("alias")).unwrap();
        assert!(open_relative_protected_node(&parent, "policy", false).is_err());
        std::fs::remove_file(fixture.join("alias")).unwrap();
        acl(&path, &["/grant", "*S-1-5-32-545:R"]);
        assert!(open_relative_protected_node(&parent, "policy", false).is_err());
        let state = fixture.join("state");
        std::fs::create_dir(&state).unwrap();
        assert!(open_relative_protected_node(&parent, "state", true).is_err());
        acl(&state, &["/reset"]);
        acl(
            &state,
            &[
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ],
        );
        acl(&state, &["/setowner", "*S-1-5-32-544"]);
        let state_handle = open_relative_protected_node(&parent, "state", true).unwrap();
        assert!(std::fs::rename(&state, fixture.join("moved-state")).is_err());
        assert!(open_relative_protected_node(&parent, "state", false).is_err());
        drop(state_handle);
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
