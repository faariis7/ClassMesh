//! Windows policy file *leaf* preflight, not an authorization trust decision.
//! A production publisher must additionally pin and attest every ancestor,
//! validate trusted owner/DACL, and anchor a persistent monotonic epoch.
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, Prefix};

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

    let info = information_from_handle(&file)?;
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || info.nNumberOfLinks != 1
    {
        return Err(permission_denied());
    }
    Ok(file)
}

fn information_from_handle(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
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
    Ok(info)
}

/// Require the retained *leaf* HANDLE to have a non-NULL, explicitly
/// allow-only DACL containing only SYSTEM and BUILTIN\Administrators, with
/// both SIDs present and the owner one of those SIDs.
/// This is still a leaf-only preflight: no trusted ancestor chain, protected
/// durable epoch or TOCTOU-safe production policy publisher is established.
pub fn open_protected_policy_leaf(path: &Path) -> io::Result<File> {
    let file = open_single_link_policy_leaf(path)?;
    attest_restricted_owner_acl(&file, false)?;
    Ok(file)
}

fn permission_denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "policy leaf owner or ACL is not a protected SYSTEM/Administrators descriptor",
    )
}

fn attest_restricted_owner_acl(file: &File, directory: bool) -> io::Result<()> {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, GetLengthSid,
        IsValidAcl, IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };

    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // Safety: GetSecurityInfo allocates this descriptor with LocalAlloc.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    fn sid_string(sid: PSID) -> io::Result<String> {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        if sid.is_null() {
            return Err(permission_denied());
        }
        let mut allocated: *mut u16 = std::ptr::null_mut();
        // Safety: owner/ACE SID comes from a live GetSecurityInfo descriptor.
        if unsafe { ConvertSidToStringSidW(sid, &raw mut allocated) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if allocated.is_null() {
            return Err(permission_denied());
        }
        let text = (|| {
            let mut length = 0usize;
            // Safety: ConvertSidToStringSidW allocated a NUL-terminated SID string.
            while length < 128 && unsafe { *allocated.add(length) } != 0 {
                length += 1;
            }
            if length == 128 {
                return Err(permission_denied());
            }
            // Safety: all characters are within the measured allocation.
            String::from_utf16(unsafe { std::slice::from_raw_parts(allocated, length) })
                .map_err(|_| permission_denied())
        })();
        // Safety: matches the allocation from ConvertSidToStringSidW.
        unsafe { LocalFree(allocated.cast()) };
        text
    }

    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = Descriptor(std::ptr::null_mut());
    // Safety: the File is open and held through all checks; output pointers are
    // writable; GetSecurityInfo returns descriptor-owned owner and DACL pointers.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut descriptor.0,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if descriptor.0.is_null() || owner.is_null() || dacl.is_null() {
        return Err(permission_denied());
    }
    let owner_sid = sid_string(owner)?;
    if owner_sid != "S-1-5-18" && owner_sid != "S-1-5-32-544" {
        return Err(permission_denied());
    }

    // Safety: ACL and ACE addresses are inside the descriptor allocated by
    // GetSecurityInfo, kept live by Descriptor until this method returns.
    if unsafe { IsValidAcl(dacl) } == 0 {
        return Err(permission_denied());
    }
    // Safety: non-null ACL pointer validated by IsValidAcl.
    let count = unsafe { (*dacl).AceCount };
    if !(2..=32).contains(&count) {
        return Err(permission_denied());
    }
    let mut system = false;
    let mut administrators = false;
    for idx in 0..u32::from(count) {
        let mut ace: *mut c_void = std::ptr::null_mut();
        // Safety: GetAce validates index and returns an ACL-owned ACE pointer.
        if unsafe { GetAce(dacl, idx, &raw mut ace) } == 0 || ace.is_null() {
            return Err(permission_denied());
        }
        // Safety: GetAce returns at least an in-bounds ACE_HEADER. Check size
        // BEFORE treating its memory as an ACCESS_ALLOWED_ACE.
        let header = unsafe { &*(ace.cast::<ACE_HEADER>()) };
        let allowed_inheritance = if directory { 0x01 | 0x02 } else { 0 };
        if header.AceType != 0
            || header.AceFlags & !allowed_inheritance != 0
            || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(permission_denied());
        }
        // Safety: ACE size and type checked above. SidStart is the SID embedded
        // in the allowed ACE, not a separate pathname lookup.
        let allowed = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
        let sid_ptr = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
        let ace_bytes = usize::from(header.AceSize);
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        // A SID needs at least its 8-byte fixed header. Validate that it fits
        // wholly INSIDE this ACE before parsing any variable subauthority data.
        if ace_bytes.saturating_sub(sid_offset) < 8 {
            return Err(permission_denied());
        }
        // Safety: GetAce supplied an in-bounds ACE, and at least the SID header
        // fits. GetLengthSid only reads that header's SubAuthorityCount.
        let length = unsafe { GetLengthSid(sid_ptr) };
        if length < 8 || usize::try_from(length).unwrap_or(usize::MAX) > ace_bytes - sid_offset {
            return Err(permission_denied());
        }
        // Safety: the full SID now fits in the ACE allocation.
        if unsafe { IsValidSid(sid_ptr) } == 0 {
            return Err(permission_denied());
        }
        // A trusted SID in an ACE with no usable read rights is not an
        // authorization to consume policy bytes. File READ_DATA and directory
        // LIST_DIRECTORY share bit 0x0001; READ_CONTROL (0x0002_0000) is
        // required for the same-HANDLE descriptor check. Explicit GENERIC_READ
        // and GENERIC_ALL are also sufficient when the ACL was not mapped.
        const REQUIRED_READ: u32 = 0x0002_0001;
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_ALL: u32 = 0x1000_0000;
        let mask = allowed.Mask;
        if mask & REQUIRED_READ != REQUIRED_READ && mask & (GENERIC_READ | GENERIC_ALL) == 0 {
            return Err(permission_denied());
        }
        let sid = sid_string(sid_ptr)?;
        match sid.as_str() {
            "S-1-5-18" => system = true,
            "S-1-5-32-544" => administrators = true,
            _ => return Err(permission_denied()),
        }
    }
    if !system || !administrators {
        return Err(permission_denied());
    }
    Ok(())
}

const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// One file handle for each protected ClassMesh subtree node is retained
/// alongside the leaf during validation and parsing. The caller MUST still
/// prove the system-selected ProgramData prefix is trusted before production
/// use; this type alone is not an authorization publisher.
#[derive(Debug)]
pub struct PinnedPolicyCandidate {
    leaf: File,
    _app_root: File,
    _state_dir: File,
}

impl PinnedPolicyCandidate {
    /// Keep the ancestors pinned for the full duration of the caller's parse.
    pub fn with_file<T>(&self, action: impl FnOnce(&File) -> T) -> T {
        action(&self.leaf)
    }
}

fn open_protected_directory(path: &Path) -> io::Result<File> {
    let dir = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let info = information_from_handle(&dir)?;
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(permission_denied());
    }
    attest_restricted_owner_acl(&dir, true)?;
    Ok(dir)
}

/// Isolated Windows qualification boundary for fixed ClassMesh/state tree.
/// Does NOT attest the drive root or ProgramData ancestors and must not be
/// connected to Service startup or policy reload until those trust gates and
/// durable rollback / TOCTOU requirements have independent native proof.
fn validate_app_root(app_root: &Path) -> io::Result<()> {
    let absolute_local_drive = matches!(
        app_root.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    );
    if !app_root.is_absolute()
        || !absolute_local_drive
        || app_root
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        || app_root.file_name() != Some(std::ffi::OsStr::new("ClassMesh"))
    {
        return Err(permission_denied());
    }
    Ok(())
}

pub fn open_protected_policy_in_app_root(app_root: &Path) -> io::Result<PinnedPolicyCandidate> {
    validate_app_root(app_root)?;
    let pinned_app_root = open_protected_directory(app_root)?;
    let state_root = app_root.join("state");
    let pinned_state_dir = open_protected_directory(&state_root)?;
    let leaf = open_protected_policy_leaf(&state_root.join("authorization.json"))?;
    attest_immediate_child(&pinned_app_root, &pinned_state_dir, "state")?;
    attest_immediate_child(&pinned_state_dir, &leaf, "authorization.json")?;
    Ok(PinnedPolicyCandidate {
        leaf,
        _app_root: pinned_app_root,
        _state_dir: pinned_state_dir,
    })
}

/// Return the resolved Windows path of the ORIGINAL held HANDLE (not a fresh
/// pathname lookup). Reject unbounded results and malformed UTF-16.
fn resolved_handle_path(file: &File) -> io::Result<String> {
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

    // Safety: file owns a valid HANDLE; first call only queries buffer length.
    let required =
        unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), std::ptr::null_mut(), 0, 0) };
    if required == 0 {
        return Err(io::Error::last_os_error());
    }
    if required > 32_767 {
        return Err(permission_denied());
    }
    let mut name = vec![0u16; required as usize + 1];
    // Safety: allocated UTF-16 buffer is writable and sized to the first
    // query. A raced name-length increase is rejected rather than retried.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            name.as_mut_ptr(),
            name.len() as u32,
            0,
        )
    };
    if written == 0 {
        return Err(io::Error::last_os_error());
    }
    if written > required || written as usize >= name.len() {
        return Err(permission_denied());
    }
    String::from_utf16(&name[..written as usize]).map_err(|_| permission_denied())
}

fn attest_same_volume_distinct_file_ids(
    parent: &BY_HANDLE_FILE_INFORMATION,
    child: &BY_HANDLE_FILE_INFORMATION,
) -> io::Result<()> {
    let same_volume = parent.dwVolumeSerialNumber == child.dwVolumeSerialNumber;
    let same_file = parent.nFileIndexHigh == child.nFileIndexHigh
        && parent.nFileIndexLow == child.nFileIndexLow;
    if !same_volume || same_file {
        return Err(permission_denied());
    }
    Ok(())
}

fn attest_immediate_child(parent: &File, child: &File, leaf: &str) -> io::Result<()> {
    if leaf.is_empty() || leaf.contains(['/', '\\']) || leaf == "." || leaf == ".." {
        return Err(permission_denied());
    }
    let parent_info = information_from_handle(parent)?;
    let child_info = information_from_handle(child)?;
    attest_same_volume_distinct_file_ids(&parent_info, &child_info)?;
    let parent_name = resolved_handle_path(parent)?;
    let child_name = resolved_handle_path(child)?;
    let expected = format!("{}\\{}", parent_name.trim_end_matches('\\'), leaf);
    if !child_name.eq_ignore_ascii_case(&expected) {
        return Err(permission_denied());
    }
    Ok(())
}

/// Experimental protected ProgramData prefix qualification. This type pins
/// the data root together with the protected ClassMesh/state subtree for the
/// whole parse. The system volume root and mount/relative-handle chain are
/// NOT attested. Do not use as a production Service trust token.
#[derive(Debug)]
pub struct PinnedProgramDataCandidate {
    _program_data: File,
    inner: PinnedPolicyCandidate,
}

impl PinnedProgramDataCandidate {
    pub fn with_file<T>(&self, action: impl FnOnce(&File) -> T) -> T {
        self.inner.with_file(action)
    }
}

/// Strict experimental ancestry check. Windows default ProgramData ACLs may
/// contain writable Users entries, which this *deliberately* rejects; never
/// relax the check silently or change the OS-wide ProgramData permissions.
pub fn open_protected_policy_in_program_data(
    program_data: &Path,
) -> io::Result<PinnedProgramDataCandidate> {
    let disk_prefix = matches!(
        program_data.components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    );
    if !program_data.is_absolute()
        || !disk_prefix
        || program_data
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        || program_data.file_name() != Some(std::ffi::OsStr::new("ProgramData"))
    {
        return Err(permission_denied());
    }
    let pinned_data = open_protected_directory(program_data)?;
    let inner = open_protected_policy_in_app_root(&program_data.join("ClassMesh"))?;
    attest_immediate_child(&pinned_data, &inner._app_root, "ClassMesh")?;
    Ok(PinnedProgramDataCandidate {
        _program_data: pinned_data,
        inner,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn candidate_root_rejects_parent_traversal_and_remote_prefixes() {
        for ambiguous in [
            r"C:\ProgramData\ClassMesh\..\ClassMesh",
            r"\\untrusted-server\share\ClassMesh",
            "ClassMesh",
        ] {
            assert_eq!(
                open_protected_policy_in_app_root(Path::new(ambiguous))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn ancestry_requires_same_volume_and_distinct_file_id() {
        let dir =
            std::env::temp_dir().join(format!("classmesh-volume-witness-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let child = dir.join("child.json");
        fs::write(&child, b"inert").unwrap();
        let held_parent = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&dir)
            .unwrap();
        let held_child = File::open(&child).unwrap();
        let parent_info = information_from_handle(&held_parent).unwrap();
        let child_info = information_from_handle(&held_child).unwrap();
        assert!(attest_same_volume_distinct_file_ids(&parent_info, &child_info).is_ok());
        assert!(attest_immediate_child(&held_parent, &held_child, "child.json").is_ok());

        let mut other_volume = child_info;
        other_volume.dwVolumeSerialNumber ^= 1;
        assert_eq!(
            attest_same_volume_distinct_file_ids(&parent_info, &other_volume)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            attest_same_volume_distinct_file_ids(&parent_info, &parent_info)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(held_child);
        drop(held_parent);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn resolved_handle_must_be_immediate_named_child() {
        let dir =
            std::env::temp_dir().join(format!("classmesh-resolved-handle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sibling = dir.join("sibling.json");
        fs::write(&sibling, b"fixture").unwrap();

        let held_parent = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&dir)
            .unwrap();
        let held_sibling = File::open(&sibling).unwrap();
        assert_eq!(
            attest_immediate_child(&held_parent, &held_sibling, "authorization.json")
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(attest_immediate_child(&held_parent, &held_sibling, "sibling.json").is_ok());

        drop(held_sibling);
        drop(held_parent);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn protected_programdata_parent_is_required_even_if_app_tree_is_secured() {
        use std::process::Command;

        fn allow_only_privileged(path: &Path, is_directory: bool) {
            let rights = if is_directory { "(OI)(CI)F" } else { "F" };
            let system = format!("*S-1-5-18:{rights}");
            let admins = format!("*S-1-5-32-544:{rights}");
            assert!(
                Command::new("icacls.exe")
                    .arg(path)
                    .arg("/reset")
                    .status()
                    .unwrap()
                    .success()
            );
            for args in [
                vec![
                    "/inheritance:r",
                    "/grant:r",
                    system.as_str(),
                    admins.as_str(),
                ],
                vec!["/setowner", "*S-1-5-32-544"],
            ] {
                assert!(
                    Command::new("icacls.exe")
                        .arg(path)
                        .args(args)
                        .status()
                        .unwrap()
                        .success()
                );
            }
        }
        let fixture =
            std::env::temp_dir().join(format!("classmesh-programdata-root-{}", std::process::id()));
        let data = fixture.join("ProgramData");
        let app = data.join("ClassMesh");
        let state = app.join("state");
        fs::create_dir_all(&state).unwrap();
        let leaf = state.join("authorization.json");
        fs::write(&leaf, b"fixture").unwrap();
        for directory in [&data, &app, &state] {
            allow_only_privileged(directory, true);
        }
        allow_only_privileged(&leaf, false);

        let candidate = open_protected_policy_in_program_data(&data).unwrap();
        assert_eq!(candidate.with_file(|f| f.metadata().unwrap().len()), 7);
        assert!(
            fs::rename(&data, fixture.join("renamed")).is_err(),
            "pinned data root must not be movable until parsing ends"
        );
        drop(candidate);

        let output = Command::new("icacls.exe")
            .arg(&data)
            .args(["/grant", "*S-1-5-32-545:(OI)(CI)M"])
            .status()
            .unwrap();
        assert!(output.success());
        assert_eq!(
            open_protected_policy_in_program_data(&data)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let output = Command::new("icacls.exe")
            .arg(&data)
            .args(["/remove:g", "*S-1-5-32-545"])
            .status()
            .unwrap();
        assert!(output.success());
        assert!(open_protected_policy_in_program_data(&data).is_ok());
        fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn protected_subtree_denies_untrusted_state_directory() {
        use std::process::Command;

        fn acl(path: &Path, args: &[&str]) {
            assert!(
                Command::new("icacls.exe")
                    .arg(path)
                    .args(args)
                    .status()
                    .unwrap()
                    .success(),
                "failed native ACL fixture: {args:?}"
            );
        }

        let fixture =
            std::env::temp_dir().join(format!("classmesh-subtree-policy-{}", std::process::id()));
        let root = fixture.join("ClassMesh");
        let state = root.join("state");
        fs::create_dir_all(&state).unwrap();
        let leaf = state.join("authorization.json");
        fs::write(&leaf, b"qualified").unwrap();
        for directory in [&root, &state] {
            acl(directory, &["/reset"]);
            acl(
                directory,
                &[
                    "/inheritance:r",
                    "/grant:r",
                    "*S-1-5-18:(OI)(CI)F",
                    "*S-1-5-32-544:(OI)(CI)F",
                ],
            );
            acl(directory, &["/setowner", "*S-1-5-32-544"]);
        }
        acl(&leaf, &["/reset"]);
        acl(
            &leaf,
            &[
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:F",
                "*S-1-5-32-544:F",
            ],
        );
        acl(&leaf, &["/setowner", "*S-1-5-32-544"]);

        let candidate = open_protected_policy_in_app_root(&root).unwrap();
        assert_eq!(candidate.with_file(|f| f.metadata().unwrap().len()), 9);
        assert!(
            fs::rename(&state, root.join("renamed-while-pinned")).is_err(),
            "pinned protected directory unexpectedly allowed a rename"
        );
        drop(candidate);

        acl(&state, &["/grant", "*S-1-5-32-545:R"]);
        assert_eq!(
            open_protected_policy_in_app_root(&root).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        acl(&state, &["/remove:g", "*S-1-5-32-545"]);
        assert!(open_protected_policy_in_app_root(&root).is_ok());

        // A protected ancestor with SYSTEM write-only but Admin full is not
        // sufficient to authorize traversal and descriptor inspection.
        acl(&state, &["/grant:r", "*S-1-5-18:(OI)(CI)W"]);
        assert_eq!(
            open_protected_policy_in_app_root(&root).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        acl(&state, &["/grant:r", "*S-1-5-18:(OI)(CI)F"]);
        assert!(open_protected_policy_in_app_root(&root).is_ok());

        let relocated = root.join("state-original");
        fs::rename(&state, &relocated).unwrap();
        std::os::windows::fs::symlink_dir(&relocated, &state).unwrap();
        assert_eq!(
            open_protected_policy_in_app_root(&root).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
            "state junction must never be followed"
        );
        fs::remove_dir(&state).unwrap();
        fs::rename(&relocated, &state).unwrap();
        assert!(open_protected_policy_in_app_root(&root).is_ok());
        fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn protected_owner_dacl_round_trip() {
        use std::process::Command;

        fn icacls(path: &Path, args: &[&str]) {
            let status = Command::new("icacls.exe")
                .arg(path)
                .args(args)
                .status()
                .expect("icacls must run on native elevated Windows");
            assert!(status.success(), "icacls failed: {args:?}");
        }

        let dir = std::env::temp_dir().join(format!("classmesh-policy-acl-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let policy = dir.join("authorization.json");
        fs::write(&policy, b"test-only").unwrap();

        icacls(&policy, &["/reset"]);
        icacls(
            &policy,
            &[
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:F",
                "*S-1-5-32-544:F",
            ],
        );
        icacls(&policy, &["/setowner", "*S-1-5-32-544"]);

        let file = open_protected_policy_leaf(&policy).unwrap();
        assert_eq!(file.metadata().unwrap().len(), 9);
        drop(file);

        icacls(&policy, &["/grant", "*S-1-5-32-545:R"]);
        assert_eq!(
            open_protected_policy_leaf(&policy).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        icacls(&policy, &["/remove:g", "*S-1-5-32-545"]);
        assert!(open_protected_policy_leaf(&policy).is_ok());

        // An ACE naming SYSTEM but granting WRITE without READ must not
        // satisfy the service's ability to read trusted policy bytes.
        icacls(&policy, &["/grant:r", "*S-1-5-18:W"]);
        assert_eq!(
            open_protected_policy_leaf(&policy).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
            "SYSTEM write-only must not qualify as a policy reader"
        );
        icacls(&policy, &["/grant:r", "*S-1-5-18:F"]);
        assert!(open_protected_policy_leaf(&policy).is_ok());

        // Removing the SYSTEM allowance must fail even though the elevated
        // Administrators account still has read access to the file.
        icacls(&policy, &["/remove:g", "*S-1-5-18"]);
        assert_eq!(
            open_protected_policy_leaf(&policy).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        icacls(&policy, &["/grant", "*S-1-5-18:F"]);
        assert!(open_protected_policy_leaf(&policy).is_ok());

        fs::remove_dir_all(dir).unwrap();
    }

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
        // RED: a regular single-link file owned/writable by the interactive
        // user is NOT sufficiently protected for policy authorization.
        assert_eq!(
            open_protected_policy_leaf(&original).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        {
            let file = open_single_link_policy_leaf(&original).unwrap();
            assert_eq!(file.metadata().unwrap().len(), 19);
        }
        let reparse = dir.join("redirect.json");
        std::os::windows::fs::symlink_file(&original, &reparse).unwrap();
        assert_eq!(
            open_single_link_policy_leaf(&reparse).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_file(reparse).unwrap();

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

/// Epoch-scoped protected policy blob preflight. This only qualifies the
/// ClassMesh/state subtree and the selected leaf. The volume root and real
/// ProgramData ancestors are NOT qualified; not a production trust token.
#[derive(Debug)]
pub struct PinnedEpochPolicyCandidate {
    epoch: u64,
    leaf: File,
    _app_root: File,
    _state_dir: File,
}

impl PinnedEpochPolicyCandidate {
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Caller must keep this candidate alive throughout the SAME-HANDLE parse.
    pub fn with_file<T>(&self, action: impl FnOnce(&File) -> T) -> T {
        action(&self.leaf)
    }
}

/// Rejects zero epoch, ambiguous app-root and unprotected or non-immediate
/// child. The filename is derived solely from the numeric checkpoint epoch;
/// never accepts caller-supplied filenames or backup paths.
pub fn open_protected_epoch_policy_in_app_root(
    app_root: &Path,
    epoch: u64,
) -> io::Result<PinnedEpochPolicyCandidate> {
    if epoch == 0 {
        return Err(permission_denied());
    }
    validate_app_root(app_root)?;
    let filename = format!("policy-{epoch:016x}.json");
    let pinned_app_root = open_protected_directory(app_root)?;
    let state_root = app_root.join("state");
    let pinned_state_dir = open_protected_directory(&state_root)?;
    let leaf = open_protected_policy_leaf(&state_root.join(&filename))?;
    attest_immediate_child(&pinned_app_root, &pinned_state_dir, "state")?;
    attest_immediate_child(&pinned_state_dir, &leaf, &filename)?;
    Ok(PinnedEpochPolicyCandidate {
        epoch,
        leaf,
        _app_root: pinned_app_root,
        _state_dir: pinned_state_dir,
    })
}

#[cfg(test)]
mod epoch_blob_tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    fn icacls(path: &Path, args: &[&str]) {
        assert!(
            Command::new("icacls.exe")
                .arg(path)
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }

    fn privileged(path: &Path, directory: bool) {
        let rights = if directory { "(OI)(CI)F" } else { "F" };
        let system = format!("*S-1-5-18:{rights}");
        let admins = format!("*S-1-5-32-544:{rights}");
        icacls(path, &["/reset"]);
        icacls(path, &["/inheritance:r", "/grant:r", &system, &admins]);
        icacls(path, &["/setowner", "*S-1-5-32-544"]);
    }

    #[test]
    fn pinned_epoch_blob_enforces_exact_epoch_and_parent_security() {
        let fixture =
            std::env::temp_dir().join(format!("classmesh-epoch-blob-{}", std::process::id()));
        let root = fixture.join("ClassMesh");
        let state = root.join("state");
        fs::create_dir_all(&state).unwrap();
        let leaf = state.join("policy-000000000000002a.json");
        fs::write(&leaf, b"epoch 42").unwrap();
        for path in [&root, &state] {
            privileged(path, true);
        }
        privileged(&leaf, false);
        let candidate = open_protected_epoch_policy_in_app_root(&root, 42).unwrap();
        assert_eq!(candidate.epoch(), 42);
        assert_eq!(candidate.with_file(|f| f.metadata().unwrap().len()), 8);
        assert!(fs::rename(&state, root.join("moved-state")).is_err());
        drop(candidate);
        assert_eq!(
            open_protected_epoch_policy_in_app_root(&root, 43)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            open_protected_epoch_policy_in_app_root(&root, 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        icacls(&state, &["/grant", "*S-1-5-32-545:R"]);
        assert_eq!(
            open_protected_epoch_policy_in_app_root(&root, 42)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        icacls(&state, &["/remove:g", "*S-1-5-32-545"]);
        assert!(open_protected_epoch_policy_in_app_root(&root, 42).is_ok());
        fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn rejects_hardlink_and_ambiguous_epoch_paths() {
        for path in [
            r"C:\ProgramData\ClassMesh\..\ClassMesh",
            r"\\host\share\ClassMesh",
            "ClassMesh",
        ] {
            assert_eq!(
                open_protected_epoch_policy_in_app_root(Path::new(path), 42)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        let fixture =
            std::env::temp_dir().join(format!("classmesh-epoch-hardlink-{}", std::process::id()));
        let root = fixture.join("ClassMesh");
        let state = root.join("state");
        fs::create_dir_all(&state).unwrap();
        let leaf = state.join("policy-000000000000002a.json");
        fs::write(&leaf, b"data").unwrap();
        fs::hard_link(&leaf, state.join("alias.json")).unwrap();
        for path in [&root, &state] {
            privileged(path, true);
        }
        privileged(&leaf, false);
        assert_eq!(
            open_protected_epoch_policy_in_app_root(&root, 42)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(fixture).unwrap();
    }
}

#[cfg(test)]
mod bound_pair_tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    fn privileged(path: &Path, directory: bool) {
        let rights = if directory { "(OI)(CI)F" } else { "F" };
        let system = format!("*S-1-5-18:{rights}");
        let admins = format!("*S-1-5-32-544:{rights}");
        for args in [
            vec!["/reset"],
            vec!["/inheritance:r", "/grant:r", &system, &admins],
            vec!["/setowner", "*S-1-5-32-544"],
        ] {
            assert!(
                Command::new("icacls.exe")
                    .arg(path)
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }

    #[test]
    fn protected_pair_pins_both_leaves_and_rejects_checkpoint_acl() {
        let fixture = std::env::temp_dir().join(format!("classmesh-pair-{}", std::process::id()));
        let root = fixture.join("ClassMesh");
        let state = root.join("state");
        fs::create_dir_all(&state).unwrap();
        let checkpoint = state.join("policy-checkpoint.v2");
        let blob = state.join("policy-0000000000000033.json");
        fs::write(&checkpoint, b"checkpoint").unwrap();
        fs::write(&blob, b"policy").unwrap();
        for directory in [&root, &state] {
            privileged(directory, true);
        }
        for leaf in [&checkpoint, &blob] {
            privileged(leaf, false);
        }
        let pair = open_protected_bound_policy_pair_in_app_root(&root, 51).unwrap();
        assert_eq!(pair.epoch(), 51);
        assert_eq!(
            pair.with_files(|a, b| (a.metadata().unwrap().len(), b.metadata().unwrap().len())),
            (10, 6)
        );
        assert!(fs::rename(&checkpoint, state.join("checkpoint-replaced")).is_err());
        assert!(fs::rename(&blob, state.join("blob-replaced")).is_err());
        drop(pair);
        assert_eq!(
            open_protected_bound_policy_pair_in_app_root(&root, 52)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            open_protected_bound_policy_pair_in_app_root(&root, 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(
            Command::new("icacls.exe")
                .arg(&checkpoint)
                .args(["/grant", "*S-1-5-32-545:R"])
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            open_protected_bound_policy_pair_in_app_root(&root, 51)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(fixture).unwrap();
    }

    #[test]
    fn checkpoint_hardlink_is_not_a_trusted_pair() {
        let fixture =
            std::env::temp_dir().join(format!("classmesh-pair-link-{}", std::process::id()));
        let root = fixture.join("ClassMesh");
        let state = root.join("state");
        fs::create_dir_all(&state).unwrap();
        let checkpoint = state.join("policy-checkpoint.v2");
        let blob = state.join("policy-0000000000000033.json");
        fs::write(&checkpoint, b"checkpoint").unwrap();
        fs::write(&blob, b"policy").unwrap();
        fs::hard_link(&checkpoint, state.join("checkpoint-alias")).unwrap();
        for directory in [&root, &state] {
            privileged(directory, true);
        }
        for leaf in [&checkpoint, &blob] {
            privileged(leaf, false);
        }
        assert_eq!(
            open_protected_bound_policy_pair_in_app_root(&root, 51)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::remove_dir_all(fixture).unwrap();
    }
}

/// Experimental dual-file checkpoint+epoch policy preflight. Both protected
/// leaves and their ClassMesh/state ancestors stay pinned through the callback.
/// This does NOT attest the volume root, ProgramData prefix, trusted anchor
/// provenance or checkpoint durability; never use as a production publisher.
#[derive(Debug)]
pub struct PinnedBoundPolicyPair {
    epoch: u64,
    checkpoint: File,
    policy: File,
    _app_root: File,
    _state_dir: File,
}

impl PinnedBoundPolicyPair {
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn with_files<T>(&self, action: impl FnOnce(&File, &File) -> T) -> T {
        action(&self.checkpoint, &self.policy)
    }
}

/// Fixed V2 checkpoint and deterministic epoch blob only. The caller must
/// independently establish that `epoch` came from a trusted durable anchor;
/// this function does NOT infer it from a path or trust unverified bytes.
pub fn open_protected_bound_policy_pair_in_app_root(
    app_root: &Path,
    epoch: u64,
) -> io::Result<PinnedBoundPolicyPair> {
    if epoch == 0 {
        return Err(permission_denied());
    }
    validate_app_root(app_root)?;
    let filename = format!("policy-{epoch:016x}.json");
    let pinned_app_root = open_protected_directory(app_root)?;
    let state_root = app_root.join("state");
    let pinned_state_dir = open_protected_directory(&state_root)?;
    let checkpoint = open_protected_policy_leaf(&state_root.join("policy-checkpoint.v2"))?;
    let policy = open_protected_policy_leaf(&state_root.join(&filename))?;
    attest_immediate_child(&pinned_app_root, &pinned_state_dir, "state")?;
    attest_immediate_child(&pinned_state_dir, &checkpoint, "policy-checkpoint.v2")?;
    attest_immediate_child(&pinned_state_dir, &policy, &filename)?;
    attest_same_volume_distinct_file_ids(
        &information_from_handle(&checkpoint)?,
        &information_from_handle(&policy)?,
    )?;
    Ok(PinnedBoundPolicyPair {
        epoch,
        checkpoint,
        policy,
        _app_root: pinned_app_root,
        _state_dir: pinned_state_dir,
    })
}

/// Internal-only reuse of the existing strict directory owner/DACL attestor.
/// This does not qualify its parent or the OS-selected ProgramData root.
pub(crate) fn open_protected_directory_for_bootstrap(path: &Path) -> io::Result<File> {
    open_protected_directory(path)
}

/// Internal-only same-HANDLE immediate-child adjacency for bootstrap tests.
/// Does not establish trust in the supplied ProgramData parent.
pub(crate) fn attest_bootstrap_child(parent: &File, child: &File) -> io::Result<()> {
    attest_immediate_child(parent, child, "ClassMesh")
}

/// Internal-only retained-HANDLE immediate state-child adjacency for isolated
/// create-only bootstrap. Does not authenticate the OS ProgramData ancestry.
pub(crate) fn attest_bootstrap_state_child(parent: &File, child: &File) -> io::Result<()> {
    attest_immediate_child(parent, child, "state")
}
