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
    if count < 2 || count > 32 {
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
pub fn open_protected_policy_in_app_root(app_root: &Path) -> io::Result<PinnedPolicyCandidate> {
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
    let pinned_app_root = open_protected_directory(app_root)?;
    let state_root = app_root.join("state");
    let pinned_state_dir = open_protected_directory(&state_root)?;
    let leaf = open_protected_policy_leaf(&state_root.join("authorization.json"))?;
    Ok(PinnedPolicyCandidate {
        leaf,
        _app_root: pinned_app_root,
        _state_dir: pinned_state_dir,
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
