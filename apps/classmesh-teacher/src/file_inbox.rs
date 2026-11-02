//! Teacher AppInbox storage backed by an explicitly prepared local directory.
//!
//! The caller must supply a pre-provisioned, appropriately protected root.
//! File-ID binding, protected Windows ACL/retained ancestor handles and
//! post-sync readback reduce unsafe publication; same-user races and Windows
//! crash durability still require independent qualification.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use classmesh_control::file_transfer_receiver::FileTransferInboxSink;
use classmesh_protocol::file_transfer::MAX_FILE_TRANSFER_BYTES;

// OS file IDs are stronger than canonical path spelling: a directory or a
// .part name can be replaced with a different object at the same path.
type FileIdentity = (u64, u64);

#[cfg(unix)]
fn path_identity(path: &Path) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::symlink_metadata(path).ok()?;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(unix)]
fn open_file_identity(file: &File) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().ok()?;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn open_file_identity(file: &File) -> Option<FileIdentity> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };

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
    // SAFETY: File retains ownership of the live HANDLE and info is writable.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut info) } == 0 {
        return None;
    }
    Some((
        u64::from(info.dwVolumeSerialNumber),
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

#[cfg(windows)]
fn path_identity(path: &Path) -> Option<FileIdentity> {
    use std::os::windows::fs::OpenOptionsExt;
    // Open the named object itself, including a directory, not a reparse target.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .ok()?;
    open_file_identity(&file)
}

#[cfg(not(any(unix, windows)))]
fn path_identity(_path: &Path) -> Option<FileIdentity> {
    None // Unknown filesystem identity: fail closed.
}

#[cfg(not(any(unix, windows)))]
fn open_file_identity(_file: &File) -> Option<FileIdentity> {
    None
}

// Windows junctions are reparse points but are not always reported as
// symlinks. Check the ORIGINAL ancestor spelling before it is followed.
#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

// Check the caller's ORIGINAL spelling before canonicalization can hide an
// ancestor junction/symlink on Windows and Unix. Repeat on the resolved path at every boundary.
// This detects static reparse ancestors but does not replace retained
// directory HANDLEs, trusted owner/DACL checks or native Windows evidence.
#[cfg(any(unix, windows))]
fn root_ancestors_safe(root: &Path) -> bool {
    root.ancestors()
        .filter(|ancestor| ancestor.has_root())
        .all(|ancestor| {
            fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
                metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && !is_reparse_point(&metadata)
            })
        })
}

#[cfg(not(any(unix, windows)))]
fn root_ancestors_safe(_root: &Path) -> bool {
    true
}

// Publishing a hard link is not a durable commit until its containing
// directory entry is flushed. Windows directory flush/ACL qualification is a
// separate acceptance gate; do not infer Windows crash durability here.
#[cfg(unix)]
fn sync_inbox_directory(root: &Path) -> std::io::Result<()> {
    File::open(root)?.sync_all()
}

#[cfg(not(unix))]
fn sync_inbox_directory(_root: &Path) -> std::io::Result<()> {
    Ok(())
}

// The inbox root must be private. Its direct parent may grant foreign
// read/traverse rights but not create/delete/replace rights. Higher ancestors
// may also grant create-new-sibling rights (e.g. C:\), but must not allow
// replacing existing descendants or rewriting their ACLs.
// These are sampled ACL checks; namespace HANDLEs are retained separately.
#[cfg(windows)]
fn windows_directory_acl_safe(
    root: &Path,
    require_private: bool,
    allow_foreign_create: bool,
) -> bool {
    use std::ffi::c_void;
    use std::mem::{offset_of, size_of};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetSecurityInfo, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
        EqualSid, GetAce, GetLengthSid, GetTokenInformation, IsValidAcl, IsValidSid,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_MAX_SID_SIZE, TOKEN_QUERY,
        TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinCreatorOwnerSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: OpenProcessToken returned this owned handle.
                unsafe { CloseHandle(self.0) };
            }
        }
    }
    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: GetSecurityInfo allocates with LocalAlloc.
                unsafe { LocalFree(self.0) };
            }
        }
    }
    fn well_known(kind: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE) -> Option<Vec<u8>> {
        let mut sid = vec![0_u8; SECURITY_MAX_SID_SIZE as usize];
        let mut length = sid.len() as u32;
        // SAFETY: destination is writable for the maximum documented SID size.
        if unsafe { CreateWellKnownSid(kind, null_mut(), sid.as_mut_ptr().cast(), &mut length) }
            == 0
        {
            return None;
        }
        sid.truncate(length as usize);
        Some(sid)
    }
    fn equal_sid(a: PSID, b: PSID) -> bool {
        // SAFETY: both pointers come from validated SIDs in live allocations.
        unsafe { EqualSid(a, b) != 0 }
    }

    // Keep the inspected directory HANDLE live through descriptor parsing.
    // OPEN_REPARSE_POINT prevents this descriptor check from following a leaf link.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let Ok(dir) = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(root)
    else {
        return false;
    };

    let mut raw_token = null_mut();
    // SAFETY: pseudo-process handle is valid and output HANDLE is writable.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) } == 0 {
        return false;
    }
    let token = Token(raw_token);
    let mut required = 0_u32;
    // SAFETY: zero-size probe asks Windows for the required buffer length.
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &raw mut required) };
    if required < size_of::<TOKEN_USER>() as u32 || required > 4096 {
        return false;
    }
    let mut user_words = vec![0_usize; (required as usize).div_ceil(size_of::<usize>())];
    // SAFETY: word-aligned allocation is large enough for the reported bytes.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            user_words.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    } == 0
    {
        return false;
    }
    // SAFETY: TokenUser query initialized this aligned TOKEN_USER buffer.
    let user_sid = unsafe { (*(user_words.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    if user_sid.is_null() || unsafe { IsValidSid(user_sid) } == 0 {
        return false;
    }
    let Some(system) = well_known(WinLocalSystemSid) else {
        return false;
    };
    let Some(admins) = well_known(WinBuiltinAdministratorsSid) else {
        return false;
    };
    let Some(creator) = well_known(WinCreatorOwnerSid) else {
        return false;
    };
    // NT SERVICE\TrustedInstaller owns the standard Windows volume root.
    // Resolve its documented service SID, rather than accepting arbitrary
    // foreign owners of ancestors as trusted.
    let installer_text: Vec<u16> = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut installer_raw: PSID = null_mut();
    // SAFETY: NUL-terminated UTF-16 SID and writable output pointer.
    if unsafe { ConvertStringSidToSidW(installer_text.as_ptr(), &raw mut installer_raw) } == 0 {
        return false;
    }
    let installer_len = unsafe { GetLengthSid(installer_raw) } as usize;
    if installer_len < 8 || installer_len > SECURITY_MAX_SID_SIZE as usize {
        unsafe { LocalFree(installer_raw) };
        return false;
    }
    // SAFETY: ConvertStringSidToSidW returned a valid allocated SID.
    let installer =
        unsafe { std::slice::from_raw_parts(installer_raw.cast::<u8>(), installer_len) }.to_vec();
    unsafe { LocalFree(installer_raw) };
    let system_sid = system.as_ptr().cast_mut().cast();
    let admins_sid = admins.as_ptr().cast_mut().cast();
    let creator_sid = creator.as_ptr().cast_mut().cast();
    let installer_sid = installer.as_ptr().cast_mut().cast();

    let mut owner: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = Descriptor(null_mut());
    // SAFETY: dir remains open, outputs are writable, descriptor is freed by RAII.
    if unsafe {
        GetSecurityInfo(
            dir.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut descriptor.0,
        )
    } != 0
    {
        return false;
    }
    if descriptor.0.is_null()
        || owner.is_null()
        || dacl.is_null()
        || unsafe { IsValidSid(owner) } == 0
        || unsafe { IsValidAcl(dacl) } == 0
    {
        return false;
    }
    // A directory owned by a foreign user is not a trusted AppInbox, even
    // if its current DACL happens to be restrictive.
    if !equal_sid(owner, user_sid)
        && !equal_sid(owner, system_sid)
        && !equal_sid(owner, admins_sid)
        && !equal_sid(owner, installer_sid)
    {
        return false;
    }

    // Reject any unrecognized ACE rather than guessing its effect. This
    // conservative policy also rejects foreign read access to file contents.
    let count = unsafe { (*dacl).AceCount };
    if count == 0 || count > 64 {
        return false;
    }
    for index in 0..u32::from(count) {
        let mut raw_ace: *mut c_void = null_mut();
        // SAFETY: index is within the validated ACL's ACE count.
        if unsafe { GetAce(dacl, index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
            return false;
        }
        // SAFETY: GetAce returns at least a valid ACE_HEADER in the live ACL.
        let header = unsafe { &*(raw_ace.cast::<ACE_HEADER>()) };
        let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if header.AceType != 0 || usize::from(header.AceSize) < sid_offset + 8 {
            return false;
        }
        // SAFETY: ACE type and minimum size validated before accessing SidStart.
        let allowed = unsafe { &*(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
        let sid: PSID = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
        // SAFETY: GetLengthSid reads the SID header already bounded by ACE size.
        let sid_length = unsafe { GetLengthSid(sid) } as usize;
        if sid_length < 8
            || sid_length > usize::from(header.AceSize) - sid_offset
            || unsafe { IsValidSid(sid) } == 0
        {
            return false;
        }
        if !equal_sid(sid, user_sid)
            && !equal_sid(sid, system_sid)
            && !equal_sid(sid, admins_sid)
            && !equal_sid(sid, creator_sid)
        {
            if require_private {
                return false;
            }
            // On an ancestor, read/traverse and create-new-sibling rights
            // alone cannot replace an existing protected child. Deny any
            // foreign delete/rename, ACL/owner rewrite, generic write/all,
            // or attribute rewrite. Inherit-only ACEs are checked on their
            // actual descendant instead of on the current directory.
            const INHERIT_ONLY_ACE: u8 = 0x08;
            const UNSAFE_ANCESTOR_RIGHTS: u32 = 0x0001_0000
                | 0x0004_0000
                | 0x0008_0000
                | 0x0000_0040
                | 0x0000_0010
                | 0x0000_0100
                | 0x1000_0000
                | 0x4000_0000;
            // The direct parent is more sensitive than volume ancestors:
            // a foreign principal must not create a sibling of the inbox.
            const CREATE_CHILD_RIGHTS: u32 = 0x0000_0002 | 0x0000_0004;
            let forbidden = UNSAFE_ANCESTOR_RIGHTS
                | if allow_foreign_create {
                    0
                } else {
                    CREATE_CHILD_RIGHTS
                };
            if header.AceFlags & INHERIT_ONLY_ACE == 0 && allowed.Mask & forbidden != 0 {
                return false;
            }
        }
    }
    true
}

#[cfg(windows)]
fn windows_root_dacl_private(root: &Path) -> bool {
    windows_directory_acl_safe(root, true, false)
}

#[cfg(windows)]
fn windows_parent_dacl_safe(root: &Path) -> bool {
    windows_directory_acl_safe(root, false, false)
}

#[cfg(windows)]
fn windows_ancestor_dacl_safe(root: &Path) -> bool {
    windows_directory_acl_safe(root, false, true)
}

#[cfg(not(windows))]
fn windows_root_dacl_private(_root: &Path) -> bool {
    true
}

#[cfg(not(windows))]
fn windows_parent_dacl_safe(_root: &Path) -> bool {
    true
}

#[cfg(not(windows))]
fn windows_ancestor_dacl_safe(_root: &Path) -> bool {
    true
}

// Keep all original-path directory HANDLEs alive for the duration of a
// Windows transfer. Excluding FILE_SHARE_DELETE denies directory renames and
// unlink/replacement while complete() temporarily closes its .part HANDLE.
// This is a namespace lifetime guard, not a substitute for protected
// provisioning, fresh ACL checks or handle-relative create/link operations.
#[cfg(windows)]
fn windows_hold_namespace(root: &Path) -> Result<Vec<File>, TeacherFileInboxError> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    let mut guards = Vec::new();
    for ancestor in root.ancestors() {
        let guard = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(ancestor)
            .map_err(|_| TeacherFileInboxError::InvalidRoot)?;
        if !fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
            metadata.is_dir() && !metadata.file_type().is_symlink() && !is_reparse_point(&metadata)
        }) {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        guards.push(guard);
    }
    Ok(guards)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherFileInboxError {
    InvalidRoot,
    InvalidSize,
    ExistingTransfer,
    Busy,
    WrongTransfer,
    InvalidOffset,
    Incomplete,
    CorruptFile,
    Io,
}

#[derive(Debug)]
struct ActiveFile {
    id: [u8; 16],
    file: File,
    #[cfg(windows)]
    _ancestor_guards: Vec<File>,
    temp_path: PathBuf,
    final_path: PathBuf,
    received: u64,
    declared_size: u64,
    streamed_sha256: Sha256,
}

// The pre-provisioned inbox leaf must be private and owned by the effective
// unprivileged Teacher process; never silently chown or chmod it.
#[cfg(unix)]
fn root_permissions_safe(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: geteuid only reads the current POSIX process identity.
    let effective_uid = unsafe { geteuid() };
    effective_uid != 0
        && metadata.uid() == effective_uid
        && metadata.permissions().mode() & 0o077 == 0
}

// Sticky shared temporary ancestors are safe only when root-owned or owned
// by the same Teacher principal. Nonsticky foreign-writable ancestors fail.
#[cfg(unix)]
fn unix_ancestor_permissions_safe(root: &fs::Metadata, ancestor: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mode = ancestor.mode();
    mode & 0o022 == 0
        || (mode & 0o1000 != 0 && (ancestor.uid() == 0 || ancestor.uid() == root.uid()))
}

#[cfg(not(unix))]
fn unix_ancestor_permissions_safe(_root: &fs::Metadata, _ancestor: &fs::Metadata) -> bool {
    true
}

#[cfg(not(unix))]
fn root_permissions_safe(_metadata: &fs::Metadata) -> bool {
    true
}

/// Persist a single authenticated Teacher file into opaque, transfer-ID named
/// AppInbox files. Never turn the sender's display name into a path.
///
/// Caller must provide a private, previously created root. Only the receiver's
/// SHA-256 verified `finish` invokes `complete` to publish the finished file.
#[derive(Debug)]
pub struct TeacherFileInbox {
    root: PathBuf,
    root_identity: FileIdentity,
    active: Option<ActiveFile>,
}

impl TeacherFileInbox {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, TeacherFileInboxError> {
        Self::new_with_post_admission_hook(root, || {})
    }

    // Production and deterministic admission-race tests share this path.
    fn new_with_post_admission_hook(
        root: impl Into<PathBuf>,
        after_admission: impl FnOnce(),
    ) -> Result<Self, TeacherFileInboxError> {
        let root = root.into();
        if !Self::root_ready(&root) {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        let admitted_identity = path_identity(&root).ok_or(TeacherFileInboxError::InvalidRoot)?;
        after_admission();
        // The caller's original path must still identify the admitted root.
        // Otherwise an attacker can replace it with a symlink or a different
        // directory between the first check and canonicalization.
        if !Self::root_ready(&root) || path_identity(&root) != Some(admitted_identity) {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        // Resolve ancestor symlinks once at admission. Retaining the caller's
        // absolute spelling would let an ancestor alias be retargeted before
        // begin/complete and silently redirect verified file bytes. This is
        // defense in depth, NOT a Windows handle-based anti-reparse guarantee
        // against an attacker able to replace actual directory ancestors.
        let resolved = fs::canonicalize(&root).map_err(|_| TeacherFileInboxError::InvalidRoot)?;
        if !Self::root_ready(&root)
            || path_identity(&root) != Some(admitted_identity)
            || !Self::root_ready(&resolved)
            || path_identity(&resolved) != Some(admitted_identity)
        {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        let root = resolved;
        let root_identity = admitted_identity;
        Ok(Self {
            root,
            root_identity,
            active: None,
        })
    }

    fn root_ready(root: &Path) -> bool {
        let Ok(root_metadata) = fs::symlink_metadata(root) else {
            return false;
        };
        root.is_absolute()
            && !root
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            && root_ancestors_safe(root)
            && windows_root_dacl_private(root)
            && root.parent().is_some_and(windows_parent_dacl_safe)
            && root.ancestors().skip(2).all(windows_ancestor_dacl_safe)
            && root_permissions_safe(&root_metadata)
            && root.ancestors().skip(1).all(|ancestor| {
                fs::symlink_metadata(ancestor)
                    .is_ok_and(|metadata| unix_ancestor_permissions_safe(&root_metadata, &metadata))
            })
    }

    fn root_unchanged(&self) -> bool {
        Self::root_ready(&self.root) && path_identity(&self.root) == Some(self.root_identity)
    }

    fn path_matches_open_file(path: &Path, file: &File) -> bool {
        let from_handle = open_file_identity(file);
        let from_name = fs::symlink_metadata(path).ok().and_then(|m| {
            if m.is_file() && !m.file_type().is_symlink() && !is_reparse_point(&m) {
                path_identity(path)
            } else {
                None
            }
        });
        from_handle.is_some() && from_handle == from_name
    }

    fn partial_name_absent(active: &ActiveFile) -> bool {
        // Permission and metadata errors are not proof that the writable
        // alias is gone. Only a definite NotFound can permit Completed.
        matches!(
            fs::symlink_metadata(&active.temp_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
    }

    fn unlink_partial_before_final_check(&self, active: &ActiveFile) {
        // Keep the published inode HANDLE alive through the final destination
        // check, so a late rejection can retract the original .bin safely.
        // Removing .part while the handle is open is best-effort; a failed
        // unlink leaves a stale private partial, never a false Completed.
        if self.root_unchanged() && Self::path_matches_open_file(&active.temp_path, &active.file) {
            let _ = fs::remove_file(&active.temp_path);
        }
    }

    fn cleanup_partial(&self, active: ActiveFile) {
        // Never unlink a replacement .part or a file in a substituted root.
        let owned =
            self.root_unchanged() && Self::path_matches_open_file(&active.temp_path, &active.file);
        drop(active.file);
        if owned {
            let _ = fs::remove_file(active.temp_path);
        }
    }

    fn rollback_published_if_owned(&self, active: &ActiveFile) {
        // A root may become group/world-writable *after* hard_link. Its
        // permissions are then unsafe for Completed, but we can still try
        // to retract our own unacknowledged name if the root's OS identity
        // and the published inode both remain the originals. Never follow
        // a substituted root or unlink a different file at the same name.
        // This remains best-effort: hostile same-user name races require
        // retained directory handles and qualified ACLs before activation.
        if path_identity(&self.root) == Some(self.root_identity)
            && Self::path_matches_open_file(&active.final_path, &active.file)
            && fs::remove_file(&active.final_path).is_ok()
        {
            let _ = sync_inbox_directory(&self.root);
        }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The only published filename format. Caller may show this once the
    /// corresponding receiver returns a committed Completed status.
    #[must_use]
    pub fn completed_path(&self, id: &[u8; 16]) -> PathBuf {
        self.root.join(format!("{}.bin", id_stem(id)))
    }

    fn part_path(&self, id: &[u8; 16]) -> PathBuf {
        self.root.join(format!("{}.part", id_stem(id)))
    }
    fn begin_with_post_create(
        &mut self,
        id: &[u8; 16],
        size: u64,
        after_create: impl FnOnce(),
    ) -> Result<(), TeacherFileInboxError> {
        if size == 0 || size > MAX_FILE_TRANSFER_BYTES || id.iter().all(|b| *b == 0) {
            return Err(TeacherFileInboxError::InvalidSize);
        }
        if self.active.is_some() {
            return Err(TeacherFileInboxError::Busy);
        }
        if !self.root_unchanged() {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        // Acquire namespace guards before opening the .part file. A second
        // root check rejects detected ACL/path changes after guard acquisition.
        #[cfg(windows)]
        let ancestor_guards = windows_hold_namespace(&self.root)?;
        if !Self::root_ready(&self.root) {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        let temp_path = self.part_path(id);
        let final_path = self.completed_path(id);
        if fs::symlink_metadata(&final_path).is_ok() {
            return Err(TeacherFileInboxError::ExistingTransfer);
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&temp_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                TeacherFileInboxError::ExistingTransfer
            } else {
                TeacherFileInboxError::Io
            }
        })?;
        // Admission must bind the newly opened .part HANDLE to the same
        // trusted root and name, not just validate the directory before I/O.
        // An ancestor or .part may be exchanged while create_new is opening.
        after_create();
        let active = ActiveFile {
            id: *id,
            file,
            #[cfg(windows)]
            _ancestor_guards: ancestor_guards,
            temp_path,
            final_path,
            received: 0,
            declared_size: size,
            streamed_sha256: Sha256::new(),
        };
        if !self.root_unchanged() {
            self.cleanup_partial(active);
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        if !Self::path_matches_open_file(&active.temp_path, &active.file) {
            self.cleanup_partial(active);
            return Err(TeacherFileInboxError::Io);
        }
        self.active = Some(active);
        Ok(())
    }
    // The network receiver hashes the incoming chunks, but that does not
    // prove that the disk still contains those bytes. A local writer can
    // modify an existing .part inode without changing its OS file identity.
    // Read back the same retained HANDLE, in bounded memory, before publish.
    fn disk_matches_received_bytes(active: &ActiveFile) -> Result<bool, TeacherFileInboxError> {
        let mut reader = active
            .file
            .try_clone()
            .map_err(|_| TeacherFileInboxError::Io)?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|_| TeacherFileInboxError::Io)?;
        let mut on_disk = Sha256::new();
        let mut length = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|_| TeacherFileInboxError::Io)?;
            if count == 0 {
                break;
            }
            length = length
                .checked_add(count as u64)
                .ok_or(TeacherFileInboxError::CorruptFile)?;
            if length > active.declared_size {
                return Ok(false);
            }
            on_disk.update(&buffer[..count]);
        }
        Ok(length == active.received
            && on_disk.finalize() == active.streamed_sha256.clone().finalize())
    }

    fn complete_with_directory_sync(
        &mut self,
        id: &[u8; 16],
        sync_directory: impl FnMut(&Path) -> std::io::Result<()>,
    ) -> Result<(), TeacherFileInboxError> {
        self.complete_with_post_readback_hook(id, sync_directory, || {})
    }

    // The production complete path and the deterministic post-readback race
    // tests use the same commit implementation. The callback is a no-op in
    // production and models a concurrent local filesystem mutator in tests.
    fn complete_with_post_readback_hook(
        &mut self,
        id: &[u8; 16],
        sync_directory: impl FnMut(&Path) -> std::io::Result<()>,
        after_readback: impl FnOnce(),
    ) -> Result<(), TeacherFileInboxError> {
        self.complete_with_post_cleanup_hook(id, sync_directory, after_readback, || {})
    }

    // Test-only mutation hook runs at the final cleanup boundary of the same
    // production completion path. Production always supplies a no-op.
    fn complete_with_post_cleanup_hook(
        &mut self,
        id: &[u8; 16],
        mut sync_directory: impl FnMut(&Path) -> std::io::Result<()>,
        after_readback: impl FnOnce(),
        after_cleanup: impl FnOnce(),
    ) -> Result<(), TeacherFileInboxError> {
        let Some(active) = self.active.as_ref() else {
            return Err(TeacherFileInboxError::WrongTransfer);
        };
        if active.id != *id {
            return Err(TeacherFileInboxError::WrongTransfer);
        }
        if active.received != active.declared_size {
            return Err(TeacherFileInboxError::Incomplete);
        }
        // A path-only check at admission is insufficient: the directory or
        // .part name may have been substituted after we wrote verified chunks.
        if !self.root_unchanged() {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        if !Self::path_matches_open_file(&active.temp_path, &active.file) {
            return Err(TeacherFileInboxError::Io);
        }
        active
            .file
            .sync_all()
            .map_err(|_| TeacherFileInboxError::Io)?;
        if !Self::disk_matches_received_bytes(active)? {
            return Err(TeacherFileInboxError::CorruptFile);
        }
        if !self.root_unchanged() || !Self::path_matches_open_file(&active.temp_path, &active.file)
        {
            return Err(TeacherFileInboxError::Io);
        }

        // Atomic create-if-absent publishing: unlike rename, hard_link never
        // replaces an existing .bin. Retain the original file handle while
        // linking, then verify the new name still identifies that same file.
        fs::hard_link(&active.temp_path, &active.final_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                TeacherFileInboxError::ExistingTransfer
            } else {
                TeacherFileInboxError::Io
            }
        })?;
        if !self.root_unchanged() || !Self::path_matches_open_file(&active.final_path, &active.file)
        {
            self.rollback_published_if_owned(active);
            return Err(TeacherFileInboxError::Io);
        }
        // File::sync_all above persists bytes and inode metadata, but not
        // the new .bin directory entry. Do not acknowledge Completed before
        // the containing directory has been flushed on supported Unix hosts.
        if sync_directory(&self.root).is_err() {
            self.rollback_published_if_owned(active);
            return Err(TeacherFileInboxError::Io);
        }
        // Directory synchronization may take time. Revalidate the committed
        // name and root identity after it returns, not only before it starts.
        // This is still path-based defense in depth, not a retained-ancestor
        // HANDLE guarantee against an active same-user directory mutator.
        if !self.root_unchanged() || !Self::path_matches_open_file(&active.final_path, &active.file)
        {
            self.rollback_published_if_owned(active);
            return Err(TeacherFileInboxError::Io);
        }
        // Unlink the private .part name BEFORE the final disk readback.
        // Otherwise a same-inode writer can mutate the published .bin during
        // this last filesystem operation, after the last digest, while the
        // final name/identity checks still pass. Keep the original HANDLE
        // and active transfer for safe rollback if any later check fails.
        let active = self
            .active
            .as_ref()
            .ok_or(TeacherFileInboxError::WrongTransfer)?;
        let published_identity =
            open_file_identity(&active.file).ok_or(TeacherFileInboxError::Io)?;
        let final_path = active.final_path.clone();
        // A failed best-effort unlink leaves a stale private .part; never
        // unlink a replacement file at that name.
        self.unlink_partial_before_final_check(active);
        after_cleanup();

        // A successful publish must not leave a second writable name for
        // the same inode. If cleanup failed, or a local actor recreated a
        // .part alias during cleanup, never acknowledge Completed while the
        // published bytes can still be mutated through that alias. An
        // unexpected metadata error also fails closed, not as NotFound.
        if !Self::partial_name_absent(active) {
            self.rollback_published_if_owned(active);
            return Err(TeacherFileInboxError::Io);
        }

        // The .bin link was flushed above, but unlinking its former writable
        // .part name is a SECOND namespace mutation. Flush the directory
        // again before Completed, otherwise a crash can resurrect that alias.
        // Keep the original file HANDLE for safe rollback on sync failure.
        if !self.root_unchanged() || sync_directory(&self.root).is_err() {
            self.rollback_published_if_owned(active);
            return Err(TeacherFileInboxError::Io);
        }
        // The directory flush itself can race with recreation of .part.
        // Revalidate the alias after the flush before trusting the final
        // disk digest, rather than only checking immediately after unlink.
        if !Self::partial_name_absent(active) {
            self.rollback_published_if_owned(active);
            return Err(TeacherFileInboxError::Io);
        }

        // The directory sync and .part unlink can take time. A local writer
        // may change the *same inode* via .bin without changing its file ID.
        // This final bounded digest must run after both operations, before
        // acknowledging Completed. Windows exclusive-handle/ACL qualification
        // remains a separate production gate.
        let post_sync_error = match Self::disk_matches_received_bytes(active) {
            Ok(true) => None,
            Ok(false) => Some(TeacherFileInboxError::CorruptFile),
            Err(error) => Some(error),
        };
        if let Some(error) = post_sync_error {
            self.rollback_published_if_owned(active);
            return Err(error);
        }
        after_readback();
        // A final digest authenticates the retained inode, not a pathname.
        // Check the exact published destination binding after the readback,
        // without performing another mutating filesystem operation afterward.
        if !self.root_unchanged()
            || !Self::partial_name_absent(active)
            || !fs::symlink_metadata(&final_path).is_ok_and(|metadata| {
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && !is_reparse_point(&metadata)
            })
            || path_identity(&final_path) != Some(published_identity)
        {
            // Preserve active for receiver abort and never remove a
            // substituted .bin or root.
            self.rollback_published_if_owned(active);
            return Err(TeacherFileInboxError::Io);
        }
        self.active.take();
        Ok(())
    }
}

impl FileTransferInboxSink for TeacherFileInbox {
    type Error = TeacherFileInboxError;

    fn begin(&mut self, id: &[u8; 16], _filename: &str, size: u64) -> Result<(), Self::Error> {
        self.begin_with_post_create(id, size, || {})
    }

    fn append(&mut self, id: &[u8; 16], offset: u64, content: &[u8]) -> Result<(), Self::Error> {
        if !Self::root_ready(&self.root) {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        let active = self
            .active
            .as_ref()
            .ok_or(TeacherFileInboxError::WrongTransfer)?;
        if active.id != *id {
            return Err(TeacherFileInboxError::WrongTransfer);
        }
        if offset != active.received {
            return Err(TeacherFileInboxError::InvalidOffset);
        }
        let end = offset
            .checked_add(content.len() as u64)
            .ok_or(TeacherFileInboxError::InvalidOffset)?;
        if end > active.declared_size {
            return Err(TeacherFileInboxError::InvalidSize);
        }
        // The sink's retained File HANDLE does not authorize continuing to
        // write when its inbox root or .part pathname has been substituted.
        // Recheck at each chunk boundary, not only begin/complete, so an
        // attacker cannot keep receiving bytes into a displaced directory.
        if !self.root_unchanged() {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        if !Self::path_matches_open_file(&active.temp_path, &active.file) {
            return Err(TeacherFileInboxError::Io);
        }
        self.active
            .as_mut()
            .ok_or(TeacherFileInboxError::WrongTransfer)?
            .file
            .write_all(content)
            .map_err(|_| TeacherFileInboxError::Io)?;
        // A rename or permission change can race with write_all; fail the
        // chunk instead of acknowledging Progress if detected afterward.
        let active = self
            .active
            .as_ref()
            .ok_or(TeacherFileInboxError::WrongTransfer)?;
        if !self.root_unchanged() {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        if !Self::path_matches_open_file(&active.temp_path, &active.file) {
            return Err(TeacherFileInboxError::Io);
        }
        let active = self
            .active
            .as_mut()
            .ok_or(TeacherFileInboxError::WrongTransfer)?;
        active.received = end;
        active.streamed_sha256.update(content);
        Ok(())
    }

    fn complete(&mut self, id: &[u8; 16]) -> Result<(), Self::Error> {
        self.complete_with_directory_sync(id, sync_inbox_directory)
    }

    fn abort(&mut self, id: &[u8; 16]) {
        let Some(active) = self.active.take() else {
            return;
        };
        if active.id != *id {
            self.active = Some(active);
            return;
        }
        self.cleanup_partial(active);
    }
}

impl Drop for TeacherFileInbox {
    fn drop(&mut self) {
        if let Some(active) = self.active.take() {
            self.cleanup_partial(active);
        }
    }
}

fn id_stem(id: &[u8; 16]) -> String {
    use std::fmt::Write as _;
    let mut result = String::with_capacity(32);
    for byte in id {
        write!(&mut result, "{byte:02x}").expect("writing hex to String cannot fail");
    }
    result
}
#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use classmesh_control::file_transfer_receiver::{
        FileTransferInboxSink, FileTransferPeer, FileTransferReceiver, ReceiveError,
    };
    use classmesh_protocol::control_wire::{
        FileDestinationPolicy, FileTransferChunk, FileTransferFinish, FileTransferOffer,
        FileTransferState,
    };
    use classmesh_security::PrincipalId;
    use sha2::{Digest, Sha256};

    use super::{TeacherFileInbox, TeacherFileInboxError};

    static NEXT: AtomicU64 = AtomicU64::new(1);
    // Match production's pre-provisioned private leaf; do not relax
    // owner-only admission merely to make test-created roots pass.
    fn create_private_test_root(root: &std::path::Path) -> std::io::Result<()> {
        fs::create_dir(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    #[cfg(windows)]
    fn create_private_test_root_all(root: &std::path::Path) -> std::io::Result<()> {
        fs::create_dir_all(root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    const ID: [u8; 16] = [0x71; 16];

    fn temp_root(label: &str) -> std::path::PathBuf {
        // macOS /var is a system symlink to /private/var; tests must use
        // a canonical parent to exercise the intentionally strict admission.
        std::env::temp_dir()
            .canonicalize()
            .expect("canonical test temporary parent")
            .join(format!(
                "classmesh-teacher-inbox-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ))
    }

    fn offer(data: &[u8]) -> FileTransferOffer {
        FileTransferOffer {
            transfer_id: ID.to_vec(),
            filename: "lesson.pdf".to_string(),
            total_size: data.len() as u64,
            sha256: Sha256::digest(data).to_vec(),
            destination: FileDestinationPolicy::AppInbox as i32,
        }
    }

    fn peer() -> FileTransferPeer {
        FileTransferPeer {
            principal: PrincipalId([3; 32]),
            control_session_id: 14,
        }
    }

    #[test]
    fn verified_file_receiver_writes_bytes_to_opaque_inbox_only_after_hash_and_commit() {
        let root = temp_root("committed");
        create_private_test_root(&root).expect("explicit test root");
        let sink = TeacherFileInbox::new(&root).expect("prepared root");
        let expected = b"authenticated lesson from classroom";
        let mut receiver = FileTransferReceiver::new(sink);
        let status = receiver.offer(peer(), &offer(expected)).expect("offer");
        assert_eq!(status.state, FileTransferState::Accepted as i32);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        let chunk = FileTransferChunk {
            transfer_id: ID.to_vec(),
            offset: 0,
            content: expected.to_vec(),
        };
        let status = receiver.chunk(peer(), &chunk).expect("chunk");
        assert_eq!(status.state, FileTransferState::Progress as i32);
        assert!(!root.join(format!("{}.bin", "71".repeat(16))).exists());
        let status = receiver
            .finish(
                peer(),
                &FileTransferFinish {
                    transfer_id: ID.to_vec(),
                },
            )
            .expect("finish");
        assert_eq!(status.state, FileTransferState::Completed as i32);
        assert_eq!(
            fs::read(root.join(format!("{}.bin", "71".repeat(16)))).expect("committed bytes"),
            expected
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn same_inode_disk_corruption_after_chunk_must_not_publish_completed() {
        use std::io::Write as _;

        // The network receiver hashes authenticated bytes, but another local
        // writer can alter the same .part inode without changing its file ID.
        // Do not acknowledge Completed for bytes other than those received.
        let root = temp_root("same-inode-corruption");
        create_private_test_root(&root).unwrap();
        let expected = b"authenticated classroom lesson";
        let mut receiver = FileTransferReceiver::new(TeacherFileInbox::new(&root).unwrap());
        receiver.offer(peer(), &offer(expected)).unwrap();
        receiver
            .chunk(
                peer(),
                &FileTransferChunk {
                    transfer_id: ID.to_vec(),
                    offset: 0,
                    content: expected.to_vec(),
                },
            )
            .unwrap();

        let partial = root.join(format!("{}.part", "71".repeat(16)));
        let mut same_inode_writer = fs::OpenOptions::new().write(true).open(&partial).unwrap();
        same_inode_writer
            .write_all(&vec![b'X'; expected.len()])
            .unwrap();
        drop(same_inode_writer);

        assert_eq!(
            receiver.finish(
                peer(),
                &FileTransferFinish {
                    transfer_id: ID.to_vec(),
                },
            ),
            Err(ReceiveError::SinkFailure),
            "the received stream hash must not stand in for disk readback",
        );
        assert!(!receiver.sink().completed_path(&ID).exists());
        assert!(!partial.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn truncated_same_inode_is_reported_as_corrupt_not_completed() {
        let root = temp_root("truncated-part");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 8).unwrap();
        sink.append(&ID, 0, b"original").unwrap();

        let partial = root.join(format!("{}.part", "71".repeat(16)));
        fs::OpenOptions::new()
            .write(true)
            .open(&partial)
            .unwrap()
            .set_len(3)
            .unwrap();
        assert_eq!(sink.complete(&ID), Err(TeacherFileInboxError::CorruptFile));
        assert!(!sink.completed_path(&ID).exists());
        sink.abort(&ID);
        assert!(!partial.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn failed_directory_commit_sync_cannot_leave_an_unacknowledged_published_file() {
        // A verified .part inode alone is not a crash-durable committed
        // directory entry. A failed post-link directory flush must not
        // report Completed or leave a visible .bin on the ordinary path.
        let root = temp_root("directory-sync-failure");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();

        assert_eq!(
            sink.complete_with_directory_sync(&ID, |_root| {
                Err(std::io::Error::other("injected directory sync failure"))
            }),
            Err(TeacherFileInboxError::Io),
        );
        assert!(!sink.completed_path(&ID).exists());
        sink.abort(&ID);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn failed_post_unlink_directory_sync_must_not_ack_completed() {
        // A durable .bin link is insufficient if removing its writable .part
        // alias was never flushed. A crash can resurrect that alias.
        // Inject failure only on the *second* directory sync.
        let root = temp_root("post-unlink-sync-failure");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();
        let mut sync_calls = 0;
        let outcome = sink.complete_with_directory_sync(&ID, |path| {
            sync_calls += 1;
            if sync_calls == 2 {
                Err(std::io::Error::other("injected post-unlink sync failure"))
            } else {
                super::sync_inbox_directory(path)
            }
        });
        assert_eq!(sync_calls, 2, "both link and unlink must be durable");
        assert_eq!(outcome, Err(TeacherFileInboxError::Io));
        assert!(!sink.completed_path(&ID).exists());
        sink.abort(&ID);
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn post_publish_same_inode_mutation_during_directory_sync_is_not_completed() {
        use std::io::Write as _;

        // The first disk readback passes before hard_link. A local writer can
        // still alter the *same inode* via its newly published .bin name while
        // directory sync is in progress. Identity-only checks must not ACK it.
        let root = temp_root("post-publish-same-inode-mutation");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"good").unwrap();
        let published = sink.completed_path(&ID);

        let outcome = sink.complete_with_directory_sync(&ID, |_root| {
            fs::OpenOptions::new()
                .write(true)
                .open(&published)?
                .write_all(b"evil")?;
            Ok(())
        });
        assert_eq!(outcome, Err(TeacherFileInboxError::CorruptFile));
        assert!(
            !published.exists(),
            "corrupt published name must be rolled back"
        );
        sink.abort(&ID);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn replaced_published_name_after_final_readback_must_not_report_completed() {
        // The last readback proves the retained inode's bytes, not that the
        // destination name still points to that inode at ACK time.
        let root = temp_root("final-readback-name-swap");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();
        let published = sink.completed_path(&ID);
        let displaced = root.join("original-displaced.bin");

        let result =
            sink.complete_with_post_readback_hook(&ID, super::sync_inbox_directory, || {
                fs::rename(&published, &displaced).unwrap();
                fs::write(&published, b"decoy").unwrap();
            });
        assert_eq!(result, Err(TeacherFileInboxError::Io));
        assert_eq!(fs::read(&published).unwrap(), b"decoy");
        assert_eq!(fs::read(&displaced).unwrap(), b"data");
        sink.abort(&ID);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn replaced_root_after_final_readback_must_not_report_completed() {
        let root = temp_root("final-readback-root-swap");
        let moved = temp_root("final-readback-root-original");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();

        let result =
            sink.complete_with_post_readback_hook(&ID, super::sync_inbox_directory, || {
                fs::rename(&root, &moved).unwrap();
                create_private_test_root(&root).unwrap();
            });
        assert_eq!(result, Err(TeacherFileInboxError::Io));
        assert!(!sink.completed_path(&ID).exists());
        sink.abort(&ID);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn root_replacement_during_final_partial_cleanup_must_not_ack_completed() {
        // Final .part cleanup happens after the last destination identity
        // check. A local directory mutator must not redirect the Completed
        // path during that cleanup window.
        let root = temp_root("cleanup-root-swap");
        let moved = temp_root("cleanup-root-original");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();

        let result = sink.complete_with_post_cleanup_hook(
            &ID,
            super::sync_inbox_directory,
            || {},
            || {
                fs::rename(&root, &moved).unwrap();
                create_private_test_root(&root).unwrap();
            },
        );
        assert_eq!(result, Err(TeacherFileInboxError::Io));
        assert!(!sink.completed_path(&ID).exists());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn published_name_replacement_during_final_cleanup_must_not_ack_completed() {
        let root = temp_root("cleanup-name-swap");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();
        let published = sink.completed_path(&ID);
        let displaced = root.join("original-displaced.bin");

        let result = sink.complete_with_post_cleanup_hook(
            &ID,
            super::sync_inbox_directory,
            || {},
            || {
                fs::rename(&published, &displaced).unwrap();
                fs::write(&published, b"decoy").unwrap();
            },
        );
        assert_eq!(result, Err(TeacherFileInboxError::Io));
        assert_eq!(fs::read(&published).unwrap(), b"decoy");
        assert_eq!(fs::read(&displaced).unwrap(), b"data");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn same_inode_mutation_during_partial_cleanup_must_not_ack_completed() {
        use std::io::Write as _;

        // Removing .part happens after the previous disk readback. A writer
        // using the published .bin name can change bytes without changing
        // the inode identity while that cleanup runs.
        let root = temp_root("cleanup-same-inode-corruption");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"good").unwrap();
        let published = sink.completed_path(&ID);

        let result = sink.complete_with_post_cleanup_hook(
            &ID,
            super::sync_inbox_directory,
            || {},
            || {
                fs::OpenOptions::new()
                    .write(true)
                    .open(&published)
                    .unwrap()
                    .write_all(b"evil")
                    .unwrap();
            },
        );
        assert_eq!(result, Err(TeacherFileInboxError::CorruptFile));
        assert!(
            !published.exists(),
            "corrupted published bytes must never be acknowledged"
        );
        sink.abort(&ID);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn root_permission_revocation_after_partial_cleanup_rolls_back_unacknowledged_bin() {
        use std::os::unix::fs::PermissionsExt;

        // A permission change at the final cleanup boundary must not leave
        // a published .bin when the receiver will reject Completed.
        let root = temp_root("root-mode-revoked-after-cleanup");
        create_private_test_root(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();
        let published = sink.completed_path(&ID);

        let result = sink.complete_with_post_cleanup_hook(
            &ID,
            super::sync_inbox_directory,
            || {},
            || fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap(),
        );
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result, Err(TeacherFileInboxError::Io));
        assert!(
            !published.exists(),
            "a rejected final commit must retract its own published name"
        );
        sink.abort(&ID);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn root_permission_revocation_during_publish_must_not_leave_unacknowledged_bin() {
        use std::os::unix::fs::PermissionsExt;

        // Publication has already created the hard link when the directory
        // sync hook runs. Revoking the private-root invariant must not leave
        // an unacknowledged .bin even when the root inode is unchanged.
        let root = temp_root("root-mode-revoked-on-sync");
        create_private_test_root(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();
        let published = sink.completed_path(&ID);

        let result = sink.complete_with_directory_sync(&ID, |_root| {
            fs::set_permissions(&root, fs::Permissions::from_mode(0o777))?;
            Ok(())
        });
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result, Err(TeacherFileInboxError::Io));
        assert!(
            !published.exists(),
            "a rejected commit must not retain a published file in the same root"
        );
        sink.abort(&ID);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rollback_never_deletes_a_replacement_published_name() {
        let root = temp_root("postlink-decoy");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();
        let published = sink.completed_path(&ID);
        let displaced = root.join("displaced.bin");

        let result = sink.complete_with_directory_sync(&ID, |_root| {
            fs::rename(&published, &displaced)?;
            fs::write(&published, b"decoy")?;
            Ok(())
        });
        assert_eq!(result, Err(TeacherFileInboxError::Io));
        assert_eq!(fs::read(&published).unwrap(), b"decoy");
        assert_eq!(fs::read(&displaced).unwrap(), b"data");
        sink.abort(&ID);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn root_replacement_during_directory_sync_must_not_report_completed() {
        // A retained file inode does not bind the root pathname. If a
        // directory mutator replaces the root during the commit flush,
        // reporting Completed would point the caller to a different inbox.
        let root = temp_root("root-swap-on-sync");
        let moved = temp_root("root-swap-on-sync-original");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();

        let outcome = sink.complete_with_directory_sync(&ID, |_root| {
            fs::rename(&root, &moved)?;
            create_private_test_root(&root)?;
            Ok(())
        });
        assert_eq!(outcome, Err(TeacherFileInboxError::Io));
        assert!(!sink.completed_path(&ID).exists());
        sink.abort(&ID);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn received_file_remains_private_before_and_after_publication() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("private-mode");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        let part = root.join(format!("{}.part", "71".repeat(16)));
        assert_eq!(
            fs::metadata(&part).unwrap().permissions().mode() & 0o777,
            0o600,
            "authenticated file chunks must not be readable by other local users",
        );
        sink.append(&ID, 0, b"data").unwrap();
        sink.complete(&ID).unwrap();
        let published = sink.completed_path(&ID);
        assert_eq!(
            fs::metadata(&published).unwrap().permissions().mode() & 0o777,
            0o600,
            "publishing must not relax private file permissions",
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_rejects_group_or_world_writable_root_even_if_it_is_preexisting() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("untrusted-root-mode");
        create_private_test_root(&root).unwrap();
        for mode in [0o770, 0o777] {
            fs::set_permissions(&root, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(
                    TeacherFileInbox::new(&root),
                    Err(TeacherFileInboxError::InvalidRoot)
                ),
                "an inbox writable by other local principals must be rejected (mode {mode:o})",
            );
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(TeacherFileInbox::new(&root).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_rejects_root_that_becomes_group_writable_before_begin() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("root-mode-changed");
        create_private_test_root(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            sink.begin(&ID, "lesson.pdf", 4),
            Err(TeacherFileInboxError::InvalidRoot),
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_rejects_root_swap_between_partial_create_and_offer_acceptance() {
        let root = temp_root("begin-root-swap");
        let moved = temp_root("begin-root-original");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        assert_eq!(
            sink.begin_with_post_create(&ID, 4, || {
                fs::rename(&root, &moved).unwrap();
                create_private_test_root(&root).unwrap();
            }),
            Err(TeacherFileInboxError::InvalidRoot),
            "a moved inbox must not return Accepted after a partial file was created",
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_rejects_part_swap_between_create_and_offer_acceptance() {
        let root = temp_root("begin-part-swap");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        let part = root.join(format!("{}.part", "71".repeat(16)));
        let displaced = root.join("displaced.part");
        assert_eq!(
            sink.begin_with_post_create(&ID, 4, || {
                fs::rename(&part, &displaced).unwrap();
                fs::write(&part, b"decoy").unwrap();
            }),
            Err(TeacherFileInboxError::Io),
            "an exchanged .part must not return Accepted",
        );
        assert_eq!(fs::read(&part).unwrap(), b"decoy");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_digest_does_not_publish_file_and_aborts_partial() {
        let root = temp_root("hash-mismatch");
        create_private_test_root(&root).unwrap();
        let mut receiver = FileTransferReceiver::new(TeacherFileInbox::new(&root).unwrap());
        receiver.offer(peer(), &offer(b"expected bytes")).unwrap();
        receiver
            .chunk(
                peer(),
                &FileTransferChunk {
                    transfer_id: ID.to_vec(),
                    offset: 0,
                    content: b"wrong payload!".to_vec(),
                },
            )
            .unwrap();
        assert_eq!(
            receiver.finish(
                peer(),
                &FileTransferFinish {
                    transfer_id: ID.to_vec()
                }
            ),
            Err(ReceiveError::HashMismatch)
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inbox_refuses_missing_root_and_reused_transfer_without_overwriting() {
        let root = temp_root("exclusive");
        assert!(matches!(
            TeacherFileInbox::new(&root),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
        create_private_test_root(&root).unwrap();
        let final_file = root.join(format!("{}.bin", "71".repeat(16)));
        fs::write(&final_file, b"important existing file").unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        assert_eq!(
            sink.begin(&ID, "lesson.pdf", 4),
            Err(TeacherFileInboxError::ExistingTransfer)
        );
        assert_eq!(fs::read(final_file).unwrap(), b"important existing file");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inbox_rejects_replaced_root_before_creating_partial_file() {
        // A canonical absolute path can still be replaced with a different
        // directory after admission. No bytes may enter the replacement root.
        let root = temp_root("root-replaced");
        let moved = temp_root("root-moved");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        fs::rename(&root, &moved).unwrap();
        create_private_test_root(&root).unwrap();

        assert_eq!(
            sink.begin(&ID, "lesson.pdf", 4),
            Err(TeacherFileInboxError::InvalidRoot)
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_rejects_replaced_root_during_transfer_without_deleting_decoy() {
        let root = temp_root("root-swap-active");
        let moved = temp_root("root-swap-original");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"good").unwrap();
        fs::rename(&root, &moved).unwrap();
        create_private_test_root(&root).unwrap();
        let decoy_part = root.join(format!("{}.part", "71".repeat(16)));
        fs::write(&decoy_part, b"decoy").unwrap();

        assert_eq!(sink.complete(&ID), Err(TeacherFileInboxError::InvalidRoot));
        sink.abort(&ID);
        assert_eq!(fs::read(&decoy_part).unwrap(), b"decoy");
        assert!(!sink.completed_path(&ID).exists());
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_never_publishes_replaced_partial_file_as_verified_bytes() {
        // A peer's bytes were written to an open file, but a same-user
        // directory mutator replaces the .part name before commit.
        let root = temp_root("part-replaced");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"good").unwrap();
        let part = root.join(format!("{}.part", "71".repeat(16)));
        let displaced = root.join("displaced.part");
        fs::rename(&part, &displaced).unwrap();
        fs::write(&part, b"evil").unwrap();

        assert_eq!(sink.complete(&ID), Err(TeacherFileInboxError::Io));
        assert!(!sink.completed_path(&ID).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_refuses_chunk_after_root_replacement_without_writing_to_old_inode() {
        let root = temp_root("chunk-root-replaced");
        let moved = temp_root("chunk-root-moved");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 8).unwrap();
        sink.append(&ID, 0, b"good").unwrap();
        fs::rename(&root, &moved).unwrap();
        create_private_test_root(&root).unwrap();

        assert_eq!(
            sink.append(&ID, 4, b"evil"),
            Err(TeacherFileInboxError::InvalidRoot),
        );
        let old_part = moved.join(format!("{}.part", "71".repeat(16)));
        assert_eq!(fs::read(old_part).unwrap(), b"good");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        sink.abort(&ID);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_refuses_chunk_after_partial_name_replacement() {
        let root = temp_root("chunk-part-replaced");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 8).unwrap();
        sink.append(&ID, 0, b"good").unwrap();
        let part = root.join(format!("{}.part", "71".repeat(16)));
        let displaced = root.join("displaced.part");
        fs::rename(&part, &displaced).unwrap();
        fs::write(&part, b"decoy").unwrap();

        assert_eq!(sink.append(&ID, 4, b"evil"), Err(TeacherFileInboxError::Io),);
        assert_eq!(fs::read(displaced).unwrap(), b"good");
        assert_eq!(fs::read(part).unwrap(), b"decoy");
        sink.abort(&ID);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn readonly_inbox_root_is_io_failure_not_duplicate_offer() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("readonly-begin");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap();
        let result = sink.begin(&ID, "lesson.pdf", 4);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result, Err(TeacherFileInboxError::Io));
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn readonly_inbox_root_at_publish_is_io_failure_not_duplicate() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("readonly-publish");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o500)).unwrap();
        let result = sink.complete(&ID);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(result, Err(TeacherFileInboxError::Io));
        assert!(!sink.completed_path(&ID).exists());
        sink.abort(&ID);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inbox_rejects_relative_root_even_when_directory_exists() {
        // The process working directory is global and may change between
        // admission and a later chunk. A relative AppInbox could redirect
        // authenticated file bytes to an unintended location.
        assert!(matches!(
            TeacherFileInbox::new("."),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn inbox_rejects_root_swapped_to_symlink_during_admission() {
        // A trusted root can be replaced after the first metadata check but
        // before canonicalize. Do not silently admit the attacker's target.
        let root = temp_root("admission-root");
        let displaced = temp_root("admission-original");
        let decoy = temp_root("admission-decoy");
        create_private_test_root(&root).unwrap();
        fs::create_dir(&decoy).unwrap();
        let outcome = TeacherFileInbox::new_with_post_admission_hook(&root, || {
            fs::rename(&root, &displaced).unwrap();
            std::os::unix::fs::symlink(&decoy, &root).unwrap();
        });
        assert!(matches!(outcome, Err(TeacherFileInboxError::InvalidRoot)));
        fs::remove_file(root).unwrap();
        fs::remove_dir_all(displaced).unwrap();
        fs::remove_dir_all(decoy).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_rejects_ancestor_symlink_retargeted_during_admission() {
        // A preexisting alias can point at a trusted leaf during the first
        // check and at a different leaf by the time canonicalize resolves it.
        let original_parent = temp_root("admission-original-parent");
        let decoy_parent = temp_root("admission-decoy-parent");
        let alias = temp_root("admission-parent-alias");
        fs::create_dir_all(original_parent.join("inbox")).unwrap();
        fs::create_dir_all(decoy_parent.join("inbox")).unwrap();
        std::os::unix::fs::symlink(&original_parent, &alias).unwrap();
        let result = TeacherFileInbox::new_with_post_admission_hook(alias.join("inbox"), || {
            fs::remove_file(&alias).unwrap();
            std::os::unix::fs::symlink(&decoy_parent, &alias).unwrap();
        });
        assert!(matches!(result, Err(TeacherFileInboxError::InvalidRoot)));
        fs::remove_file(alias).unwrap();
        fs::remove_dir_all(original_parent).unwrap();
        fs::remove_dir_all(decoy_parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_rejects_alias_before_an_ancestor_symlink_can_be_retargeted() {
        // Do not accept an alias merely because canonicalization pins its
        // current destination: the original spelling crosses an untrusted
        // namespace link and must fail closed at admission.
        let original_parent = temp_root("original-parent");
        let decoy_parent = temp_root("decoy-parent");
        let alias = temp_root("parent-alias");
        let original = original_parent.join("inbox");
        let decoy = decoy_parent.join("inbox");
        fs::create_dir_all(&original).unwrap();
        fs::create_dir_all(&decoy).unwrap();
        std::os::unix::fs::symlink(&original_parent, &alias).unwrap();

        assert!(matches!(
            TeacherFileInbox::new(alias.join("inbox")),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
        fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&decoy_parent, &alias).unwrap();
        assert!(matches!(
            TeacherFileInbox::new(alias.join("inbox")),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
        assert_eq!(fs::read_dir(&original).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&decoy).unwrap().count(), 0);
        fs::remove_file(alias).unwrap();
        fs::remove_dir_all(original_parent).unwrap();
        fs::remove_dir_all(decoy_parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn recreated_partial_hardlink_after_cleanup_must_not_ack_completed() {
        // A same-user writer can reintroduce an alias to the published inode
        // during final cleanup. Reporting Completed would leave a writable
        // .part alias to the verified .bin after the receiver has finished.
        let root = temp_root("partial-relinked-after-cleanup");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();
        let published = sink.completed_path(&ID);
        let partial = root.join(format!("{}.part", "71".repeat(16)));
        let result = sink.complete_with_post_cleanup_hook(
            &ID,
            super::sync_inbox_directory,
            || {},
            || fs::hard_link(&published, &partial).unwrap(),
        );
        assert_eq!(result, Err(TeacherFileInboxError::Io));
        assert!(!published.exists(), "unacknowledged .bin must be retracted");
        sink.abort(&ID);
        assert!(!partial.exists(), "abort must remove the retained partial");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn relinked_partial_during_second_directory_sync_must_not_complete() {
        // A concurrent writer can recreate the writable .part alias after
        // the pre-sync absence check, while the unlink durability flush runs.
        // The same production complete path must not acknowledge this alias.
        let root = temp_root("partial-relinked-during-second-sync");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();
        let published = sink.completed_path(&ID);
        let partial = root.join(format!("{}.part", "71".repeat(16)));
        let mut sync_calls = 0;
        let result = sink.complete_with_directory_sync(&ID, |path| {
            sync_calls += 1;
            let outcome = super::sync_inbox_directory(path);
            if sync_calls == 2 {
                fs::hard_link(&published, &partial).unwrap();
            }
            outcome
        });
        assert_eq!(sync_calls, 2);
        assert_eq!(result, Err(TeacherFileInboxError::Io));
        assert!(!published.exists(), "must retract unacknowledged .bin");
        sink.abort(&ID);
        assert!(!partial.exists(), "abort must remove owned .part alias");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn relinked_partial_after_final_readback_must_not_complete() {
        // Even the last disk digest does not establish that the .part alias
        // remains absent at the final Completed decision boundary.
        let root = temp_root("partial-relinked-after-final-readback");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();
        let published = sink.completed_path(&ID);
        let partial = root.join(format!("{}.part", "71".repeat(16)));
        let result =
            sink.complete_with_post_readback_hook(&ID, super::sync_inbox_directory, || {
                fs::hard_link(&published, &partial).unwrap()
            });
        assert_eq!(result, Err(TeacherFileInboxError::Io));
        assert!(!published.exists(), "must retract unacknowledged .bin");
        sink.abort(&ID);
        assert!(!partial.exists(), "abort must remove owned .part alias");
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn inbox_rejects_root_swapped_to_junction_during_admission() {
        use std::process::Command;

        // Windows reparse points must not replace a checked AppInbox root
        // between its first metadata check and canonicalization.
        let root = temp_root("windows-admission-root");
        let original = temp_root("windows-admission-original");
        let decoy = temp_root("windows-admission-decoy");
        create_private_test_root(&root).unwrap();
        fs::create_dir(&decoy).unwrap();
        let result = TeacherFileInbox::new_with_post_admission_hook(&root, || {
            fs::rename(&root, &original).unwrap();
            let output = Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&root)
                .arg(&decoy)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "Windows junction fixture failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        });
        assert!(matches!(result, Err(TeacherFileInboxError::InvalidRoot)));
        fs::remove_dir(root).unwrap();
        fs::remove_dir_all(original).unwrap();
        fs::remove_dir_all(decoy).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn inbox_rejects_junction_in_untrusted_ancestor_before_canonicalizing() {
        use std::process::Command;

        // A junction in an ancestor can redirect a seemingly ordinary
        // AppInbox leaf. Canonicalizing first erases evidence of the junction.
        let real_parent = temp_root("windows-real-parent");
        let alias = temp_root("windows-ancestor-junction");
        fs::create_dir_all(real_parent.join("inbox")).unwrap();
        let output = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&alias)
            .arg(&real_parent)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "Windows junction fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(matches!(
            TeacherFileInbox::new(alias.join("inbox")),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
        fs::remove_dir(&alias).unwrap();
        fs::remove_dir_all(real_parent).unwrap();
    }

    #[test]
    fn inbox_rejects_parent_dir_components_in_trusted_root() {
        let parent = temp_root("parent-component");
        let inbox = parent.join("inbox");
        fs::create_dir_all(&inbox).unwrap();
        // A mutable intermediate directory must not redirect dot-dot
        // traversal after the admission checks. On Windows, canonicalize()
        // produces a verbatim \\?\ path: PathBuf::join("..") normalizes
        // that spelling *before* the inbox sees it. Construct an unnormalized
        // input to exercise the actual lexical admission gate on Windows.
        #[cfg(windows)]
        let ambiguous = std::path::PathBuf::from(format!(r"{}\..\inbox", inbox.display()));
        #[cfg(not(windows))]
        let ambiguous = inbox.join("..").join("inbox");
        assert!(
            ambiguous
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        );
        assert!(matches!(
            TeacherFileInbox::new(ambiguous),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_rejects_group_or_world_writable_root_without_chmod() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("untrusted-unix-mode");
        create_private_test_root(&root).unwrap();
        for mode in [0o777, 0o770] {
            fs::set_permissions(&root, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(
                    TeacherFileInbox::new(&root),
                    Err(TeacherFileInboxError::InvalidRoot)
                ),
                "mode {mode:o} must not be admitted as an AppInbox"
            );
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                mode,
                "rejecting a shared root must not silently chmod it"
            );
        }

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            TeacherFileInbox::new(&root).is_ok(),
            "private preprovisioned root remains admissible"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_accepts_private_root_inside_sticky_temporary_parent() {
        use std::os::unix::fs::PermissionsExt;

        let parent = temp_root("sticky-temporary-parent");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o1777)).unwrap();
        let root = parent.join("private-inbox");
        create_private_test_root(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            TeacherFileInbox::new(&root).is_ok(),
            "root must be checked independently of its sticky temporary ancestor"
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_rejects_symlinked_parent_of_apparently_real_root() {
        // The leaf itself is a directory; its untrusted parent alias must
        // not be canonicalized away before checking the original spelling.
        let parent = temp_root("real-parent");
        let alias = temp_root("symlinked-parent");
        let real_root = parent.join("inbox");
        fs::create_dir_all(&real_root).unwrap();
        std::os::unix::fs::symlink(&parent, &alias).unwrap();
        assert!(matches!(
            TeacherFileInbox::new(alias.join("inbox")),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
        fs::remove_file(alias).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn inbox_rejects_foreign_windows_dacl_at_admission_and_before_begin() {
        use std::process::Command;
        let root = temp_root("foreign-dacl");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).expect("private Windows test root");
        // The test owns this disposable directory. A foreign principal with
        // Modify rights must not be able to rewrite received lesson bytes.
        let grant = Command::new("icacls")
            .arg(&root)
            .arg("/grant")
            .arg("*S-1-1-0:(OI)(CI)M")
            .output()
            .expect("native Windows icacls");
        assert!(grant.status.success(), "icacls failed: {grant:?}");
        assert!(matches!(
            TeacherFileInbox::new(&root),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
        assert_eq!(
            sink.begin(&ID, "lesson.pdf", 4),
            Err(TeacherFileInboxError::InvalidRoot)
        );
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn inbox_rejects_writable_grandparent_even_when_parent_and_leaf_are_private() {
        use std::process::Command;
        let grandparent = temp_root("foreign-grandparent-dacl");
        let parent = grandparent.join("parent");
        let root = parent.join("inbox");
        fs::create_dir(&grandparent).unwrap();
        fs::create_dir(&parent).unwrap();
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).expect("initial private ancestors");
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"DATA").unwrap();

        // The ACL grant has no inheritance flags. Both direct parent and
        // inbox remain private; an attacker can replace the parent entry.
        let grant = Command::new("icacls")
            .arg(&grandparent)
            .arg("/grant")
            .arg("*S-1-1-0:M")
            .output()
            .expect("native Windows icacls");
        assert!(grant.status.success(), "icacls failed: {grant:?}");
        assert!(super::windows_root_dacl_private(&parent));
        assert!(super::windows_root_dacl_private(&root));
        assert!(matches!(
            TeacherFileInbox::new(&root),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
        assert_eq!(sink.complete(&ID), Err(TeacherFileInboxError::InvalidRoot));
        assert!(!sink.completed_path(&ID).exists());
        sink.abort(&ID);
        fs::remove_dir_all(grandparent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn inbox_accepts_read_only_foreign_parent_but_rejects_child_creation() {
        use std::process::Command;
        let base = temp_root("read-only-parent");
        let parent = base.join("parent");
        let root = parent.join("inbox");
        create_private_test_root_all(&root).unwrap();
        // A standard Windows profile may grant traversal to AppContainer
        // capability SIDs. Reading/traversing the parent cannot replace the
        // private inbox; denying this would make ordinary provisioning fail.
        let read_grant = Command::new("icacls")
            .arg(&parent)
            .arg("/grant")
            .arg("*S-1-1-0:RX")
            .output()
            .expect("native Windows icacls");
        assert!(read_grant.status.success(), "icacls failed: {read_grant:?}");
        assert!(TeacherFileInbox::new(&root).is_ok());

        // Creating children of the immediate parent is still forbidden even
        // though higher-level ancestors may permit unrelated sibling creation.
        let write_grant = Command::new("icacls")
            .arg(&parent)
            .arg("/grant")
            .arg("*S-1-1-0:W")
            .output()
            .expect("native Windows icacls");
        assert!(
            write_grant.status.success(),
            "icacls failed: {write_grant:?}"
        );
        assert!(matches!(
            TeacherFileInbox::new(&root),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
        fs::remove_dir_all(base).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn inbox_rejects_untrusted_immediate_parent_even_when_leaf_is_private() {
        use std::process::Command;
        let parent = temp_root("foreign-parent-dacl");
        let root = parent.join("inbox");
        fs::create_dir(&parent).unwrap();
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).expect("initial private parent and leaf");
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"DATA").unwrap();

        // Grant only on the parent, without inheritance flags. The leaf
        // remains private but a foreign principal can replace its parent
        // directory entry, so neither admission nor Completed is safe.
        let grant = Command::new("icacls")
            .arg(&parent)
            .arg("/grant")
            .arg("*S-1-1-0:M")
            .output()
            .expect("native Windows icacls");
        assert!(grant.status.success(), "icacls failed: {grant:?}");
        assert!(super::windows_root_dacl_private(&root));
        assert!(matches!(
            TeacherFileInbox::new(&root),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
        assert_eq!(sink.complete(&ID), Err(TeacherFileInboxError::InvalidRoot));
        assert!(!sink.completed_path(&ID).exists());
        sink.abort(&ID);
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn inbox_rejects_windows_acl_revoked_after_chunk_before_publish() {
        use std::process::Command;
        let root = temp_root("acl-revoked-before-publish");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).expect("private Windows test root");
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"DATA").unwrap();
        let grant = Command::new("icacls")
            .arg(&root)
            .arg("/grant")
            .arg("*S-1-1-0:(OI)(CI)M")
            .output()
            .expect("native Windows icacls");
        assert!(grant.status.success(), "icacls failed: {grant:?}");
        assert_eq!(sink.complete(&ID), Err(TeacherFileInboxError::InvalidRoot));
        assert!(!sink.completed_path(&ID).exists());
        assert_eq!(
            sink.append(&ID, 4, b""),
            Err(TeacherFileInboxError::InvalidRoot)
        );
        sink.abort(&ID);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn inbox_must_not_ack_completed_if_windows_refuses_part_unlink() {
        let root = temp_root("blocked-part-unlink");
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"DATA").unwrap();
        let part = root.join(format!("{}.part", "71".repeat(16)));
        let final_path = sink.completed_path(&ID);
        use std::os::windows::fs::OpenOptionsExt;
        // A second local HANDLE that shares read/write but not delete keeps
        // the hard link publish possible while refusing the .part unlink.
        let blocker = fs::OpenOptions::new()
            .read(true)
            .share_mode(0x1 | 0x2)
            .open(&part)
            .unwrap();
        assert_eq!(sink.complete(&ID), Err(TeacherFileInboxError::Io));
        drop(blocker);
        if final_path.exists() {
            fs::remove_file(&final_path).unwrap();
        }
        if part.exists() {
            fs::remove_file(&part).unwrap();
        }
        fs::remove_dir(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn inbox_retains_ancestor_handles_while_receiving_to_block_directory_replacement() {
        let parent = temp_root("retained-parent");
        let moved_parent = temp_root("retained-parent-moved");
        let root = parent.join("inbox");
        fs::create_dir(&parent).unwrap();
        create_private_test_root(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).expect("private prepared inbox");
        sink.begin(&ID, "lesson.pdf", 4).unwrap();

        // Renaming a parent while the transfer is active must be denied on
        // Windows; otherwise subsequent pathname operations may target an
        // attacker-controlled replacement, despite admission-time DACLs.
        // Fault-inject the exact interval after complete() closes its .part
        // HANDLE and before it publishes the hard link. Without separate
        // retained directory HANDLEs, a parent rename succeeds in this gap.
        let placeholder = fs::File::open(std::env::current_exe().unwrap()).unwrap();
        let old_part_handle =
            std::mem::replace(&mut sink.active.as_mut().unwrap().file, placeholder);
        drop(old_part_handle);
        let rename_during_transfer = fs::rename(&parent, &moved_parent);
        assert!(
            rename_during_transfer.is_err(),
            "Windows allowed ancestor rename after .part HANDLE closed"
        );
        sink.abort(&ID);
        drop(sink);
        // Guard handles must be released on abort.
        fs::rename(&parent, &moved_parent).expect("ancestor unlocked after transfer");
        fs::remove_dir_all(moved_parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn inbox_rejects_junction_in_parent_before_accepting_root() {
        let parent = temp_root("trusted-parent-junction");
        let alias = temp_root("parent-junction");
        let inbox = parent.join("inbox");
        fs::create_dir_all(&inbox).unwrap();
        let output = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(&alias)
            .arg(&parent)
            .output()
            .expect("cmd mklink available on Windows");
        assert!(output.status.success(), "junction setup failed: {output:?}");
        assert!(matches!(
            TeacherFileInbox::new(alias.join("inbox")),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
        fs::remove_dir(&alias).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_rejects_symlink_root_instead_of_following_an_untrusted_destination() {
        let root = temp_root("real");
        let alias = temp_root("alias");
        create_private_test_root(&root).unwrap();
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        assert!(matches!(
            TeacherFileInbox::new(&alias),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
        fs::remove_file(alias).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
