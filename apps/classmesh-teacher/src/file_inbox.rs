//! Teacher AppInbox storage backed by an explicitly prepared local directory.
//!
//! The caller must supply a pre-provisioned, appropriately protected root.
//! Static path checks reject observed symlink/junction ancestors, but do NOT
//! establish retained ancestor HANDLEs, durable namespace commits, or
//! anti-TOCTOU guarantees against an adversary replacing directory ancestors.
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use classmesh_control::file_transfer_receiver::FileTransferInboxSink;
use classmesh_protocol::file_transfer::MAX_FILE_TRANSFER_BYTES;

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
}

// A shared writable inbox lets other users replace transfer paths between
// pathname-based publication and cleanup. The caller owns provisioning;
// rejecting an unsafe root must never silently chmod someone else's directory.
#[cfg(unix)]
fn root_permissions_safe(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o022 == 0
}

// A private inbox is not safe beneath a non-sticky group/world-writable
// directory: another principal could replace the private leaf by pathname.
// Sticky directories are acceptable only when owned by root or by the inbox
// owner, because the sticky-directory owner may otherwise delete the leaf.
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

// Windows ACL/owner checks remain authoritative on Windows; Unix mode bits
// are not a substitute for those checks.
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
    active: Option<ActiveFile>,
}

impl TeacherFileInbox {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, TeacherFileInboxError> {
        let root = root.into();
        if !Self::root_ready(&root) {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        Ok(Self { root, active: None })
    }

    fn root_ready(root: &Path) -> bool {
        let Ok(root_metadata) = fs::symlink_metadata(root) else {
            return false;
        };
        root.is_absolute()
            // A mutable intermediate directory must never redirect a
            // parent traversal after the original-path security checks.
            && !root
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            && windows_root_dacl_private(root)
            // The leaf may be private while its parent grants a foreign
            // principal directory-entry replacement rights. Do not accept
            // that as a trusted namespace for publishing received files.
            && root.parent().is_some_and(windows_parent_dacl_safe)
            && root.ancestors().skip(2).all(windows_ancestor_dacl_safe)
            // A canonical temporary ancestor may be writable only if sticky
            // and owned by root/the inbox owner; a non-sticky writable parent
            // could replace the private inbox entry before publication.
            && root_permissions_safe(&root_metadata)
            && root.ancestors().all(|ancestor| {
                fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
                    metadata.is_dir()
                        && !metadata.file_type().is_symlink()
                        && !is_reparse_point(&metadata)
                        && (ancestor == root
                            || unix_ancestor_permissions_safe(&root_metadata, &metadata))
                })
            })
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
}

impl FileTransferInboxSink for TeacherFileInbox {
    type Error = TeacherFileInboxError;

    fn begin(&mut self, id: &[u8; 16], _filename: &str, size: u64) -> Result<(), Self::Error> {
        if size == 0 || size > MAX_FILE_TRANSFER_BYTES || id.iter().all(|b| *b == 0) {
            return Err(TeacherFileInboxError::InvalidSize);
        }
        if self.active.is_some() {
            return Err(TeacherFileInboxError::Busy);
        }
        if !Self::root_ready(&self.root) {
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
        // create_new guarantees that a pre-existing .part (including a
        // dangling symlink) can never be followed or overwritten.
        if fs::symlink_metadata(&final_path).is_ok() {
            return Err(TeacherFileInboxError::ExistingTransfer);
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|_| TeacherFileInboxError::ExistingTransfer)?;
        self.active = Some(ActiveFile {
            id: *id,
            file,
            #[cfg(windows)]
            _ancestor_guards: ancestor_guards,
            temp_path,
            final_path,
            received: 0,
            declared_size: size,
        });
        Ok(())
    }

    fn append(&mut self, id: &[u8; 16], offset: u64, content: &[u8]) -> Result<(), Self::Error> {
        if !Self::root_ready(&self.root) {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        let active = self
            .active
            .as_mut()
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
        active
            .file
            .write_all(content)
            .map_err(|_| TeacherFileInboxError::Io)?;
        // The ACL can change while a chunk is written; never report Progress
        // after a detected change to an untrusted destination.
        if !Self::root_ready(&self.root) {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        active.received = end;
        Ok(())
    }

    fn complete(&mut self, id: &[u8; 16]) -> Result<(), Self::Error> {
        let Some(active) = self.active.as_ref() else {
            return Err(TeacherFileInboxError::WrongTransfer);
        };
        if active.id != *id {
            return Err(TeacherFileInboxError::WrongTransfer);
        }
        if active.received != active.declared_size {
            return Err(TeacherFileInboxError::Incomplete);
        }
        // Admission-time ACL checks are not a lifetime grant. Refuse to
        // publish or acknowledge when another principal acquired inbox access.
        if !Self::root_ready(&self.root) {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        let active = self
            .active
            .take()
            .ok_or(TeacherFileInboxError::WrongTransfer)?;
        if active.file.sync_all().is_err() {
            drop(active.file);
            let _ = fs::remove_file(active.temp_path);
            return Err(TeacherFileInboxError::Io);
        }
        drop(active.file);

        // Atomic create-if-absent publishing: unlike rename, hard_link never
        // replaces an existing .bin even if another process races publication.
        if fs::hard_link(&active.temp_path, &active.final_path).is_err() {
            let _ = fs::remove_file(active.temp_path);
            return Err(TeacherFileInboxError::ExistingTransfer);
        }
        // Do not acknowledge a committed file while a second .part name can
        // still be opened to modify its bytes. On Windows an unrelated HANDLE
        // can deny deletion even after the sink closes its own file handle.
        if fs::remove_file(&active.temp_path).is_err() {
            // Best-effort rollback: a concurrently held no-share-delete HANDLE
            // may prevent both unlinks. In that case return Io, never Completed.
            let _ = fs::remove_file(&active.final_path);
            return Err(TeacherFileInboxError::Io);
        }
        Ok(())
    }

    fn abort(&mut self, id: &[u8; 16]) {
        let Some(active) = self.active.take() else {
            return;
        };
        if active.id != *id {
            self.active = Some(active);
            return;
        }
        drop(active.file);
        let _ = fs::remove_file(active.temp_path);
    }
}

impl Drop for TeacherFileInbox {
    fn drop(&mut self) {
        if let Some(active) = self.active.take() {
            drop(active.file);
            let _ = fs::remove_file(active.temp_path);
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
        fs::create_dir(&root).expect("explicit test root");
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
    fn wrong_digest_does_not_publish_file_and_aborts_partial() {
        let root = temp_root("hash-mismatch");
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
        for mode in [0o777, 0o770, 0o755, 0o750] {
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
    fn inbox_partial_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_root("private-part-mode");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut sink = TeacherFileInbox::new(&root).expect("private AppInbox");
        sink.begin(&ID, "untrusted-name.pdf", 4).unwrap();
        let partial = root.join(format!("{}.part", "71".repeat(16)));
        let mode = fs::metadata(&partial).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "received classroom bytes must never be readable by another local principal");
        sink.abort(&ID);
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
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            TeacherFileInbox::new(&root).is_ok(),
            "root must be checked independently of its sticky temporary ancestor"
        );
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_rejects_nonsticky_writable_ancestor_before_publication() {
        use std::os::unix::fs::PermissionsExt;

        let parent = temp_root("nonsticky-writable-parent");
        let root = parent.join("private-inbox");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut sink = TeacherFileInbox::new(&root).expect("initially private ancestry");
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"DATA").unwrap();

        // Without the sticky bit, another principal can replace the inbox
        // entry in this world-writable parent even though its leaf is 0700.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            TeacherFileInbox::new(&root),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
        assert_eq!(sink.complete(&ID), Err(TeacherFileInboxError::InvalidRoot));
        assert!(!sink.completed_path(&ID).exists());
        sink.abort(&ID);
        fs::remove_dir_all(parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn inbox_rejects_symlinked_parent_of_apparently_real_root() {
        let parent = temp_root("trusted-parent");
        let alias = temp_root("parent-alias");
        let inbox = parent.join("inbox");
        fs::create_dir_all(&inbox).unwrap();
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir_all(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
        std::os::unix::fs::symlink(&root, &alias).unwrap();
        assert!(matches!(
            TeacherFileInbox::new(&alias),
            Err(TeacherFileInboxError::InvalidRoot)
        ));
        fs::remove_file(alias).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
