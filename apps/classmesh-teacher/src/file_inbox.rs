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

// Fail-closed DACL admission for the provisioned Windows AppInbox root and
// its immediate parent. This is not a retained-ancestor-HANDLE or anti-TOCTOU proof.
// A NULL DACL, unknown ACE, foreign owner, or an ACE granting any access to
// an untrusted SID must not be treated as a private receiving directory.
#[cfg(windows)]
fn windows_root_dacl_private(root: &Path) -> bool {
    use std::ffi::c_void;
    use std::mem::{offset_of, size_of};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
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
    let system_sid = system.as_ptr().cast_mut().cast();
    let admins_sid = admins.as_ptr().cast_mut().cast();
    let creator_sid = creator.as_ptr().cast_mut().cast();

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
    if !equal_sid(owner, user_sid) && !equal_sid(owner, system_sid) && !equal_sid(owner, admins_sid)
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
            return false;
        }
    }
    true
}

#[cfg(not(windows))]
fn windows_root_dacl_private(_root: &Path) -> bool {
    true
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
    temp_path: PathBuf,
    final_path: PathBuf,
    received: u64,
    declared_size: u64,
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
        root.is_absolute()
            && windows_root_dacl_private(root)
            // The leaf may be private while its parent grants a foreign
            // principal directory-entry replacement rights. Do not accept
            // that as a trusted namespace for publishing received files.
            && root.parent().is_some_and(windows_root_dacl_private)
            && root.ancestors().all(|ancestor| {
                fs::symlink_metadata(ancestor).is_ok_and(|metadata| {
                    metadata.is_dir()
                        && !metadata.file_type().is_symlink()
                        && !is_reparse_point(&metadata)
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
