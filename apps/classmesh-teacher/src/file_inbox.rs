//! Teacher AppInbox storage backed by an explicitly prepared local directory.
//!
//! The caller must supply a pre-provisioned, appropriately protected root.
//! OS file-ID checks reject observed root/partial-file replacement, but
//! they do not establish trusted Windows ACL/ancestor-handle anti-reparse
//! guarantees or close same-user mutation races between checks and publish.
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

// A group/other-writable inbox lets another local principal replace a
// transfer's .part/.bin names between identity checks. The directory is
// provisioned by the caller; never silently chmod a shared directory.
#[cfg(unix)]
fn root_permissions_safe(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o022 == 0
}

// Windows needs separate trusted owner/DACL and retained ancestor-HANDLE
// validation before production use; Unix mode bits cannot stand in for ACLs.
#[cfg(not(unix))]
fn root_permissions_safe(_metadata: &fs::Metadata) -> bool {
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
    CorruptFile,
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
    streamed_sha256: Sha256,
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
        let root = root.into();
        if !Self::root_ready(&root) {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        // Resolve ancestor symlinks once at admission. Retaining the caller's
        // absolute spelling would let an ancestor alias be retargeted before
        // begin/complete and silently redirect verified file bytes. This is
        // defense in depth, NOT a Windows handle-based anti-reparse guarantee
        // against an attacker able to replace actual directory ancestors.
        let root = fs::canonicalize(&root).map_err(|_| TeacherFileInboxError::InvalidRoot)?;
        if !Self::root_ready(&root) {
            return Err(TeacherFileInboxError::InvalidRoot);
        }
        let root_identity = path_identity(&root).ok_or(TeacherFileInboxError::InvalidRoot)?;
        Ok(Self {
            root,
            root_identity,
            active: None,
        })
    }

    fn root_ready(root: &Path) -> bool {
        // Never retain a cwd-relative inbox. Also reject Windows junctions
        // and other direct reparse points, not only symbolic links.
        root.is_absolute()
            && fs::symlink_metadata(root).is_ok_and(|metadata| {
                metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && !is_reparse_point(&metadata)
                    && root_permissions_safe(&metadata)
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
        sync_directory: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> Result<(), TeacherFileInboxError> {
        self.complete_with_post_readback_hook(id, sync_directory, || {})
    }

    // The production complete path and the deterministic post-readback race
    // tests use the same commit implementation. The callback is a no-op in
    // production and models a concurrent local filesystem mutator in tests.
    fn complete_with_post_readback_hook(
        &mut self,
        id: &[u8; 16],
        sync_directory: impl FnOnce(&Path) -> std::io::Result<()>,
        after_readback: impl FnOnce(),
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
        // A same-inode writer can change .bin bytes *during* the directory
        // flush, after the earlier disk readback. Rehash from the retained
        // file HANDLE before ACKing Completed; inode identity alone cannot
        // establish content integrity. This is a bounded second pass, not a
        // substitute for trusted ACLs / exclusive Windows HANDLE admission.
        let post_sync_error = match Self::disk_matches_received_bytes(active) {
            Ok(true) => None,
            Ok(false) => Some(TeacherFileInboxError::CorruptFile),
            Err(error) => Some(error),
        };
        if let Some(error) = post_sync_error {
            // Revoke the published name only when it still identifies the
            // retained file in the original root.
            self.rollback_published_if_owned(active);
            return Err(error);
        }
        after_readback();
        // The final disk digest authenticates the retained inode, but an
        // attacker may exchange the published name or its root while that
        // bounded readback is in progress. Check the destination binding once
        // more before returning Completed to the authenticated receiver.
        if !self.root_unchanged() || !Self::path_matches_open_file(&active.final_path, &active.file)
        {
            self.rollback_published_if_owned(active);
            return Err(TeacherFileInboxError::Io);
        }
        let active = self
            .active
            .take()
            .ok_or(TeacherFileInboxError::WrongTransfer)?;
        // The .bin is committed. A failed best-effort unlink leaves a stale
        // .part; never unlink a replacement file at that name.
        self.cleanup_partial(active);
        Ok(())
    }
}

impl FileTransferInboxSink for TeacherFileInbox {
    type Error = TeacherFileInboxError;

    fn begin(&mut self, id: &[u8; 16], _filename: &str, size: u64) -> Result<(), Self::Error> {
        self.begin_with_post_create(id, size, || {})
    }

    fn append(&mut self, id: &[u8; 16], offset: u64, content: &[u8]) -> Result<(), Self::Error> {
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
    const ID: [u8; 16] = [0x71; 16];

    fn temp_root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
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
    fn same_inode_disk_corruption_after_chunk_must_not_publish_completed() {
        use std::io::Write as _;

        // The network receiver hashes authenticated bytes, but another local
        // writer can alter the same .part inode without changing its file ID.
        // Do not acknowledge Completed for bytes other than those received.
        let root = temp_root("same-inode-corruption");
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
    fn post_publish_same_inode_mutation_during_directory_sync_is_not_completed() {
        use std::io::Write as _;

        // The first disk readback passes before hard_link. A local writer can
        // still alter the *same inode* via its newly published .bin name while
        // directory sync is in progress. Identity-only checks must not ACK it.
        let root = temp_root("post-publish-same-inode-mutation");
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();

        let result =
            sink.complete_with_post_readback_hook(&ID, super::sync_inbox_directory, || {
                fs::rename(&root, &moved).unwrap();
                fs::create_dir(&root).unwrap();
            });
        assert_eq!(result, Err(TeacherFileInboxError::Io));
        assert!(!sink.completed_path(&ID).exists());
        sink.abort(&ID);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(moved).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn root_permission_revocation_during_publish_must_not_leave_unacknowledged_bin() {
        use std::os::unix::fs::PermissionsExt;

        // Publication has already created the hard link when the directory
        // sync hook runs. Revoking the private-root invariant must not leave
        // an unacknowledged .bin even when the root inode is unchanged.
        let root = temp_root("root-mode-revoked-on-sync");
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();

        let outcome = sink.complete_with_directory_sync(&ID, |_root| {
            fs::rename(&root, &moved)?;
            fs::create_dir(&root)?;
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        assert_eq!(
            sink.begin_with_post_create(&ID, 4, || {
                fs::rename(&root, &moved).unwrap();
                fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
    fn inbox_rejects_replaced_root_before_creating_partial_file() {
        // A canonical absolute path can still be replaced with a different
        // directory after admission. No bytes may enter the replacement root.
        let root = temp_root("root-replaced");
        let moved = temp_root("root-moved");
        fs::create_dir(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();

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
        fs::create_dir(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"good").unwrap();
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
        let mut sink = TeacherFileInbox::new(&root).unwrap();
        sink.begin(&ID, "lesson.pdf", 8).unwrap();
        sink.append(&ID, 0, b"good").unwrap();
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();

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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
        fs::create_dir(&root).unwrap();
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
    fn inbox_pins_resolved_root_when_an_ancestor_symlink_changes() {
        // An absolute path is not enough: an attacker who can retarget an
        // ancestor symlink between construction and begin can redirect bytes.
        let original_parent = temp_root("original-parent");
        let decoy_parent = temp_root("decoy-parent");
        let alias = temp_root("parent-alias");
        let original = original_parent.join("inbox");
        let decoy = decoy_parent.join("inbox");
        fs::create_dir_all(&original).unwrap();
        fs::create_dir_all(&decoy).unwrap();
        std::os::unix::fs::symlink(&original_parent, &alias).unwrap();

        let mut sink = TeacherFileInbox::new(alias.join("inbox")).unwrap();
        fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(&decoy_parent, &alias).unwrap();

        sink.begin(&ID, "lesson.pdf", 4).unwrap();
        sink.append(&ID, 0, b"data").unwrap();
        sink.complete(&ID).unwrap();

        let filename = format!("{}.bin", "71".repeat(16));
        assert_eq!(fs::read(original.join(&filename)).unwrap(), b"data");
        assert!(!decoy.join(filename).exists());
        fs::remove_file(alias).unwrap();
        fs::remove_dir_all(original_parent).unwrap();
        fs::remove_dir_all(decoy_parent).unwrap();
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
