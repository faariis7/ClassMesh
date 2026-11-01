//! Teacher AppInbox storage backed by an explicitly prepared local directory.
//!
//! The caller must supply a pre-provisioned, appropriately protected root.
//! OS file-ID checks reject observed root/partial-file replacement, but
//! they do not establish trusted Windows ACL/ancestor-handle anti-reparse
//! guarantees or close same-user mutation races between checks and publish.
use std::fs::{self, File, OpenOptions};
use std::io::Write;
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
        if !self.root_unchanged() {
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
        if !self.root_unchanged() || !Self::path_matches_open_file(&active.temp_path, &active.file)
        {
            return Err(TeacherFileInboxError::Io);
        }

        // Atomic create-if-absent publishing: unlike rename, hard_link never
        // replaces an existing .bin. Retain the original file handle while
        // linking, then verify the new name still identifies that same file.
        fs::hard_link(&active.temp_path, &active.final_path)
            .map_err(|_| TeacherFileInboxError::ExistingTransfer)?;
        if !self.root_unchanged() || !Self::path_matches_open_file(&active.final_path, &active.file)
        {
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
