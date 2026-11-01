use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use classmesh_control::file_transfer_receiver::FileTransferInboxSink;
use classmesh_control::file_transfer_source::{
    FileSourceId, FileTransferOutboxSource, FileTransferSourceMetadata,
};
use classmesh_protocol::file_transfer::{
    MAX_FILE_CHUNK_BYTES, MAX_FILE_TRANSFER_BYTES, validate_filename,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsOutboxSourceError {
    InvalidDisplayName,
    MissingSource,
    AlreadyRegistered,
    FileTooLarge,
    ReadTooLarge,
    InvalidOffset,
    Io,
}

#[derive(Debug)]
struct RegisteredOutboxFile {
    file: File,
    metadata: FileTransferSourceMetadata,
}

#[derive(Debug)]
pub struct WindowsFileTransferOutboxSource {
    root: PathBuf,
    registered: HashMap<FileSourceId, RegisteredOutboxFile>,
}

impl WindowsFileTransferOutboxSource {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            registered: HashMap::new(),
        }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Registers an already staged ClassMesh-owned source.
    ///
    /// The staged path is derived exclusively from the opaque source ID. The
    /// display filename is validated metadata and is never joined into a path.
    pub fn register_staged_file(
        &mut self,
        source_id: FileSourceId,
        display_filename: &str,
    ) -> Result<(), WindowsOutboxSourceError> {
        validate_filename(display_filename)
            .map_err(|_| WindowsOutboxSourceError::InvalidDisplayName)?;
        // Never replace an active pinned HANDLE or its hashed metadata. A
        // staging-path swap followed by re-registration must not redirect the
        // already authenticated transfer to a different file object.
        if self.registered.contains_key(&source_id) {
            return Err(WindowsOutboxSourceError::AlreadyRegistered);
        }
        let path = self.root.join(format!("{}.bin", source_id_stem(source_id)));
        // A final-component OPEN_REPARSE_POINT flag does not protect against
        // intermediate directory junctions redirecting this opaque source.
        validate_staged_parent_chain(&path).map_err(|_| WindowsOutboxSourceError::MissingSource)?;
        let mut file =
            open_registered_source(&path).map_err(|_| WindowsOutboxSourceError::MissingSource)?;
        let metadata = file.metadata().map_err(|_| WindowsOutboxSourceError::Io)?;
        if !metadata.is_file() {
            return Err(WindowsOutboxSourceError::MissingSource);
        }
        let total_size = metadata.len();
        if total_size == 0 || total_size > MAX_FILE_TRANSFER_BYTES {
            return Err(WindowsOutboxSourceError::FileTooLarge);
        }

        let mut digest = Sha256::new();
        let mut buffer = vec![0_u8; MAX_FILE_CHUNK_BYTES];
        let mut hashed = 0_u64;
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|_| WindowsOutboxSourceError::Io)?;
            if count == 0 {
                break;
            }
            hashed = hashed
                .checked_add(count as u64)
                .ok_or(WindowsOutboxSourceError::FileTooLarge)?;
            if hashed > MAX_FILE_TRANSFER_BYTES {
                return Err(WindowsOutboxSourceError::FileTooLarge);
            }
            digest.update(&buffer[..count]);
        }
        if hashed != total_size {
            return Err(WindowsOutboxSourceError::Io);
        }

        self.registered.insert(
            source_id,
            RegisteredOutboxFile {
                file,
                metadata: FileTransferSourceMetadata {
                    filename: display_filename.to_owned(),
                    total_size,
                    sha256: digest.finalize().into(),
                },
            },
        );
        Ok(())
    }

    fn ensure_staged_source_registered(
        &mut self,
        source_id: FileSourceId,
    ) -> Result<(), WindowsOutboxSourceError> {
        if self.registered.contains_key(&source_id) {
            return Ok(());
        }
        let display_filename = format!("{}.bin", source_id_stem(source_id));
        self.register_staged_file(source_id, &display_filename)
    }

    #[cfg(test)]
    fn staged_path(&self, source_id: FileSourceId) -> PathBuf {
        self.root.join(format!("{}.bin", source_id_stem(source_id)))
    }
}

impl FileTransferOutboxSource for WindowsFileTransferOutboxSource {
    type Error = WindowsOutboxSourceError;

    fn metadata(
        &mut self,
        source_id: FileSourceId,
    ) -> Result<FileTransferSourceMetadata, Self::Error> {
        self.ensure_staged_source_registered(source_id)?;
        self.registered
            .get(&source_id)
            .map(|registered| registered.metadata.clone())
            .ok_or(WindowsOutboxSourceError::MissingSource)
    }

    fn read_at(
        &mut self,
        source_id: FileSourceId,
        offset: u64,
        max_bytes: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        if max_bytes == 0 || max_bytes > MAX_FILE_CHUNK_BYTES {
            return Err(WindowsOutboxSourceError::ReadTooLarge);
        }
        self.ensure_staged_source_registered(source_id)?;
        let registered = self
            .registered
            .get_mut(&source_id)
            .ok_or(WindowsOutboxSourceError::MissingSource)?;
        if offset >= registered.metadata.total_size {
            return Err(WindowsOutboxSourceError::InvalidOffset);
        }

        let remaining = registered.metadata.total_size - offset;
        let length = max_bytes
            .min(usize::try_from(remaining).map_err(|_| WindowsOutboxSourceError::InvalidOffset)?);
        // Always read the original hashed HANDLE: a replaced opaque staging
        // path must never redirect bytes to another file.
        let current_size = registered
            .file
            .metadata()
            .map_err(|_| WindowsOutboxSourceError::Io)?
            .len();
        if current_size != registered.metadata.total_size {
            return Err(WindowsOutboxSourceError::Io);
        }
        registered
            .file
            .seek(SeekFrom::Start(offset))
            .map_err(|_| WindowsOutboxSourceError::Io)?;
        let mut output = vec![0_u8; length];
        registered
            .file
            .read_exact(&mut output)
            .map_err(|_| WindowsOutboxSourceError::Io)?;
        Ok(output)
    }

    fn close(&mut self, source_id: FileSourceId) {
        if let Some(registered) = self.registered.remove(&source_id) {
            // Never unlink an untrusted pathname after releasing the pinned
            // handle: the name may now belong to a different staged file.
            cleanup_registered_source(registered);
        }
    }
}

// Reject existing symlink/junction ancestors before opening the staged file.
// This is defense in depth, NOT a substitute for trusted root ACLs or a
// handle-relative traversal: a concurrently writable ancestor remains a
// rename/reparse race until the directory ownership is independently secured.
fn validate_staged_parent_chain(path: &Path) -> std::io::Result<()> {
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "staged source must use an absolute path",
        ));
    }
    for parent in path.ancestors().skip(1) {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "staged source parent must be a real directory",
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "staged source parent must not be a junction/reparse point",
                ));
            }
        }
    }
    Ok(())
}

// Windows opens the registered file with DELETE access so close can mark the
// exact hashed HANDLE for deletion, even if its original name was replaced.
// A denied DELETE grant fails registration closed rather than falling back to
// an unsafe pathname unlink.
#[cfg(windows)]
fn open_registered_source(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    const GENERIC_READ: u32 = 0x8000_0000;
    const DELETE: u32 = 0x0001_0000;
    // The registered bytes were already SHA-256 hashed. Refuse new writers
    // while this pinned source is active; sharing WRITE permits same-size
    // in-place mutation after the digest was recorded.
    const FILE_SHARE_READ_DELETE: u32 = 0x0000_0005;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let file = OpenOptions::new()
        .read(true)
        .access_mode(GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ_DELETE)
        // Open the link itself, never a reparse target outside the staging root.
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "staged source must not be a reparse point",
        ));
    }
    Ok(file)
}

#[cfg(not(windows))]
fn open_registered_source(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(windows)]
fn cleanup_registered_source(registered: RegisteredOutboxFile) {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    // FILE_INFO_BY_HANDLE_CLASS::FileDispositionInfo (4). The Win32 kernel
    // applies this disposition to the open file object, never to a reused name.
    #[repr(C)]
    struct FileDispositionInfo {
        delete_file: u8, // BOOLEAN
    }
    #[link(name = "Kernel32")]
    unsafe extern "system" {
        #[link_name = "SetFileInformationByHandle"]
        fn set_file_information_by_handle(
            file: *mut c_void,
            information_class: u32,
            information: *const c_void,
            information_size: u32,
        ) -> i32;
    }
    let disposition = FileDispositionInfo { delete_file: 1 };
    // Failure leaves the original staged object behind; it must not trigger
    // a fallback DeleteFile(path) against a possibly substituted pathname.
    // SAFETY: the borrowed HANDLE is live for the synchronous Win32 call;
    // the disposition pointer references a correctly laid-out BOOLEAN value.
    let _ = unsafe {
        set_file_information_by_handle(
            registered.file.as_raw_handle(),
            4,
            (&raw const disposition).cast(),
            std::mem::size_of::<FileDispositionInfo>() as u32,
        )
    };
}

#[cfg(not(windows))]
fn cleanup_registered_source(_registered: RegisteredOutboxFile) {
    // There is no portable atomic unlink-by-open-handle API. On test hosts,
    // deliberately leave the staged file for its trusted owner to reclaim;
    // a metadata-check-then-unlink would still have a pathname swap race.
}

fn source_id_stem(source_id: FileSourceId) -> String {
    let bytes = source_id.as_bytes();
    transfer_id_stem(&bytes)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsInboxStorageError {
    Busy,
    InvalidSize,
    WrongTransfer,
    NonSequentialOffset,
    SizeExceeded,
    Incomplete,
    ExistingTransfer,
    Io,
}

#[derive(Debug)]
struct ActiveInboxFile {
    id: [u8; 16],
    file: File,
    temp_path: PathBuf,
    final_path: PathBuf,
    next_offset: u64,
    declared_size: u64,
}

/// App-owned Windows inbox storage.
///
/// The network-provided display filename is intentionally not used as a
/// filesystem path. Files are addressed only by the already-validated opaque
/// transfer ID beneath a fixed root chosen by the Service.
#[derive(Debug)]
pub struct WindowsFileTransferInboxSink {
    root: PathBuf,
    active: Option<ActiveInboxFile>,
}

impl WindowsFileTransferInboxSink {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            active: None,
        }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[cfg(test)]
    fn active_next_offset(&self) -> Option<u64> {
        self.active.as_ref().map(|active| active.next_offset)
    }
}

impl FileTransferInboxSink for WindowsFileTransferInboxSink {
    type Error = WindowsInboxStorageError;

    fn begin(&mut self, id: &[u8; 16], _filename: &str, size: u64) -> Result<(), Self::Error> {
        if size == 0 || size > MAX_FILE_TRANSFER_BYTES {
            return Err(WindowsInboxStorageError::InvalidSize);
        }
        if self.active.is_some() {
            return Err(WindowsInboxStorageError::Busy);
        }

        fs::create_dir_all(&self.root).map_err(|_| WindowsInboxStorageError::Io)?;
        let stem = transfer_id_stem(id);
        let temp_path = self.root.join(format!("{stem}.part"));
        let final_path = self.root.join(format!("{stem}.bin"));
        if temp_path.exists() || final_path.exists() {
            return Err(WindowsInboxStorageError::ExistingTransfer);
        }

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|_| WindowsInboxStorageError::Io)?;
        self.active = Some(ActiveInboxFile {
            id: *id,
            file,
            temp_path,
            final_path,
            next_offset: 0,
            declared_size: size,
        });
        Ok(())
    }

    fn append(&mut self, id: &[u8; 16], offset: u64, content: &[u8]) -> Result<(), Self::Error> {
        let active = self
            .active
            .as_mut()
            .ok_or(WindowsInboxStorageError::WrongTransfer)?;
        if active.id != *id {
            return Err(WindowsInboxStorageError::WrongTransfer);
        }
        if active.next_offset != offset {
            return Err(WindowsInboxStorageError::NonSequentialOffset);
        }

        let end = offset
            .checked_add(content.len() as u64)
            .ok_or(WindowsInboxStorageError::SizeExceeded)?;
        if end > active.declared_size {
            return Err(WindowsInboxStorageError::SizeExceeded);
        }

        active
            .file
            .write_all(content)
            .map_err(|_| WindowsInboxStorageError::Io)?;
        active.next_offset = end;
        Ok(())
    }

    fn complete(&mut self, id: &[u8; 16]) -> Result<(), Self::Error> {
        {
            let active = self
                .active
                .as_ref()
                .ok_or(WindowsInboxStorageError::WrongTransfer)?;
            if active.id != *id {
                return Err(WindowsInboxStorageError::WrongTransfer);
            }
            if active.next_offset != active.declared_size {
                return Err(WindowsInboxStorageError::Incomplete);
            }
        }

        let active = self
            .active
            .take()
            .ok_or(WindowsInboxStorageError::WrongTransfer)?;
        if active.file.sync_all().is_err() {
            let _ = fs::remove_file(&active.temp_path);
            return Err(WindowsInboxStorageError::Io);
        }
        drop(active.file);

        if fs::rename(&active.temp_path, &active.final_path).is_err() {
            let _ = fs::remove_file(&active.temp_path);
            return Err(WindowsInboxStorageError::Io);
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

impl Drop for WindowsFileTransferInboxSink {
    fn drop(&mut self) {
        if let Some(active) = self.active.take() {
            drop(active.file);
            let _ = fs::remove_file(active.temp_path);
        }
    }
}

fn transfer_id_stem(id: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(32);
    for byte in id {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEST_ID: AtomicU64 = AtomicU64::new(1);

    fn test_root(name: &str) -> PathBuf {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        // macOS /var is commonly a symlink to /private/var; use the
        // physical temp root so the parent-chain check tests our fixture.
        std::env::temp_dir()
            .canonicalize()
            .expect("canonical temp root")
            .join(format!(
                "classmesh-file-inbox-{}-{name}-{id}",
                std::process::id()
            ))
    }

    fn transfer_id() -> [u8; 16] {
        [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ]
    }

    fn source_id() -> FileSourceId {
        FileSourceId::new([0x5a; 16]).expect("nonzero source id")
    }

    #[test]
    fn outbox_registration_uses_opaque_source_path_and_streaming_metadata() {
        let root = test_root("outbox-register");
        fs::create_dir_all(&root).expect("root");
        let mut source = WindowsFileTransferOutboxSource::new(&root);
        let id = source_id();
        let staged = source.staged_path(id);
        fs::write(&staged, b"classmesh-outbox").expect("seed staged source");

        source
            .register_staged_file(id, "lesson.pdf")
            .expect("register staged file");
        let metadata = source.metadata(id).expect("metadata");
        assert_eq!(metadata.filename, "lesson.pdf");
        assert_eq!(metadata.total_size, 16);
        assert_eq!(
            metadata.sha256,
            <[u8; 32]>::from(Sha256::digest(b"classmesh-outbox"))
        );
        assert_eq!(
            source.read_at(id, 0, MAX_FILE_CHUNK_BYTES).expect("read"),
            b"classmesh-outbox"
        );

        source.close(id);
        #[cfg(windows)]
        assert!(!staged.exists());
        #[cfg(not(windows))]
        assert!(
            staged.exists(),
            "portable close fails closed without unlink"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn outbox_reads_the_registered_file_even_if_its_path_is_replaced() {
        let root = test_root("outbox-replaced-path");
        fs::create_dir_all(&root).expect("root");
        let mut source = WindowsFileTransferOutboxSource::new(&root);
        let id = source_id();
        let staged = source.staged_path(id);
        let moved = root.join("original-stage.bin");
        fs::write(&staged, b"trusted-stage").expect("stage");
        source
            .register_staged_file(id, "lesson.pdf")
            .expect("register");

        // An authorized staging process may atomically rotate the path while
        // the Service is streaming. It must never switch to the new file.
        fs::rename(&staged, &moved).expect("rotate registered file");
        fs::write(&staged, b"foreign-stage").expect("replace name");
        assert_eq!(
            source
                .read_at(id, 0, MAX_FILE_CHUNK_BYTES)
                .expect("read original handle"),
            b"trusted-stage"
        );

        source.close(id);
        // Closing a pinned source must never unlink a different file that
        // reused the same staging pathname while the source was active.
        assert_eq!(
            fs::read(&staged).expect("replacement must survive source close"),
            b"foreign-stage"
        );
        let _ = fs::remove_file(moved);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn outbox_rejects_reregistration_after_staging_path_substitution() {
        let root = test_root("outbox-rebind");
        fs::create_dir_all(&root).expect("root");
        let mut source = WindowsFileTransferOutboxSource::new(&root);
        let id = source_id();
        let staged = source.staged_path(id);
        let moved = root.join("original-stage.bin");
        fs::write(&staged, b"trusted-stage").expect("stage");
        source
            .register_staged_file(id, "lesson.pdf")
            .expect("register");

        fs::rename(&staged, &moved).expect("rotate original");
        fs::write(&staged, b"foreign-stage").expect("replace original path");
        assert_eq!(
            source.register_staged_file(id, "lesson.pdf"),
            Err(WindowsOutboxSourceError::AlreadyRegistered),
            "a second registration must not replace the pinned source handle"
        );
        assert_eq!(
            source
                .read_at(id, 0, MAX_FILE_CHUNK_BYTES)
                .expect("pinned read"),
            b"trusted-stage"
        );
        assert_eq!(
            source.metadata(id).expect("pinned metadata").sha256,
            <[u8; 32]>::from(Sha256::digest(b"trusted-stage"))
        );
        source.close(id);
        assert_eq!(
            fs::read(&staged).expect("foreign source survives"),
            b"foreign-stage"
        );
        let _ = fs::remove_file(moved);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(any(windows, unix))]
    #[test]
    fn outbox_rejects_reparse_directory_in_staged_source_parent_chain() {
        let root = test_root("outbox-parent-alias");
        let trusted_parent = root.join("trusted");
        let trusted = trusted_parent.join("state").join("file-outbox");
        let alias = root.join("alias");
        let aliased_root = alias.join("state").join("file-outbox");
        fs::create_dir_all(&trusted).expect("trusted root");
        let id = source_id();
        let trusted_source = WindowsFileTransferOutboxSource::new(&trusted);
        fs::write(trusted_source.staged_path(id), b"trusted-source").expect("seed source");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&trusted_parent, &alias).expect("create parent symlink");
        #[cfg(windows)]
        {
            let status = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&alias)
                .arg(&trusted_parent)
                .status()
                .expect("invoke junction creation");
            assert!(status.success(), "create parent junction");
        }

        let mut source = WindowsFileTransferOutboxSource::new(&aliased_root);
        assert_eq!(
            source.register_staged_file(id, "lesson.pdf"),
            Err(WindowsOutboxSourceError::MissingSource),
            "an ancestor junction/symlink must not redirect a staged source open"
        );
        assert_eq!(
            fs::read(trusted_source.staged_path(id)).expect("trusted source survives"),
            b"trusted-source"
        );
        #[cfg(unix)]
        fs::remove_file(&alias).expect("unlink symlink only");
        #[cfg(windows)]
        fs::remove_dir(&alias).expect("unlink junction only");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn outbox_lazily_registers_only_the_opaque_app_owned_staged_path() {
        let root = test_root("outbox-lazy-register");
        fs::create_dir_all(&root).expect("root");
        let mut source = WindowsFileTransferOutboxSource::new(&root);
        let id = source_id();
        let staged = source.staged_path(id);
        fs::write(&staged, b"locally-staged").expect("seed staged source");

        let metadata = source.metadata(id).expect("lazy metadata");
        assert_eq!(metadata.filename, format!("{}.bin", source_id_stem(id)));
        assert_eq!(metadata.total_size, 14);
        assert_eq!(
            source.read_at(id, 0, MAX_FILE_CHUNK_BYTES).expect("read"),
            b"locally-staged"
        );

        source.close(id);
        #[cfg(windows)]
        assert!(!staged.exists());
        #[cfg(not(windows))]
        assert!(
            staged.exists(),
            "portable close fails closed without unlink"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn outbox_pinned_hash_rejects_in_place_writer_until_close() {
        let root = test_root("outbox-deny-in-place-writer");
        fs::create_dir_all(&root).expect("root");
        let mut source = WindowsFileTransferOutboxSource::new(&root);
        let id = source_id();
        let staged = source.staged_path(id);
        fs::write(&staged, b"trusted-stage").expect("stage");
        source
            .register_staged_file(id, "lesson.pdf")
            .expect("register immutable source");

        // Before restricting FILE_SHARE_WRITE this succeeds on Windows and
        // lets a new writer replace same-size bytes after SHA-256 hashing.
        let writer = OpenOptions::new().write(true).open(&staged);
        assert!(
            writer.is_err(),
            "a new writer must not mutate hashed bytes while pinned"
        );
        assert_eq!(
            source
                .read_at(id, 0, MAX_FILE_CHUNK_BYTES)
                .expect("pinned read"),
            b"trusted-stage"
        );

        source.close(id);
        assert!(!staged.exists(), "close removes the exact pinned object");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn outbox_rejects_non_file_staged_sources() {
        let root = test_root("outbox-non-file");
        fs::create_dir_all(&root).expect("root");
        let mut source = WindowsFileTransferOutboxSource::new(&root);
        let id = source_id();
        let staged = source.staged_path(id);
        fs::create_dir_all(&staged).expect("seed staged directory");

        assert_eq!(
            source.register_staged_file(id, "lesson.pdf"),
            Err(WindowsOutboxSourceError::MissingSource)
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn outbox_rejects_invalid_display_names_oversize_reads_and_mutation() {
        let root = test_root("outbox-reject");
        fs::create_dir_all(&root).expect("root");
        let mut source = WindowsFileTransferOutboxSource::new(&root);
        let id = source_id();
        let staged = source.staged_path(id);
        fs::write(&staged, b"abcd").expect("seed");

        assert_eq!(
            source.register_staged_file(id, "..\\evil.exe"),
            Err(WindowsOutboxSourceError::InvalidDisplayName)
        );
        source
            .register_staged_file(id, "lesson.pdf")
            .expect("register");
        assert_eq!(
            source.read_at(id, 0, MAX_FILE_CHUNK_BYTES + 1),
            Err(WindowsOutboxSourceError::ReadTooLarge)
        );
        // Windows pins hashed bytes with FILE_SHARE_READ | FILE_SHARE_DELETE:
        // a new writer must be denied rather than changing the source size.
        // Portable hosts lack this share-mode contract, so they still verify
        // that an actual size mutation is rejected at the read boundary.
        #[cfg(windows)]
        {
            assert!(
                fs::write(&staged, b"changed-size").is_err(),
                "Windows must deny mutation of the pinned hashed source"
            );
            assert_eq!(source.read_at(id, 0, 4).expect("pinned read"), b"abcd");
        }
        #[cfg(not(windows))]
        {
            fs::write(&staged, b"changed-size").expect("portable mutate");
            assert_eq!(source.read_at(id, 0, 4), Err(WindowsOutboxSourceError::Io));
        }
        source.close(id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn storage_path_is_opaque_id_based_not_sender_filename() {
        let root = test_root("opaque");
        let id = transfer_id();
        let mut sink = WindowsFileTransferInboxSink::new(&root);
        sink.begin(&id, "..\\..\\evil.exe", 3)
            .expect("display filename is never used as a path");
        sink.append(&id, 0, b"abc").expect("append");
        sink.complete(&id).expect("complete");

        let stem = transfer_id_stem(&id);
        assert!(root.join(format!("{stem}.bin")).is_file());
        assert!(!root.join("evil.exe").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn storage_revalidates_declared_size_at_filesystem_boundary() {
        let root = test_root("size-boundary");
        let id = transfer_id();
        let mut sink = WindowsFileTransferInboxSink::new(&root);
        assert_eq!(
            sink.begin(&id, "empty.bin", 0),
            Err(WindowsInboxStorageError::InvalidSize)
        );
        assert_eq!(
            sink.begin(&id, "oversize.bin", MAX_FILE_TRANSFER_BYTES + 1),
            Err(WindowsInboxStorageError::InvalidSize)
        );
        assert!(!root.exists());
    }

    #[test]
    fn append_requires_exact_transfer_and_sequential_bounded_offsets() {
        let root = test_root("offsets");
        let id = transfer_id();
        let mut sink = WindowsFileTransferInboxSink::new(&root);
        sink.begin(&id, "lesson.pdf", 4).expect("begin");

        assert_eq!(
            sink.append(&[9; 16], 0, b"a"),
            Err(WindowsInboxStorageError::WrongTransfer)
        );
        assert_eq!(
            sink.append(&id, 1, b"a"),
            Err(WindowsInboxStorageError::NonSequentialOffset)
        );
        assert_eq!(
            sink.append(&id, 0, b"abcde"),
            Err(WindowsInboxStorageError::SizeExceeded)
        );
        assert_eq!(sink.active_next_offset(), Some(0));

        sink.append(&id, 0, b"ab").expect("first append");
        sink.append(&id, 2, b"cd").expect("second append");
        assert_eq!(sink.active_next_offset(), Some(4));
        sink.abort(&id);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn incomplete_complete_fails_and_abort_removes_partial_file() {
        let root = test_root("abort");
        let id = transfer_id();
        let stem = transfer_id_stem(&id);
        let mut sink = WindowsFileTransferInboxSink::new(&root);
        sink.begin(&id, "lesson.pdf", 4).expect("begin");
        sink.append(&id, 0, b"ab").expect("append");
        assert_eq!(
            sink.complete(&id),
            Err(WindowsInboxStorageError::Incomplete)
        );
        assert!(root.join(format!("{stem}.part")).is_file());
        sink.abort(&id);
        assert!(!root.join(format!("{stem}.part")).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn existing_transfer_is_never_overwritten() {
        let root = test_root("existing");
        fs::create_dir_all(&root).expect("root");
        let id = transfer_id();
        let stem = transfer_id_stem(&id);
        fs::write(root.join(format!("{stem}.bin")), b"existing").expect("seed");

        let mut sink = WindowsFileTransferInboxSink::new(&root);
        assert_eq!(
            sink.begin(&id, "lesson.pdf", 3),
            Err(WindowsInboxStorageError::ExistingTransfer)
        );
        assert_eq!(
            fs::read(root.join(format!("{stem}.bin"))).expect("read"),
            b"existing"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn drop_cleans_partial_file() {
        let root = test_root("drop");
        let id = transfer_id();
        let stem = transfer_id_stem(&id);
        {
            let mut sink = WindowsFileTransferInboxSink::new(&root);
            sink.begin(&id, "lesson.pdf", 3).expect("begin");
            sink.append(&id, 0, b"a").expect("append");
            assert!(root.join(format!("{stem}.part")).is_file());
        }
        assert!(!root.join(format!("{stem}.part")).exists());
        let _ = fs::remove_dir_all(root);
    }
}
