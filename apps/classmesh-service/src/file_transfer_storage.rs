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
    FileTooLarge,
    ReadTooLarge,
    InvalidOffset,
    Io,
}

#[derive(Debug, Clone)]
struct RegisteredOutboxFile {
    path: PathBuf,
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
        let path = self.root.join(format!("{}.bin", source_id_stem(source_id)));
        let metadata = fs::metadata(&path).map_err(|_| WindowsOutboxSourceError::MissingSource)?;
        if !metadata.is_file() {
            return Err(WindowsOutboxSourceError::MissingSource);
        }
        let total_size = metadata.len();
        if total_size == 0 || total_size > MAX_FILE_TRANSFER_BYTES {
            return Err(WindowsOutboxSourceError::FileTooLarge);
        }

        let mut file = File::open(&path).map_err(|_| WindowsOutboxSourceError::Io)?;
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
                path,
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
            .get(&source_id)
            .ok_or(WindowsOutboxSourceError::MissingSource)?;
        if offset >= registered.metadata.total_size {
            return Err(WindowsOutboxSourceError::InvalidOffset);
        }

        let remaining = registered.metadata.total_size - offset;
        let length = max_bytes
            .min(usize::try_from(remaining).map_err(|_| WindowsOutboxSourceError::InvalidOffset)?);
        let mut file = File::open(&registered.path).map_err(|_| WindowsOutboxSourceError::Io)?;
        let current_size = file
            .metadata()
            .map_err(|_| WindowsOutboxSourceError::Io)?
            .len();
        if current_size != registered.metadata.total_size {
            return Err(WindowsOutboxSourceError::Io);
        }
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| WindowsOutboxSourceError::Io)?;
        let mut output = vec![0_u8; length];
        file.read_exact(&mut output)
            .map_err(|_| WindowsOutboxSourceError::Io)?;
        Ok(output)
    }

    fn close(&mut self, source_id: FileSourceId) {
        if let Some(registered) = self.registered.remove(&source_id) {
            let _ = fs::remove_file(registered.path);
        }
    }
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
        std::env::temp_dir().join(format!(
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
        assert!(!staged.exists());
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
        assert!(!staged.exists());
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
        fs::write(&staged, b"changed-size").expect("mutate");
        assert_eq!(source.read_at(id, 0, 4), Err(WindowsOutboxSourceError::Io));
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
