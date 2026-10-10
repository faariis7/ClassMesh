use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use classmesh_control::file_transfer_receiver::FileTransferInboxSink;
use classmesh_protocol::file_transfer::MAX_FILE_TRANSFER_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsInboxStorageError {
    Busy,
    WrongTransfer,
    NonSequentialOffset,
    InvalidSize,
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
