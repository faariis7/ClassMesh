use std::collections::BTreeSet;

use crate::control_wire::{
    FileDestinationPolicy, FileTransferCancel, FileTransferChunk, FileTransferFinish,
    FileTransferOffer, FileTransferState, FileTransferStatus,
};
use crate::{Capability, ProtocolVersion};

pub const FILE_TRANSFER_MIN_VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 7 };
pub const TRANSFER_ID_BYTES: usize = 16;
pub const SHA256_BYTES: usize = 32;
pub const MAX_FILE_NAME_BYTES: usize = 255;
pub const MAX_FILE_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_FILE_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_TRANSFER_DIAGNOSTIC_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTransferError {
    InvalidTransferId,
    InvalidFilename,
    FileTooLarge,
    InvalidHash,
    InvalidDestination,
    EmptyChunk,
    ChunkTooLarge,
    InvalidOffset,
    InvalidState,
    DiagnosticTooLarge,
    InvalidDiagnostic,
}

#[must_use]
pub fn file_transfer_available(
    version: ProtocolVersion,
    capabilities: &BTreeSet<Capability>,
) -> bool {
    version.major == FILE_TRANSFER_MIN_VERSION.major
        && version.minor >= FILE_TRANSFER_MIN_VERSION.minor
        && capabilities.contains(&Capability::FileTransfer)
}

pub fn validate_transfer_id(id: &[u8]) -> Result<(), FileTransferError> {
    if id.len() != TRANSFER_ID_BYTES || id.iter().all(|byte| *byte == 0) {
        return Err(FileTransferError::InvalidTransferId);
    }
    Ok(())
}

pub fn validate_filename(filename: &str) -> Result<(), FileTransferError> {
    if filename.is_empty()
        || filename.len() > MAX_FILE_NAME_BYTES
        || filename == "."
        || filename == ".."
        || filename.trim() != filename
        || filename.ends_with('.')
        || filename.chars().any(|ch| {
            ch.is_control() || matches!(ch, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*')
        })
    {
        return Err(FileTransferError::InvalidFilename);
    }

    // Windows reserved device names stay invalid even with a file extension.
    let stem = filename.split('.').next().unwrap_or_default();
    let upper = stem.to_ascii_uppercase();
    let reserved = matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (upper.len() == 4
            && (upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.as_bytes()[3].is_ascii_digit()
            && upper.as_bytes()[3] != b'0');
    if reserved {
        return Err(FileTransferError::InvalidFilename);
    }
    Ok(())
}

pub fn validate_offer(offer: &FileTransferOffer) -> Result<(), FileTransferError> {
    validate_transfer_id(&offer.transfer_id)?;
    validate_filename(&offer.filename)?;
    if offer.total_size == 0 || offer.total_size > MAX_FILE_TRANSFER_BYTES {
        return Err(FileTransferError::FileTooLarge);
    }
    if offer.sha256.len() != SHA256_BYTES {
        return Err(FileTransferError::InvalidHash);
    }
    if FileDestinationPolicy::try_from(offer.destination) != Ok(FileDestinationPolicy::AppInbox) {
        return Err(FileTransferError::InvalidDestination);
    }
    Ok(())
}

pub fn validate_chunk(chunk: &FileTransferChunk) -> Result<(), FileTransferError> {
    validate_transfer_id(&chunk.transfer_id)?;
    if chunk.content.is_empty() {
        return Err(FileTransferError::EmptyChunk);
    }
    if chunk.content.len() > MAX_FILE_CHUNK_BYTES {
        return Err(FileTransferError::ChunkTooLarge);
    }
    let end = chunk
        .offset
        .checked_add(chunk.content.len() as u64)
        .ok_or(FileTransferError::InvalidOffset)?;
    if end > MAX_FILE_TRANSFER_BYTES {
        return Err(FileTransferError::InvalidOffset);
    }
    Ok(())
}

pub fn validate_finish(finish: &FileTransferFinish) -> Result<(), FileTransferError> {
    validate_transfer_id(&finish.transfer_id)
}

pub fn validate_cancel(cancel: &FileTransferCancel) -> Result<(), FileTransferError> {
    validate_transfer_id(&cancel.transfer_id)
}

pub fn validate_status(status: &FileTransferStatus) -> Result<(), FileTransferError> {
    validate_transfer_id(&status.transfer_id)?;
    if status.next_offset > MAX_FILE_TRANSFER_BYTES {
        return Err(FileTransferError::InvalidOffset);
    }
    let state =
        FileTransferState::try_from(status.state).map_err(|_| FileTransferError::InvalidState)?;
    if state == FileTransferState::Unspecified {
        return Err(FileTransferError::InvalidState);
    }
    if status.diagnostic.len() > MAX_TRANSFER_DIAGNOSTIC_BYTES {
        return Err(FileTransferError::DiagnosticTooLarge);
    }
    if status.diagnostic.chars().any(char::is_control) {
        return Err(FileTransferError::InvalidDiagnostic);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer_id() -> Vec<u8> {
        vec![7_u8; TRANSFER_ID_BYTES]
    }

    fn offer() -> FileTransferOffer {
        FileTransferOffer {
            transfer_id: transfer_id(),
            filename: "report-أكتوبر.pdf".to_owned(),
            total_size: 129_000,
            sha256: vec![3; SHA256_BYTES],
            destination: FileDestinationPolicy::AppInbox as i32,
        }
    }

    #[test]
    fn availability_requires_additive_v07_and_explicit_capability() {
        let caps = BTreeSet::from([Capability::FileTransfer]);
        assert!(!file_transfer_available(
            ProtocolVersion { major: 0, minor: 6 },
            &caps
        ));
        assert!(!file_transfer_available(
            ProtocolVersion { major: 1, minor: 7 },
            &caps
        ));
        assert!(!file_transfer_available(
            FILE_TRANSFER_MIN_VERSION,
            &BTreeSet::new()
        ));
        assert!(file_transfer_available(FILE_TRANSFER_MIN_VERSION, &caps));
        assert!(file_transfer_available(
            ProtocolVersion { major: 0, minor: 8 },
            &caps
        ));
    }

    #[test]
    fn offer_is_bounded_and_inbox_only() {
        let valid = offer();
        assert_eq!(validate_offer(&valid), Ok(()));
        let mut bad = valid.clone();
        bad.transfer_id = vec![0; TRANSFER_ID_BYTES];
        assert_eq!(
            validate_offer(&bad),
            Err(FileTransferError::InvalidTransferId)
        );
        bad = valid.clone();
        bad.sha256.pop();
        assert_eq!(validate_offer(&bad), Err(FileTransferError::InvalidHash));
        bad = valid.clone();
        bad.destination = FileDestinationPolicy::Unspecified as i32;
        assert_eq!(
            validate_offer(&bad),
            Err(FileTransferError::InvalidDestination)
        );
        bad.destination = i32::MAX;
        assert_eq!(
            validate_offer(&bad),
            Err(FileTransferError::InvalidDestination)
        );
        bad = valid.clone();
        bad.total_size = 0;
        assert_eq!(validate_offer(&bad), Err(FileTransferError::FileTooLarge));
        bad.total_size = MAX_FILE_TRANSFER_BYTES + 1;
        assert_eq!(validate_offer(&bad), Err(FileTransferError::FileTooLarge));
    }

    #[test]
    fn filename_rejects_traversal_paths_device_names_and_controls() {
        for filename in [
            "",
            ".",
            "..",
            "../a.txt",
            "a/b.txt",
            "C:\\temp\\a.txt",
            "a:b.txt",
            "hello\0.txt",
            "CON.txt",
            "nul",
            "LPT9.log",
            "file.",
            " file.txt",
            "file.txt ",
            "a?b",
            "a|b",
        ] {
            assert_eq!(
                validate_filename(filename),
                Err(FileTransferError::InvalidFilename),
                "{filename:?}"
            );
        }
        assert_eq!(
            validate_filename(&"é".repeat(128)),
            Err(FileTransferError::InvalidFilename)
        );
        assert_eq!(validate_filename("تقرير.pdf"), Ok(()));
        assert_eq!(validate_filename("report_2026-10.pdf"), Ok(()));
    }

    #[test]
    fn chunks_require_non_empty_bounded_content_and_safe_offsets() {
        let chunk = FileTransferChunk {
            transfer_id: transfer_id(),
            offset: 0,
            content: vec![1; MAX_FILE_CHUNK_BYTES],
        };
        assert_eq!(validate_chunk(&chunk), Ok(()));
        let mut bad = chunk.clone();
        bad.content.clear();
        assert_eq!(validate_chunk(&bad), Err(FileTransferError::EmptyChunk));
        bad.content = vec![1; MAX_FILE_CHUNK_BYTES + 1];
        assert_eq!(validate_chunk(&bad), Err(FileTransferError::ChunkTooLarge));
        bad = chunk.clone();
        bad.offset = u64::MAX;
        assert_eq!(validate_chunk(&bad), Err(FileTransferError::InvalidOffset));
        bad.offset = MAX_FILE_TRANSFER_BYTES;
        assert_eq!(validate_chunk(&bad), Err(FileTransferError::InvalidOffset));
        bad = chunk;
        bad.transfer_id = vec![3; 15];
        assert_eq!(
            validate_chunk(&bad),
            Err(FileTransferError::InvalidTransferId)
        );
    }

    #[test]
    fn finish_cancel_and_status_are_exact_bounded_control_messages() {
        let id = transfer_id();
        assert_eq!(
            validate_finish(&FileTransferFinish {
                transfer_id: id.clone()
            }),
            Ok(())
        );
        assert_eq!(
            validate_cancel(&FileTransferCancel {
                transfer_id: id.clone()
            }),
            Ok(())
        );
        let mut status = FileTransferStatus {
            transfer_id: id,
            state: FileTransferState::Progress as i32,
            next_offset: 65_536,
            diagnostic: String::new(),
        };
        assert_eq!(validate_status(&status), Ok(()));
        status.state = FileTransferState::Unspecified as i32;
        assert_eq!(
            validate_status(&status),
            Err(FileTransferError::InvalidState)
        );
        status.state = FileTransferState::Accepted as i32;
        status.next_offset = MAX_FILE_TRANSFER_BYTES + 1;
        assert_eq!(
            validate_status(&status),
            Err(FileTransferError::InvalidOffset)
        );
        status.next_offset = 0;
        status.diagnostic = "x".repeat(MAX_TRANSFER_DIAGNOSTIC_BYTES + 1);
        assert_eq!(
            validate_status(&status),
            Err(FileTransferError::DiagnosticTooLarge)
        );
        status.diagnostic = "bad\nline".to_owned();
        assert_eq!(
            validate_status(&status),
            Err(FileTransferError::InvalidDiagnostic)
        );
    }
}
