use classmesh_protocol::control_wire::{
    FileDestinationPolicy, FileTransferCancel, FileTransferChunk, FileTransferFinish,
    FileTransferOffer,
};
use classmesh_protocol::file_transfer::{
    FileTransferError, MAX_FILE_CHUNK_BYTES, validate_cancel, validate_chunk, validate_finish,
    validate_offer, validate_transfer_id,
};

use crate::file_transfer_receiver::FileTransferPeer;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileSourceId([u8; 16]);

impl FileSourceId {
    pub fn new(value: [u8; 16]) -> Result<Self, SourceError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(SourceError::InvalidSourceId);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTransferSourceMetadata {
    pub filename: String,
    pub total_size: u64,
    pub sha256: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileTransferSourceFrame {
    Chunk(FileTransferChunk),
    Finish(FileTransferFinish),
}

pub trait FileTransferOutboxSource {
    type Error;

    fn metadata(
        &mut self,
        source_id: FileSourceId,
    ) -> Result<FileTransferSourceMetadata, Self::Error>;

    /// Reads at most `max_bytes` from an app-owned source. Implementations must
    /// not expose or accept a caller-controlled filesystem path.
    fn read_at(
        &mut self,
        source_id: FileSourceId,
        offset: u64,
        max_bytes: usize,
    ) -> Result<Vec<u8>, Self::Error>;

    fn close(&mut self, source_id: FileSourceId);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    InvalidBinding,
    InvalidSourceId,
    InvalidPayload(FileTransferError),
    Busy,
    NoActiveSource,
    WrongTransferOrSession,
    InvalidOffset,
    SourceFailure,
    EmptyRead,
    ReadTooLarge,
    ReadPastDeclaredSize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveSource {
    peer: FileTransferPeer,
    transfer_id: [u8; 16],
    source_id: FileSourceId,
    metadata: FileTransferSourceMetadata,
}

#[derive(Debug)]
pub struct FileTransferSourceSession<S: FileTransferOutboxSource> {
    source: S,
    active: Option<ActiveSource>,
}

impl<S: FileTransferOutboxSource> FileTransferSourceSession<S> {
    #[must_use]
    pub const fn new(source: S) -> Self {
        Self {
            source,
            active: None,
        }
    }

    #[must_use]
    pub const fn source(&self) -> &S {
        &self.source
    }

    pub const fn source_mut(&mut self) -> &mut S {
        &mut self.source
    }

    pub fn offer(
        &mut self,
        peer: FileTransferPeer,
        transfer_id: &[u8],
        source_id: FileSourceId,
    ) -> Result<FileTransferOffer, SourceError> {
        validate_peer(peer)?;
        validate_transfer_id(transfer_id).map_err(SourceError::InvalidPayload)?;
        let id = validated_transfer_id(transfer_id);

        if let Some(active) = &self.active {
            if active.peer != peer || active.transfer_id != id || active.source_id != source_id {
                return Err(SourceError::Busy);
            }
            return Ok(offer_from_active(active));
        }

        let metadata = match self.source.metadata(source_id) {
            Ok(metadata) => metadata,
            Err(_) => {
                self.source.close(source_id);
                return Err(SourceError::SourceFailure);
            }
        };
        let candidate = FileTransferOffer {
            transfer_id: id.to_vec(),
            filename: metadata.filename.clone(),
            total_size: metadata.total_size,
            sha256: metadata.sha256.to_vec(),
            destination: FileDestinationPolicy::AppInbox as i32,
        };
        if let Err(error) = validate_offer(&candidate) {
            self.source.close(source_id);
            return Err(SourceError::InvalidPayload(error));
        }

        self.active = Some(ActiveSource {
            peer,
            transfer_id: id,
            source_id,
            metadata,
        });
        Ok(candidate)
    }

    pub fn chunk(
        &mut self,
        peer: FileTransferPeer,
        transfer_id: &[u8],
        offset: u64,
    ) -> Result<FileTransferChunk, SourceError> {
        let active = self.bound_active(peer, transfer_id)?.clone();
        if offset >= active.metadata.total_size {
            return Err(SourceError::InvalidOffset);
        }
        let remaining = active.metadata.total_size - offset;
        let max_bytes = usize::try_from(remaining.min(MAX_FILE_CHUNK_BYTES as u64))
            .map_err(|_| SourceError::InvalidOffset)?;
        let content = self
            .source
            .read_at(active.source_id, offset, max_bytes)
            .map_err(|_| SourceError::SourceFailure)?;
        if content.is_empty() {
            return Err(SourceError::EmptyRead);
        }
        if content.len() > max_bytes || content.len() > MAX_FILE_CHUNK_BYTES {
            return Err(SourceError::ReadTooLarge);
        }
        let end = offset
            .checked_add(content.len() as u64)
            .ok_or(SourceError::ReadPastDeclaredSize)?;
        if end > active.metadata.total_size {
            return Err(SourceError::ReadPastDeclaredSize);
        }

        let chunk = FileTransferChunk {
            transfer_id: active.transfer_id.to_vec(),
            offset,
            content,
        };
        validate_chunk(&chunk).map_err(SourceError::InvalidPayload)?;
        Ok(chunk)
    }

    pub fn next(
        &mut self,
        peer: FileTransferPeer,
        transfer_id: &[u8],
        next_offset: u64,
    ) -> Result<FileTransferSourceFrame, SourceError> {
        let total_size = self.bound_active(peer, transfer_id)?.metadata.total_size;
        if next_offset > total_size {
            return Err(SourceError::InvalidOffset);
        }
        if next_offset == total_size {
            return self
                .finish(peer, transfer_id)
                .map(FileTransferSourceFrame::Finish);
        }
        self.chunk(peer, transfer_id, next_offset)
            .map(FileTransferSourceFrame::Chunk)
    }

    pub fn finish(
        &self,
        peer: FileTransferPeer,
        transfer_id: &[u8],
    ) -> Result<FileTransferFinish, SourceError> {
        let active = self.bound_active(peer, transfer_id)?;
        let finish = FileTransferFinish {
            transfer_id: active.transfer_id.to_vec(),
        };
        validate_finish(&finish).map_err(SourceError::InvalidPayload)?;
        Ok(finish)
    }

    pub fn complete(
        &mut self,
        peer: FileTransferPeer,
        transfer_id: &[u8],
    ) -> Result<(), SourceError> {
        let active = self.bound_active(peer, transfer_id)?.clone();
        self.source.close(active.source_id);
        self.active = None;
        Ok(())
    }

    pub fn cancel(
        &mut self,
        peer: FileTransferPeer,
        transfer_id: &[u8],
    ) -> Result<FileTransferCancel, SourceError> {
        let active = self.bound_active(peer, transfer_id)?.clone();
        let cancel = FileTransferCancel {
            transfer_id: active.transfer_id.to_vec(),
        };
        validate_cancel(&cancel).map_err(SourceError::InvalidPayload)?;
        self.source.close(active.source_id);
        self.active = None;
        Ok(cancel)
    }

    fn bound_active(
        &self,
        peer: FileTransferPeer,
        transfer_id: &[u8],
    ) -> Result<&ActiveSource, SourceError> {
        validate_peer(peer)?;
        validate_transfer_id(transfer_id).map_err(SourceError::InvalidPayload)?;
        let active = self.active.as_ref().ok_or(SourceError::NoActiveSource)?;
        if active.peer != peer || active.transfer_id.as_slice() != transfer_id {
            return Err(SourceError::WrongTransferOrSession);
        }
        Ok(active)
    }
}

impl<S: FileTransferOutboxSource> Drop for FileTransferSourceSession<S> {
    fn drop(&mut self) {
        if let Some(active) = self.active.take() {
            self.source.close(active.source_id);
        }
    }
}

fn validate_peer(peer: FileTransferPeer) -> Result<(), SourceError> {
    if peer.control_session_id == 0 {
        return Err(SourceError::InvalidBinding);
    }
    Ok(())
}

fn validated_transfer_id(value: &[u8]) -> [u8; 16] {
    let mut id = [0; 16];
    id.copy_from_slice(value);
    id
}

fn offer_from_active(active: &ActiveSource) -> FileTransferOffer {
    FileTransferOffer {
        transfer_id: active.transfer_id.to_vec(),
        filename: active.metadata.filename.clone(),
        total_size: active.metadata.total_size,
        sha256: active.metadata.sha256.to_vec(),
        destination: FileDestinationPolicy::AppInbox as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use classmesh_security::PrincipalId;
    use sha2::{Digest, Sha256};

    #[derive(Debug)]
    struct RecordingSource {
        bytes: Vec<u8>,
        reads: Vec<(u64, usize)>,
        closes: Arc<AtomicUsize>,
        metadata_calls: usize,
        fail_read: bool,
        oversize_read: bool,
    }

    impl RecordingSource {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                bytes,
                reads: Vec::new(),
                closes: Arc::new(AtomicUsize::new(0)),
                metadata_calls: 0,
                fail_read: false,
                oversize_read: false,
            }
        }
    }

    impl FileTransferOutboxSource for RecordingSource {
        type Error = ();

        fn metadata(
            &mut self,
            _source_id: FileSourceId,
        ) -> Result<FileTransferSourceMetadata, Self::Error> {
            self.metadata_calls += 1;
            Ok(FileTransferSourceMetadata {
                filename: "lesson.pdf".to_owned(),
                total_size: self.bytes.len() as u64,
                sha256: Sha256::digest(&self.bytes).into(),
            })
        }

        fn read_at(
            &mut self,
            _source_id: FileSourceId,
            offset: u64,
            max_bytes: usize,
        ) -> Result<Vec<u8>, Self::Error> {
            self.reads.push((offset, max_bytes));
            if self.fail_read {
                return Err(());
            }
            let start = offset as usize;
            let mut end = start.saturating_add(max_bytes).min(self.bytes.len());
            if self.oversize_read {
                end = start
                    .saturating_add(max_bytes)
                    .saturating_add(1)
                    .min(self.bytes.len());
            }
            Ok(self.bytes[start..end].to_vec())
        }

        fn close(&mut self, _source_id: FileSourceId) {
            self.closes.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn peer() -> FileTransferPeer {
        FileTransferPeer {
            principal: PrincipalId([7; 32]),
            control_session_id: 31,
        }
    }

    fn source_id() -> FileSourceId {
        FileSourceId::new([3; 16]).unwrap()
    }

    fn transfer_id() -> [u8; 16] {
        [9; 16]
    }

    #[test]
    fn source_offer_is_typed_app_owned_and_path_free() {
        let data = b"abcdef".to_vec();
        let expected_hash: [u8; 32] = Sha256::digest(&data).into();
        let mut session = FileTransferSourceSession::new(RecordingSource::new(data));
        let offer = session.offer(peer(), &transfer_id(), source_id()).unwrap();

        assert_eq!(offer.transfer_id, transfer_id());
        assert_eq!(offer.filename, "lesson.pdf");
        assert_eq!(offer.total_size, 6);
        assert_eq!(offer.sha256, expected_hash);
        assert_eq!(offer.destination, FileDestinationPolicy::AppInbox as i32);
        assert_eq!(validate_offer(&offer), Ok(()));

        // Exact replay is idempotent and does not reopen or re-resolve the source.
        assert_eq!(
            session.offer(peer(), &transfer_id(), source_id()).unwrap(),
            offer
        );
        assert_eq!(session.source().metadata_calls, 1);
    }

    #[test]
    fn source_reads_are_bounded_to_existing_chunk_limit_and_support_offsets() {
        let data = vec![5; MAX_FILE_CHUNK_BYTES + 7];
        let mut session = FileTransferSourceSession::new(RecordingSource::new(data));
        session.offer(peer(), &transfer_id(), source_id()).unwrap();

        let first = session.chunk(peer(), &transfer_id(), 0).unwrap();
        assert_eq!(first.content.len(), MAX_FILE_CHUNK_BYTES);
        assert_eq!(first.offset, 0);

        let resumed = session
            .chunk(peer(), &transfer_id(), MAX_FILE_CHUNK_BYTES as u64)
            .unwrap();
        assert_eq!(resumed.content.len(), 7);
        assert_eq!(resumed.offset, MAX_FILE_CHUNK_BYTES as u64);
        assert_eq!(
            session.source().reads,
            vec![(0, MAX_FILE_CHUNK_BYTES), (MAX_FILE_CHUNK_BYTES as u64, 7),]
        );
    }

    #[test]
    fn source_next_selects_chunk_then_finish_from_receiver_offset() {
        let data = b"abcdef".to_vec();
        let mut session = FileTransferSourceSession::new(RecordingSource::new(data));
        session.offer(peer(), &transfer_id(), source_id()).unwrap();

        let first = session.next(peer(), &transfer_id(), 0).unwrap();
        assert!(matches!(
            first,
            FileTransferSourceFrame::Chunk(FileTransferChunk { offset: 0, .. })
        ));

        let finish = session.next(peer(), &transfer_id(), 6).unwrap();
        assert!(matches!(finish, FileTransferSourceFrame::Finish(_)));

        assert_eq!(
            session.next(peer(), &transfer_id(), 7),
            Err(SourceError::InvalidOffset)
        );
    }

    #[test]
    fn wrong_peer_or_transfer_rejects_before_source_read() {
        let mut session = FileTransferSourceSession::new(RecordingSource::new(b"abcdef".to_vec()));
        session.offer(peer(), &transfer_id(), source_id()).unwrap();

        let mut other = peer();
        other.control_session_id += 1;
        assert_eq!(
            session.chunk(other, &transfer_id(), 0),
            Err(SourceError::WrongTransferOrSession)
        );
        assert_eq!(
            session.chunk(peer(), &[8; 16], 0),
            Err(SourceError::WrongTransferOrSession)
        );
        assert!(session.source().reads.is_empty());
    }

    #[test]
    fn cancel_complete_and_drop_close_the_app_owned_source() {
        let closes = Arc::new(AtomicUsize::new(0));
        let mut source = RecordingSource::new(b"abc".to_vec());
        source.closes = Arc::clone(&closes);
        let mut session = FileTransferSourceSession::new(source);

        session.offer(peer(), &transfer_id(), source_id()).unwrap();
        let cancel = session.cancel(peer(), &transfer_id()).unwrap();
        assert_eq!(validate_cancel(&cancel), Ok(()));
        assert_eq!(closes.load(Ordering::Relaxed), 1);

        session.offer(peer(), &transfer_id(), source_id()).unwrap();
        session.complete(peer(), &transfer_id()).unwrap();
        assert_eq!(closes.load(Ordering::Relaxed), 2);

        session.offer(peer(), &transfer_id(), source_id()).unwrap();
        drop(session);
        assert_eq!(closes.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn source_failures_and_oversized_reads_fail_closed() {
        let mut failing = RecordingSource::new(b"abc".to_vec());
        failing.fail_read = true;
        let mut session = FileTransferSourceSession::new(failing);
        session.offer(peer(), &transfer_id(), source_id()).unwrap();
        assert_eq!(
            session.chunk(peer(), &transfer_id(), 0),
            Err(SourceError::SourceFailure)
        );

        let mut bytes = vec![1; MAX_FILE_CHUNK_BYTES + 1];
        bytes[MAX_FILE_CHUNK_BYTES] = 2;
        let mut oversized = RecordingSource::new(bytes);
        oversized.oversize_read = true;
        let mut session = FileTransferSourceSession::new(oversized);
        session.offer(peer(), &transfer_id(), source_id()).unwrap();
        assert_eq!(
            session.chunk(peer(), &transfer_id(), 0),
            Err(SourceError::ReadTooLarge)
        );
    }

    #[test]
    fn invalid_ids_bindings_and_metadata_are_rejected_before_transfer() {
        assert_eq!(
            FileSourceId::new([0; 16]),
            Err(SourceError::InvalidSourceId)
        );

        let mut session = FileTransferSourceSession::new(RecordingSource::new(b"abc".to_vec()));
        let mut invalid_peer = peer();
        invalid_peer.control_session_id = 0;
        assert_eq!(
            session.offer(invalid_peer, &transfer_id(), source_id()),
            Err(SourceError::InvalidBinding)
        );
        assert!(matches!(
            session.offer(peer(), &[0; 16], source_id()),
            Err(SourceError::InvalidPayload(
                FileTransferError::InvalidTransferId
            ))
        ));

        let closes = Arc::new(AtomicUsize::new(0));
        let mut source = RecordingSource::new(Vec::new());
        source.closes = Arc::clone(&closes);
        let mut empty = FileTransferSourceSession::new(source);
        assert!(matches!(
            empty.offer(peer(), &transfer_id(), source_id()),
            Err(SourceError::InvalidPayload(FileTransferError::FileTooLarge))
        ));
        assert_eq!(closes.load(Ordering::Relaxed), 1);
    }
}
