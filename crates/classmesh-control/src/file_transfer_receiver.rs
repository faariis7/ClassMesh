use classmesh_protocol::control_wire::{
    FileTransferCancel, FileTransferChunk, FileTransferFinish, FileTransferOffer, FileTransferState,
    FileTransferStatus,
};
use classmesh_protocol::file_transfer::{
    FileTransferError, validate_cancel, validate_chunk, validate_finish, validate_offer,
};
use classmesh_security::PrincipalId;
use sha2::{Digest, Sha256};

/// Identity must come from the authenticated control session's command guard;
/// callers must never derive it from an untrusted file-transfer payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileTransferPeer {
    pub principal: PrincipalId,
    pub control_session_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveError {
    InvalidBinding,
    InvalidPayload(FileTransferError),
    Busy,
    NoActiveTransfer,
    WrongTransferOrSession,
    NonSequentialChunk,
    PastDeclaredSize,
    Incomplete,
    HashMismatch,
    SinkFailure,
}

/// Narrow, app-owned inbox boundary. No raw destination path or file handle is
/// supplied by a sender. Hosted tests use an in-memory/recording implementation.
pub trait FileTransferInboxSink {
    type Error;

    fn begin(&mut self, id: &[u8; 16], filename: &str, size: u64)
        -> Result<(), Self::Error>;
    fn append(
        &mut self,
        id: &[u8; 16],
        offset: u64,
        content: &[u8],
    ) -> Result<(), Self::Error>;
    fn complete(&mut self, id: &[u8; 16]) -> Result<(), Self::Error>;
    fn abort(&mut self, id: &[u8; 16]);
}

#[derive(Debug)]
struct ActiveTransfer {
    peer: FileTransferPeer,
    offer: FileTransferOffer,
    next_offset: u64,
    sha256: Sha256,
}

/// Exactly one active transfer; never buffers file content. All data is
/// streamed into an injected sink and the digest is updated only on success.
#[derive(Debug)]
pub struct FileTransferReceiver<S: FileTransferInboxSink> {
    sink: S,
    active: Option<ActiveTransfer>,
}

impl<S: FileTransferInboxSink> FileTransferReceiver<S> {
    #[must_use]
    pub const fn new(sink: S) -> Self {
        Self { sink, active: None }
    }

    #[must_use]
    pub const fn sink(&self) -> &S {
        &self.sink
    }

    pub fn offer(
        &mut self,
        peer: FileTransferPeer,
        offer: &FileTransferOffer,
    ) -> Result<FileTransferStatus, ReceiveError> {
        validate_peer(peer)?;
        validate_offer(offer).map_err(ReceiveError::InvalidPayload)?;

        if let Some(active) = &self.active {
            if active.offer.transfer_id != offer.transfer_id || active.peer != peer {
                return Err(ReceiveError::WrongTransferOrSession);
            }
            if active.offer != *offer {
                return Err(ReceiveError::Busy);
            }
            return Ok(status(
                &active.offer.transfer_id,
                FileTransferState::Progress,
                active.next_offset,
            ));
        }

        let id = validated_id(&offer.transfer_id);
        if self.sink.begin(&id, &offer.filename, offer.total_size).is_err() {
            self.sink.abort(&id);
            return Err(ReceiveError::SinkFailure);
        }
        self.active = Some(ActiveTransfer {
            peer,
            offer: offer.clone(),
            next_offset: 0,
            sha256: Sha256::new(),
        });
        Ok(status(&offer.transfer_id, FileTransferState::Accepted, 0))
    }

    pub fn chunk(
        &mut self,
        peer: FileTransferPeer,
        chunk: &FileTransferChunk,
    ) -> Result<FileTransferStatus, ReceiveError> {
        validate_peer(peer)?;
        validate_chunk(chunk).map_err(ReceiveError::InvalidPayload)?;
        let active = self.bound_active(peer, &chunk.transfer_id)?;
        if chunk.offset != active.next_offset {
            return Err(ReceiveError::NonSequentialChunk);
        }
        let end = chunk.offset + chunk.content.len() as u64;
        if end > active.offer.total_size {
            return Err(ReceiveError::PastDeclaredSize);
        }

        let id = validated_id(&chunk.transfer_id);
        if self.sink.append(&id, chunk.offset, &chunk.content).is_err() {
            self.sink.abort(&id);
            self.active = None;
            return Err(ReceiveError::SinkFailure);
        }

        let active = self.active.as_mut().ok_or(ReceiveError::NoActiveTransfer)?;
        active.sha256.update(&chunk.content);
        active.next_offset = end;
        Ok(status(
            &chunk.transfer_id,
            FileTransferState::Progress,
            end,
        ))
    }

    pub fn finish(
        &mut self,
        peer: FileTransferPeer,
        finish: &FileTransferFinish,
    ) -> Result<FileTransferStatus, ReceiveError> {
        validate_peer(peer)?;
        validate_finish(finish).map_err(ReceiveError::InvalidPayload)?;
        let active = self.bound_active(peer, &finish.transfer_id)?;
        if active.next_offset != active.offer.total_size {
            return Err(ReceiveError::Incomplete);
        }
        let actual_hash = active.sha256.clone().finalize();
        let id = validated_id(&finish.transfer_id);
        if actual_hash.as_slice() != active.offer.sha256.as_slice() {
            self.sink.abort(&id);
            self.active = None;
            return Err(ReceiveError::HashMismatch);
        }
        let total = active.next_offset;
        if self.sink.complete(&id).is_err() {
            self.sink.abort(&id);
            self.active = None;
            return Err(ReceiveError::SinkFailure);
        }
        self.active = None;
        Ok(status(
            &finish.transfer_id,
            FileTransferState::Completed,
            total,
        ))
    }

    pub fn cancel(
        &mut self,
        peer: FileTransferPeer,
        cancel: &FileTransferCancel,
    ) -> Result<FileTransferStatus, ReceiveError> {
        validate_peer(peer)?;
        validate_cancel(cancel).map_err(ReceiveError::InvalidPayload)?;
        let active = self.bound_active(peer, &cancel.transfer_id)?;
        let next = active.next_offset;
        let id = validated_id(&cancel.transfer_id);
        self.sink.abort(&id);
        self.active = None;
        Ok(status(
            &cancel.transfer_id,
            FileTransferState::Cancelled,
            next,
        ))
    }

    fn bound_active(
        &self,
        peer: FileTransferPeer,
        transfer_id: &[u8],
    ) -> Result<&ActiveTransfer, ReceiveError> {
        let active = self.active.as_ref().ok_or(ReceiveError::NoActiveTransfer)?;
        if active.peer != peer || active.offer.transfer_id.as_slice() != transfer_id {
            return Err(ReceiveError::WrongTransferOrSession);
        }
        Ok(active)
    }
}

impl<S: FileTransferInboxSink> Drop for FileTransferReceiver<S> {
    fn drop(&mut self) {
        if let Some(active) = self.active.take() {
            let id = validated_id(&active.offer.transfer_id);
            self.sink.abort(&id);
        }
    }
}

fn validate_peer(peer: FileTransferPeer) -> Result<(), ReceiveError> {
    if peer.control_session_id == 0 {
        return Err(ReceiveError::InvalidBinding);
    }
    Ok(())
}

fn validated_id(value: &[u8]) -> [u8; 16] {
    let mut id = [0; 16];
    id.copy_from_slice(value);
    id
}

fn status(id: &[u8], state: FileTransferState, next_offset: u64) -> FileTransferStatus {
    FileTransferStatus {
        transfer_id: id.to_vec(),
        state: state as i32,
        next_offset,
        diagnostic: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use classmesh_protocol::control_wire::FileDestinationPolicy;

    #[derive(Debug, Default)]
    struct RecordingSink {
        bytes: Vec<u8>,
        starts: usize,
        writes: usize,
        commits: usize,
        aborts: usize,
        fail_next_write: bool,
    }

    impl FileTransferInboxSink for RecordingSink {
        type Error = ();

        fn begin(&mut self, _id: &[u8; 16], _filename: &str, _size: u64)
            -> Result<(), Self::Error>
        {
            self.starts += 1;
            Ok(())
        }

        fn append(
            &mut self,
            _id: &[u8; 16],
            _offset: u64,
            content: &[u8],
        ) -> Result<(), Self::Error> {
            self.writes += 1;
            if self.fail_next_write {
                self.fail_next_write = false;
                return Err(());
            }
            self.bytes.extend_from_slice(content);
            Ok(())
        }

        fn complete(&mut self, _id: &[u8; 16]) -> Result<(), Self::Error> {
            self.commits += 1;
            Ok(())
        }

        fn abort(&mut self, _id: &[u8; 16]) {
            self.aborts += 1;
            self.bytes.clear();
        }
    }

    fn peer() -> FileTransferPeer {
        FileTransferPeer {
            principal: PrincipalId([7; 32]),
            control_session_id: 31,
        }
    }

    fn offer(content: &[u8]) -> FileTransferOffer {
        FileTransferOffer {
            transfer_id: vec![9; 16],
            filename: "lesson.pdf".to_owned(),
            total_size: content.len() as u64,
            sha256: Sha256::digest(content).to_vec(),
            destination: FileDestinationPolicy::AppInbox as i32,
        }
    }

    fn chunk(offset: u64, content: &[u8]) -> FileTransferChunk {
        FileTransferChunk {
            transfer_id: vec![9; 16],
            offset,
            content: content.to_vec(),
        }
    }

    fn finish() -> FileTransferFinish {
        FileTransferFinish { transfer_id: vec![9; 16] }
    }

    #[test]
    fn bounded_streaming_transfer_commits_only_after_full_hash_match() {
        let mut receiver = FileTransferReceiver::new(RecordingSink::default());
        let data = b"abcdef";
        assert_eq!(receiver.offer(peer(), &offer(data)).unwrap().next_offset, 0);
        assert_eq!(receiver.chunk(peer(), &chunk(0, b"abc")).unwrap().next_offset, 3);
        assert_eq!(receiver.offer(peer(), &offer(data)).unwrap().next_offset, 3);
        assert_eq!(receiver.chunk(peer(), &chunk(3, b"def")).unwrap().next_offset, 6);
        assert_eq!(receiver.finish(peer(), &finish()).unwrap().state,
            FileTransferState::Completed as i32);
        let sink = receiver.sink();
        assert_eq!(sink.bytes, data);
        assert_eq!((sink.starts, sink.writes, sink.commits, sink.aborts), (1, 2, 1, 0));
    }

    #[test]
    fn strict_offset_and_peer_binding_reject_before_sink_write() {
        let mut receiver = FileTransferReceiver::new(RecordingSink::default());
        let data = b"abcdef";
        receiver.offer(peer(), &offer(data)).unwrap();
        assert_eq!(receiver.chunk(peer(), &chunk(3, b"abc")),
            Err(ReceiveError::NonSequentialChunk));
        let mut other = peer();
        other.control_session_id = 32;
        assert_eq!(receiver.chunk(other, &chunk(0, b"abc")),
            Err(ReceiveError::WrongTransferOrSession));
        assert_eq!(receiver.offer(other, &offer(data)),
            Err(ReceiveError::WrongTransferOrSession));
        assert_eq!(receiver.chunk(peer(), &chunk(0, b"abc")).unwrap().next_offset, 3);
        assert_eq!(receiver.chunk(peer(), &chunk(0, b"abc")),
            Err(ReceiveError::NonSequentialChunk));
        let sink = receiver.sink();
        assert_eq!(sink.writes, 1);
    }

    #[test]
    fn cancellation_and_corrupt_hash_discard_pending_transfer() {
        let mut receiver = FileTransferReceiver::new(RecordingSink::default());
        let data = b"abc";
        receiver.offer(peer(), &offer(data)).unwrap();
        receiver.chunk(peer(), &chunk(0, data)).unwrap();
        let mut bad = offer(data);
        bad.sha256 = vec![0; 32];
        assert_eq!(receiver.offer(peer(), &bad), Err(ReceiveError::Busy));
        let cancelled = receiver.cancel(
            peer(), &FileTransferCancel { transfer_id: vec![9; 16] }
        ).unwrap();
        assert_eq!(cancelled.state, FileTransferState::Cancelled as i32);
        receiver.offer(peer(), &bad).unwrap();
        receiver.chunk(peer(), &chunk(0, data)).unwrap();
        assert_eq!(receiver.finish(peer(), &finish()), Err(ReceiveError::HashMismatch));
        let sink = receiver.sink();
        assert_eq!(sink.commits, 0);
        assert_eq!(sink.aborts, 2);
    }

    #[test]
    fn sink_failure_aborts_and_cannot_advance_resumable_offset() {
        let sink = RecordingSink { fail_next_write: true, ..RecordingSink::default() };
        let mut receiver = FileTransferReceiver::new(sink);
        receiver.offer(peer(), &offer(b"abc")).unwrap();
        assert_eq!(receiver.chunk(peer(), &chunk(0, b"abc")),
            Err(ReceiveError::SinkFailure));
        assert_eq!(receiver.finish(peer(), &finish()),
            Err(ReceiveError::NoActiveTransfer));
        let sink = receiver.sink();
        assert_eq!((sink.writes, sink.commits, sink.aborts), (1, 0, 1));
    }

    #[test]
    fn capacity_one_and_finish_before_complete_are_fail_closed() {
        let mut receiver = FileTransferReceiver::new(RecordingSink::default());
        receiver.offer(peer(), &offer(b"abc")).unwrap();
        let mut other_offer = offer(b"abcd");
        other_offer.transfer_id = vec![8; 16];
        assert_eq!(receiver.offer(peer(), &other_offer),
            Err(ReceiveError::WrongTransferOrSession));
        assert_eq!(receiver.finish(peer(), &finish()), Err(ReceiveError::Incomplete));
        assert_eq!(receiver.chunk(peer(), &chunk(0, b"abcd")),
            Err(ReceiveError::PastDeclaredSize));
        assert_eq!(receiver.chunk(peer(), &chunk(0, b"abc")).unwrap().next_offset, 3);
        assert_eq!(receiver.finish(peer(), &finish()).unwrap().next_offset, 3);
    }
}
