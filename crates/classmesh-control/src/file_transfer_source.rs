use classmesh_protocol::control_wire::ControlEnvelope;
use classmesh_protocol::control_wire::{
    FileDestinationPolicy, FileTransferCancel, FileTransferChunk, FileTransferFinish,
    FileTransferOffer,
};
use classmesh_protocol::file_transfer::{
    FileTransferError, MAX_FILE_CHUNK_BYTES, validate_cancel, validate_chunk, validate_finish,
    validate_offer, validate_transfer_id,
};

use crate::authorization::{AuthenticatedControlGuard, CommandAuthorizationError};
use crate::file_transfer_receiver::FileTransferPeer;
use crate::live_authorization::LiveAuthorizationStore;
use crate::peer_identity::AuthenticatedPeerIdentity;
use classmesh_security::{AuthorizationStore, Permission};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceReadMode {
    Unset,
    Direct,
    Acknowledged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveSource {
    peer: FileTransferPeer,
    transfer_id: [u8; 16],
    source_id: FileSourceId,
    metadata: FileTransferSourceMetadata,
    // Direct offsets and receiver ACK-driven reads cannot share a history.
    read_mode: SourceReadMode,
    // ACK-driven reads must only advance to the end of a real emitted chunk.
    next_expected_offset: u64,
    next_finish_emitted: bool,
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
            // An Offer retry is idempotent only before any source progress.
            // Once a chunk or Finish has been emitted, replaying the Offer
            // could reset receiver state for the same transfer identifier.
            if active.read_mode != SourceReadMode::Unset || active.next_finish_emitted {
                return Err(SourceError::InvalidOffset);
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
            read_mode: SourceReadMode::Unset,
            next_expected_offset: 0,
            next_finish_emitted: false,
        });
        Ok(candidate)
    }

    pub fn chunk(
        &mut self,
        peer: FileTransferPeer,
        transfer_id: &[u8],
        offset: u64,
    ) -> Result<FileTransferChunk, SourceError> {
        if self.bound_active(peer, transfer_id)?.read_mode == SourceReadMode::Acknowledged {
            return Err(SourceError::InvalidOffset);
        }
        let chunk = self.read_chunk(peer, transfer_id, offset)?;
        if let Some(active) = self.active.as_mut() {
            active.read_mode = SourceReadMode::Direct;
        }
        Ok(chunk)
    }

    fn read_chunk(
        &mut self,
        peer: FileTransferPeer,
        transfer_id: &[u8],
        offset: u64,
    ) -> Result<FileTransferChunk, SourceError> {
        let active = self.bound_active(peer, transfer_id)?.clone();
        if active.next_finish_emitted {
            return Err(SourceError::InvalidOffset);
        }
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
        let active = self.bound_active(peer, transfer_id)?;
        if active.read_mode == SourceReadMode::Direct
            || active.next_finish_emitted
            || next_offset != active.next_expected_offset
        {
            return Err(SourceError::InvalidOffset);
        }
        if next_offset == active.metadata.total_size {
            return self
                .finish(peer, transfer_id)
                .map(FileTransferSourceFrame::Finish);
        }

        let chunk = self.read_chunk(peer, transfer_id, next_offset)?;
        if let Some(active) = self.active.as_mut() {
            active.read_mode = SourceReadMode::Acknowledged;
            active.next_expected_offset = next_offset + chunk.content.len() as u64;
        }
        Ok(FileTransferSourceFrame::Chunk(chunk))
    }

    pub fn finish(
        &mut self,
        peer: FileTransferPeer,
        transfer_id: &[u8],
    ) -> Result<FileTransferFinish, SourceError> {
        let active = self.bound_active(peer, transfer_id)?;
        // Finish is a state transition: it cannot be fabricated before
        // the source emitted all declared bytes or replayed after success.
        if active.next_finish_emitted || active.next_expected_offset != active.metadata.total_size {
            return Err(SourceError::InvalidOffset);
        }
        let finish = FileTransferFinish {
            transfer_id: active.transfer_id.to_vec(),
        };
        validate_finish(&finish).map_err(SourceError::InvalidPayload)?;
        if let Some(active) = self.active.as_mut() {
            active.next_finish_emitted = true;
        }
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
        // Completed is a receiver claim, not proof that the Service emitted
        // Finish. Release the resource even when the claim is premature.
        if !active.next_finish_emitted {
            return Err(SourceError::InvalidOffset);
        }
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

/// Recheck the live ReceiveFile grant for each authenticated pull status.
/// A status is not a new pull request, but it can trigger the next source
/// read. Envelope-only validation would permit reads after grant revocation.
/// The guard consumes denied sequence numbers so a later grant cannot replay
/// the same status.
pub fn authorize_file_pull_status(
    guard: &mut AuthenticatedControlGuard,
    authorization: &AuthorizationStore,
    envelope: &ControlEnvelope,
    now_unix_ms: u64,
) -> Result<(), CommandAuthorizationError> {
    guard.authorize(
        authorization,
        envelope,
        Permission::ReceiveFile,
        now_unix_ms,
    )
}

/// Final Service-dispatch authorization for a queued file pull. Unlike an
/// ingress snapshot, this is sampled immediately before the Service-owned
/// source read; a revoked grant or poisoned publisher fails closed.
/// A future trusted policy publisher must still serialize publication with
/// source reads if it requires zero concurrent-revocation exposure.
pub fn authorize_queued_file_pull(
    authorization: &LiveAuthorizationStore,
    identity: AuthenticatedPeerIdentity,
    now_unix_ms: u64,
) -> bool {
    authorization.snapshot().is_ok_and(|snapshot| {
        identity.authorize(snapshot.store(), Permission::ReceiveFile, now_unix_ms)
    })
}

fn validate_peer(peer: FileTransferPeer) -> Result<(), SourceError> {
    // An all-zero principal is not an enrolled identity. Never resolve an
    // app-owned source for an absent authenticated caller binding.
    if peer.control_session_id == 0 || peer.principal.0.iter().all(|byte| *byte == 0) {
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
    fn queued_file_pull_rechecks_live_authority_after_status_admission() {
        use crate::live_authorization::LiveAuthorizationStore;
        use crate::peer_identity::AuthenticatedPeerIdentity;
        use classmesh_security::{
            AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
            PrincipalKind,
        };
        use std::collections::{BTreeMap, BTreeSet};
        let identity = AuthenticatedPeerIdentity {
            principal_id: PrincipalId([7; 32]),
            credential_fingerprint: CredentialFingerprint([9; 32]),
        };
        let policy = |permissions: BTreeSet<Permission>| {
            let mut credentials = BTreeMap::new();
            credentials.insert(
                identity.credential_fingerprint,
                CredentialRecord::active(identity.credential_fingerprint, 100),
            );
            let mut store = AuthorizationStore::default();
            store
                .upsert(Principal {
                    id: identity.principal_id,
                    kind: PrincipalKind::Teacher,
                    enabled: true,
                    permissions,
                    credentials,
                })
                .unwrap();
            store
        };
        let live = LiveAuthorizationStore::new(policy(BTreeSet::from([Permission::ReceiveFile])));
        assert!(authorize_queued_file_pull(&live, identity, 150));
        // A queued ACK was valid at ingress, but policy changes before the
        // Service main loop consumes it: no further source read is permitted.
        live.publish_if_version(1, policy(BTreeSet::from([Permission::SendFile])))
            .unwrap();
        assert!(!authorize_queued_file_pull(&live, identity, 150));
        live.publish_if_version(2, policy(BTreeSet::from([Permission::ReceiveFile])))
            .unwrap();
        assert!(authorize_queued_file_pull(&live, identity, 150));
    }

    #[test]
    fn file_pull_status_requires_live_receive_file_permission_and_consumes_revoked_sequence() {
        use std::collections::{BTreeMap, BTreeSet};

        use crate::authorization::{AuthenticatedControlGuard, CommandAuthorizationError};
        use crate::peer_identity::AuthenticatedPeerIdentity;
        use classmesh_protocol::PROTOCOL_VERSION;
        use classmesh_protocol::control_wire::{
            ControlEnvelope, FileTransferState, FileTransferStatus,
            ProtocolVersion as WireProtocolVersion, control_envelope,
        };
        use classmesh_security::{
            AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
            PrincipalKind,
        };

        let identity = AuthenticatedPeerIdentity {
            principal_id: PrincipalId([7; 32]),
            credential_fingerprint: CredentialFingerprint([9; 32]),
        };
        let store_with = |permissions: BTreeSet<Permission>| {
            let mut credentials = BTreeMap::new();
            credentials.insert(
                identity.credential_fingerprint,
                CredentialRecord::active(identity.credential_fingerprint, 100),
            );
            let mut store = AuthorizationStore::default();
            store
                .upsert(Principal {
                    id: identity.principal_id,
                    kind: PrincipalKind::Teacher,
                    enabled: true,
                    permissions,
                    credentials,
                })
                .expect("valid enrolled teacher");
            store
        };
        let allowed = store_with(BTreeSet::from([Permission::ReceiveFile]));
        let revoked = store_with(BTreeSet::from([Permission::SendFile]));
        let mut guard = AuthenticatedControlGuard::new(identity, 77, PROTOCOL_VERSION, 0);
        let status = |sequence| ControlEnvelope {
            control_session_id: 77,
            sequence,
            protocol_version: Some(WireProtocolVersion {
                major: u32::from(PROTOCOL_VERSION.major),
                minor: u32::from(PROTOCOL_VERSION.minor),
            }),
            request_id: 41,
            payload: Some(control_envelope::Payload::FileTransferStatus(
                FileTransferStatus {
                    transfer_id: vec![9; 16],
                    state: FileTransferState::Progress as i32,
                    next_offset: 3,
                    diagnostic: String::new(),
                },
            )),
        };

        assert_eq!(
            authorize_file_pull_status(&mut guard, &allowed, &status(1), 150),
            Ok(())
        );
        assert_eq!(
            authorize_file_pull_status(&mut guard, &revoked, &status(2), 150),
            Err(CommandAuthorizationError::Unauthorized {
                permission: Permission::ReceiveFile,
            }),
            "SendFile alone must not authorize a pull Progress status"
        );
        assert_eq!(guard.last_sequence(), 2, "denied sequence is consumed");
        assert!(matches!(
            authorize_file_pull_status(&mut guard, &allowed, &status(2), 150),
            Err(CommandAuthorizationError::NonIncreasingSequence { .. })
        ));
        assert_eq!(
            authorize_file_pull_status(&mut guard, &allowed, &status(3), 150),
            Ok(())
        );
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
    fn replayed_offer_after_source_progress_cannot_restart_transfer() {
        let mut ack = FileTransferSourceSession::new(RecordingSource::new(b"abcdef".to_vec()));
        ack.offer(peer(), &transfer_id(), source_id()).unwrap();
        assert!(matches!(
            ack.next(peer(), &transfer_id(), 0),
            Ok(FileTransferSourceFrame::Chunk(_))
        ));
        assert_eq!(
            ack.offer(peer(), &transfer_id(), source_id()),
            Err(SourceError::InvalidOffset),
            "a repeated Offer after source bytes were emitted must not reset receiver state"
        );
        assert_eq!(ack.source().metadata_calls, 1);
        assert_eq!(ack.source().reads.len(), 1);
        assert!(matches!(
            ack.next(peer(), &transfer_id(), 6),
            Ok(FileTransferSourceFrame::Finish(_))
        ));
        assert_eq!(
            ack.offer(peer(), &transfer_id(), source_id()),
            Err(SourceError::InvalidOffset)
        );
        assert_eq!(ack.complete(peer(), &transfer_id()), Ok(()));

        let mut direct = FileTransferSourceSession::new(RecordingSource::new(b"abcdef".to_vec()));
        direct.offer(peer(), &transfer_id(), source_id()).unwrap();
        direct.chunk(peer(), &transfer_id(), 0).unwrap();
        assert_eq!(
            direct.offer(peer(), &transfer_id(), source_id()),
            Err(SourceError::InvalidOffset),
            "direct reads must not permit an Offer replay either"
        );
        assert_eq!(direct.source().reads.len(), 1);
        assert!(direct.cancel(peer(), &transfer_id()).is_ok());
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
    fn next_rejects_skipped_or_replayed_offsets_without_reading_source() {
        let mut session = FileTransferSourceSession::new(RecordingSource::new(b"abcdef".to_vec()));
        session.offer(peer(), &transfer_id(), source_id()).unwrap();

        // An ACK for bytes never produced must not generate Finish.
        assert_eq!(
            session.next(peer(), &transfer_id(), 6),
            Err(SourceError::InvalidOffset)
        );
        assert_eq!(
            session.next(peer(), &transfer_id(), 3),
            Err(SourceError::InvalidOffset)
        );
        assert!(session.source().reads.is_empty());

        assert!(matches!(
            session.next(peer(), &transfer_id(), 0),
            Ok(FileTransferSourceFrame::Chunk(_))
        ));
        assert_eq!(session.source().reads.len(), 1);
        assert_eq!(
            session.next(peer(), &transfer_id(), 0),
            Err(SourceError::InvalidOffset)
        );
        assert_eq!(session.source().reads.len(), 1);

        assert!(matches!(
            session.next(peer(), &transfer_id(), 6),
            Ok(FileTransferSourceFrame::Finish(_))
        ));
        assert_eq!(
            session.next(peer(), &transfer_id(), 6),
            Err(SourceError::InvalidOffset)
        );
        assert_eq!(session.source().reads.len(), 1);
    }

    #[test]
    fn next_requires_exact_previous_chunk_end_across_multiple_chunks() {
        let data = vec![7; MAX_FILE_CHUNK_BYTES + 3];
        let mut session = FileTransferSourceSession::new(RecordingSource::new(data));
        session.offer(peer(), &transfer_id(), source_id()).unwrap();
        assert!(matches!(
            session.next(peer(), &transfer_id(), 0),
            Ok(FileTransferSourceFrame::Chunk(_))
        ));
        assert_eq!(
            session.next(peer(), &transfer_id(), (MAX_FILE_CHUNK_BYTES + 3) as u64),
            Err(SourceError::InvalidOffset)
        );
        assert_eq!(session.source().reads.len(), 1);
        assert!(matches!(
            session.next(peer(), &transfer_id(), MAX_FILE_CHUNK_BYTES as u64),
            Ok(FileTransferSourceFrame::Chunk(_))
        ));
        assert!(matches!(
            session.next(peer(), &transfer_id(), (MAX_FILE_CHUNK_BYTES + 3) as u64),
            Ok(FileTransferSourceFrame::Finish(_))
        ));
        assert_eq!(session.source().reads.len(), 2);
    }

    #[test]
    fn direct_and_ack_driven_reads_cannot_mix_or_replay_source_bytes() {
        // Direct reads and Service ACK-driven reads have incompatible
        // progress contracts; interleaving them cannot manufacture progress.
        let mut direct = FileTransferSourceSession::new(RecordingSource::new(b"abcdef".to_vec()));
        direct.offer(peer(), &transfer_id(), source_id()).unwrap();
        direct.chunk(peer(), &transfer_id(), 0).unwrap();
        assert_eq!(
            direct.next(peer(), &transfer_id(), 0),
            Err(SourceError::InvalidOffset)
        );
        assert_eq!(direct.source().reads.len(), 1);
        assert!(direct.cancel(peer(), &transfer_id()).is_ok());

        let mut sequenced =
            FileTransferSourceSession::new(RecordingSource::new(b"abcdef".to_vec()));
        sequenced
            .offer(peer(), &transfer_id(), source_id())
            .unwrap();
        assert!(matches!(
            sequenced.next(peer(), &transfer_id(), 0),
            Ok(FileTransferSourceFrame::Chunk(_))
        ));
        assert_eq!(
            sequenced.chunk(peer(), &transfer_id(), 0),
            Err(SourceError::InvalidOffset)
        );
        assert_eq!(sequenced.source().reads.len(), 1);
        assert!(matches!(
            sequenced.next(peer(), &transfer_id(), 6),
            Ok(FileTransferSourceFrame::Finish(_))
        ));
        assert_eq!(sequenced.complete(peer(), &transfer_id()), Ok(()));
    }

    #[test]
    fn completed_before_finish_is_rejected_and_releases_source() {
        let closes = Arc::new(AtomicUsize::new(0));
        let mut source = RecordingSource::new(b"abcdef".to_vec());
        source.closes = Arc::clone(&closes);
        let mut session = FileTransferSourceSession::new(source);
        session.offer(peer(), &transfer_id(), source_id()).unwrap();

        assert_eq!(
            session.complete(peer(), &transfer_id()),
            Err(SourceError::InvalidOffset)
        );
        assert_eq!(closes.load(Ordering::Relaxed), 1);

        let second = [10; 16];
        session.offer(peer(), &second, source_id()).unwrap();
        assert!(matches!(
            session.next(peer(), &second, 0),
            Ok(FileTransferSourceFrame::Chunk(_))
        ));
        assert_eq!(
            session.complete(peer(), &second),
            Err(SourceError::InvalidOffset)
        );
        assert_eq!(closes.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn finish_requires_emitted_bytes_and_is_one_shot() {
        let mut session = FileTransferSourceSession::new(RecordingSource::new(b"abcdef".to_vec()));
        session.offer(peer(), &transfer_id(), source_id()).unwrap();
        assert_eq!(
            session.finish(peer(), &transfer_id()),
            Err(SourceError::InvalidOffset)
        );
        assert!(session.source().reads.is_empty());
        assert!(matches!(
            session.next(peer(), &transfer_id(), 0),
            Ok(FileTransferSourceFrame::Chunk(_))
        ));
        assert!(session.finish(peer(), &transfer_id()).is_ok());
        assert_eq!(
            session.finish(peer(), &transfer_id()),
            Err(SourceError::InvalidOffset)
        );
        assert_eq!(
            session.next(peer(), &transfer_id(), 6),
            Err(SourceError::InvalidOffset)
        );
        assert_eq!(
            session.chunk(peer(), &transfer_id(), 0),
            Err(SourceError::InvalidOffset)
        );
        assert_eq!(session.source().reads.len(), 1);
        assert_eq!(session.complete(peer(), &transfer_id()), Ok(()));
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
        session.next(peer(), &transfer_id(), 0).unwrap();
        session.next(peer(), &transfer_id(), 3).unwrap();
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
    fn zero_principal_is_rejected_before_opening_or_reading_a_source() {
        let mut session = FileTransferSourceSession::new(RecordingSource::new(b"abc".to_vec()));
        let unauthenticated = FileTransferPeer {
            principal: PrincipalId([0; 32]),
            control_session_id: 31,
        };
        assert_eq!(
            session.offer(unauthenticated, &transfer_id(), source_id()),
            Err(SourceError::InvalidBinding)
        );
        assert_eq!(session.source().metadata_calls, 0);

        session.offer(peer(), &transfer_id(), source_id()).unwrap();
        assert_eq!(
            session.chunk(unauthenticated, &transfer_id(), 0),
            Err(SourceError::InvalidBinding)
        );
        assert!(session.source().reads.is_empty());
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
