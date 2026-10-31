//! The owning Teacher QUIC dispatcher consumes a real Student file-pull reply.
//! This is an on-demand step on its exclusive control stream, NOT a second
//! background listener. No status is reported complete until the sink commits.
use std::error::Error;
use std::fmt::{Display, Formatter};

use classmesh_protocol::control_wire::{
    ControlEnvelope, FileTransferCancel, FileTransferState, FileTransferStatus,
    ProtocolVersion as WireVersion, control_envelope,
};
use classmesh_protocol::file_transfer::{
    FileTransferError, file_transfer_pull_available, validate_status, validate_transfer_id,
};
use classmesh_protocol::{ControlRole, ProtocolVersion};
use classmesh_security::{Permission, PrincipalId, PrincipalKind};

use crate::client_session::ClientControlSession;
use crate::file_transfer_receiver::{
    FileTransferInboxSink, FileTransferPeer, FileTransferReceiver, ReceiveError,
};
use crate::live_authorization::LiveAuthorizationStore;
use crate::quic::ControlTransportError;
use crate::teacher_playback_receive::{
    AuthenticatedTeacherReceiveError, receive_authenticated_teacher_control,
};

#[derive(Debug)]
pub enum TeacherFilePullReceiveError {
    InvalidBinding,
    NotNegotiated,
    TeacherPermissionRevoked,
    InvalidTransfer(FileTransferError),
    AlreadyCompleted,
    WrongSession,
    WrongVersion,
    WrongRequest,
    WrongTransfer,
    SequenceMismatch,
    UnexpectedPayload,
    RemoteFailed(FileTransferState),
    Receiver(ReceiveError),
    AuthenticatedRead(AuthenticatedTeacherReceiveError),
    Transport(ControlTransportError),
}

impl Display for TeacherFilePullReceiveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for TeacherFilePullReceiveError {}

fn verify_current_teacher_permission(
    session: &ClientControlSession,
    authorization: &LiveAuthorizationStore,
) -> Result<(), TeacherFilePullReceiveError> {
    // This read must be fresh at every frame boundary. A valid Student TLS
    // certificate does not reinstate a revoked local Teacher ReceiveFile role.
    let snapshot = authorization
        .snapshot()
        .map_err(|_| TeacherFilePullReceiveError::TeacherPermissionRevoked)?;
    let current_teacher = session.established.negotiated.principal_id;
    if snapshot.store().principal(current_teacher).map(|p| p.kind) == Some(PrincipalKind::Teacher)
        && snapshot
            .store()
            .authorize(current_teacher, Permission::ReceiveFile)
    {
        Ok(())
    } else {
        Err(TeacherFilePullReceiveError::TeacherPermissionRevoked)
    }
}

/// Exact, one-transfer inbox owned by the same Teacher control dispatcher
/// that established the session and submitted the pull request.
pub struct TeacherFilePullInbox<S: FileTransferInboxSink> {
    receiver: FileTransferReceiver<S>,
    peer: FileTransferPeer,
    request_id: u64,
    transfer_id: [u8; 16],
    version: ProtocolVersion,
    last_inbound_sequence: u64,
    terminal: bool,
    completed: bool,
}

impl<S: FileTransferInboxSink> TeacherFilePullInbox<S> {
    pub fn new(
        session: &ClientControlSession,
        expected_student: PrincipalId,
        request_id: u64,
        transfer_id: [u8; 16],
        last_inbound_sequence: u64,
        sink: S,
    ) -> Result<Self, TeacherFilePullReceiveError> {
        if session.established.negotiated.role != ControlRole::Teacher
            || session.established.control_session_id == 0
            || request_id <= 1
            || last_inbound_sequence == 0
        {
            return Err(TeacherFilePullReceiveError::InvalidBinding);
        }
        validate_transfer_id(&transfer_id).map_err(TeacherFilePullReceiveError::InvalidTransfer)?;
        let version = session.established.negotiated.version;
        if !file_transfer_pull_available(version, &session.established.negotiated.capabilities) {
            return Err(TeacherFilePullReceiveError::NotNegotiated);
        }
        Ok(Self {
            receiver: FileTransferReceiver::new(sink),
            peer: FileTransferPeer {
                principal: expected_student,
                control_session_id: session.established.control_session_id,
            },
            request_id,
            transfer_id,
            version,
            last_inbound_sequence,
            terminal: false,
            completed: false,
        })
    }

    #[must_use]
    pub fn sink(&self) -> &S {
        self.receiver.sink()
    }

    fn apply_verified_frame(
        &mut self,
        envelope: ControlEnvelope,
    ) -> Result<FileTransferStatus, TeacherFilePullReceiveError> {
        if envelope.control_session_id != self.peer.control_session_id {
            return Err(TeacherFilePullReceiveError::WrongSession);
        }
        if envelope.protocol_version
            != Some(WireVersion {
                major: u32::from(self.version.major),
                minor: u32::from(self.version.minor),
            })
        {
            return Err(TeacherFilePullReceiveError::WrongVersion);
        }
        if envelope.request_id != self.request_id {
            return Err(TeacherFilePullReceiveError::WrongRequest);
        }
        if self.last_inbound_sequence.checked_add(1) != Some(envelope.sequence) {
            return Err(TeacherFilePullReceiveError::SequenceMismatch);
        }
        let payload = envelope
            .payload
            .ok_or(TeacherFilePullReceiveError::UnexpectedPayload)?;
        let response_id = match &payload {
            control_envelope::Payload::FileTransferOffer(offer) => &offer.transfer_id,
            control_envelope::Payload::FileTransferChunk(chunk) => &chunk.transfer_id,
            control_envelope::Payload::FileTransferFinish(finish) => &finish.transfer_id,
            control_envelope::Payload::FileTransferCancel(cancel) => &cancel.transfer_id,
            control_envelope::Payload::FileTransferStatus(status) => &status.transfer_id,
            _ => return Err(TeacherFilePullReceiveError::UnexpectedPayload),
        };
        if response_id.as_slice() != self.transfer_id {
            return Err(TeacherFilePullReceiveError::WrongTransfer);
        }
        self.last_inbound_sequence = envelope.sequence;
        match payload {
            control_envelope::Payload::FileTransferOffer(offer) => self
                .receiver
                .offer(self.peer, &offer)
                .map_err(TeacherFilePullReceiveError::Receiver),
            control_envelope::Payload::FileTransferChunk(chunk) => self
                .receiver
                .chunk(self.peer, &chunk)
                .map_err(TeacherFilePullReceiveError::Receiver),
            control_envelope::Payload::FileTransferFinish(finish) => self
                .receiver
                .finish(self.peer, &finish)
                .map_err(TeacherFilePullReceiveError::Receiver),
            control_envelope::Payload::FileTransferCancel(cancel) => self
                .receiver
                .cancel(self.peer, &cancel)
                .map_err(TeacherFilePullReceiveError::Receiver),
            control_envelope::Payload::FileTransferStatus(status) => {
                validate_status(&status).map_err(TeacherFilePullReceiveError::InvalidTransfer)?;
                let state = FileTransferState::try_from(status.state)
                    .map_err(|_| TeacherFilePullReceiveError::UnexpectedPayload)?;
                match state {
                    FileTransferState::Rejected
                    | FileTransferState::Cancelled
                    | FileTransferState::Failed => {
                        Err(TeacherFilePullReceiveError::RemoteFailed(state))
                    }
                    _ => Err(TeacherFilePullReceiveError::UnexpectedPayload),
                }
            }
            _ => Err(TeacherFilePullReceiveError::UnexpectedPayload),
        }
    }

    fn abort_pending(&mut self) {
        let _ = self.receiver.cancel(
            self.peer,
            &FileTransferCancel {
                transfer_id: self.transfer_id.to_vec(),
            },
        );
    }

    /// Receive exactly one verified QUIC response and send one correlated
    /// status back. The owning dispatcher must not read the same channel
    /// concurrently. Unexpected messages fail closed rather than being lost.
    ///
    /// Completed is returned ONLY after FileTransferReceiver has checked the
    /// full SHA-256 digest and the app-owned sink successfully committed.
    pub async fn receive_and_reply(
        &mut self,
        session: &mut ClientControlSession,
        authorization: &LiveAuthorizationStore,
        outbound_sequence: &mut u64,
        now_unix_ms: impl Fn() -> u64,
    ) -> Result<FileTransferStatus, TeacherFilePullReceiveError> {
        if self.completed {
            return Err(TeacherFilePullReceiveError::AlreadyCompleted);
        }
        if self.terminal
            || *outbound_sequence == 0
            || session.established.control_session_id != self.peer.control_session_id
            || session.established.negotiated.version != self.version
        {
            return Err(TeacherFilePullReceiveError::InvalidBinding);
        }

        let result = async {
            verify_current_teacher_permission(session, authorization)?;
            let message = receive_authenticated_teacher_control(
                session,
                authorization,
                self.peer.principal,
                now_unix_ms,
            )
            .await
            .map_err(TeacherFilePullReceiveError::AuthenticatedRead)?;
            // Authority can be withdrawn while awaiting an incoming QUIC
            // frame; deny before writing any bytes or committing the file.
            verify_current_teacher_permission(session, authorization)?;
            let status = self.apply_verified_frame(message.into_envelope())?;
            verify_current_teacher_permission(session, authorization)?;
            let sequence = outbound_sequence
                .checked_add(1)
                .ok_or(TeacherFilePullReceiveError::SequenceMismatch)?;
            // Reserve before await to avoid outbound replay after a partial send.
            *outbound_sequence = sequence;
            let envelope = ControlEnvelope {
                control_session_id: self.peer.control_session_id,
                sequence,
                protocol_version: Some(WireVersion {
                    major: u32::from(self.version.major),
                    minor: u32::from(self.version.minor),
                }),
                request_id: self.request_id,
                payload: Some(control_envelope::Payload::FileTransferStatus(
                    status.clone(),
                )),
            };
            session
                .channel
                .send(&envelope)
                .await
                .map_err(TeacherFilePullReceiveError::Transport)?;
            Ok::<_, TeacherFilePullReceiveError>(status)
        }
        .await;
        match result {
            Ok(status) => {
                let state = FileTransferState::try_from(status.state)
                    .map_err(|_| TeacherFilePullReceiveError::UnexpectedPayload)?;
                if state == FileTransferState::Completed {
                    self.completed = true;
                } else if state == FileTransferState::Cancelled {
                    self.terminal = true;
                }
                Ok(status)
            }
            Err(error) => {
                self.terminal = true;
                self.abort_pending();
                session
                    .connection
                    .close(0_u32.into(), b"teacher file pull reply invalid");
                Err(error)
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use classmesh_core::recovery::RecoveryPolicy;
    use classmesh_protocol::control_wire::{
        ControlEnvelope, FileDestinationPolicy, FileTransferChunk, FileTransferFinish,
        FileTransferOffer, FileTransferState, FileTransferStatus, ProtocolVersion as WireVersion,
        control_envelope,
    };
    use classmesh_protocol::{Capability, ControlRole, ProtocolVersion};
    use classmesh_security::{
        AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
        PrincipalId, PrincipalKind,
    };
    use quinn::Endpoint;
    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use sha2::{Digest, Sha256};

    use super::{TeacherFilePullInbox, TeacherFilePullReceiveError};
    use crate::ControlHello;
    use crate::client_session::connect_client_session_with_retries;
    use crate::file_transfer_receiver::FileTransferInboxSink;
    use crate::handshake::{ServerHelloConfig, server_hello};
    use crate::live_authorization::LiveAuthorizationStore;
    use crate::quic::{
        ControlChannel, DEFAULT_IO_TIMEOUT, accept, client_config_with_roots,
        server_config_with_certificate,
    };

    const VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 8 };
    const EXPECTED: PrincipalId = PrincipalId([7; 32]);

    #[derive(Default)]
    struct InboxSink {
        data: Vec<u8>,
        committed: bool,
        aborted: bool,
    }
    impl FileTransferInboxSink for InboxSink {
        type Error = ();
        fn begin(&mut self, _id: &[u8; 16], _filename: &str, size: u64) -> Result<(), ()> {
            self.data.clear();
            self.committed = false;
            self.aborted = false;
            if size == 0 {
                return Err(());
            }
            Ok(())
        }
        fn append(&mut self, _id: &[u8; 16], offset: u64, bytes: &[u8]) -> Result<(), ()> {
            if offset != self.data.len() as u64 {
                return Err(());
            }
            self.data.extend_from_slice(bytes);
            Ok(())
        }
        fn complete(&mut self, _id: &[u8; 16]) -> Result<(), ()> {
            self.committed = true;
            Ok(())
        }
        fn abort(&mut self, _id: &[u8; 16]) {
            self.data.clear();
            self.aborted = true;
        }
    }

    fn envelope(sequence: u64, payload: control_envelope::Payload) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: 77,
            sequence,
            protocol_version: Some(WireVersion { major: 0, minor: 8 }),
            request_id: 11,
            payload: Some(payload),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_quic_offer_chunk_finish_persists_bytes_before_completed_status()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let cert = generate_simple_self_signed(vec!["classmesh.local".into()])?;
        let certificate = CertificateDer::from(cert.cert);
        let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let server = Endpoint::server(
            server_config_with_certificate(vec![certificate.clone()], key.into())?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )?;
        let address = server.local_addr()?;
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone())?;
        let mut client_endpoint =
            Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        client_endpoint.set_default_client_config(client_config_with_roots(roots)?);

        let server_task = tokio::spawn(async move {
            let connection = accept(&server).await.map_err(|e| e.to_string())?;
            let mut channel = ControlChannel::accept(&connection, DEFAULT_IO_TIMEOUT)
                .await
                .map_err(|e| e.to_string())?;
            server_hello(
                &mut channel,
                &ServerHelloConfig {
                    local_version: VERSION,
                    local_capabilities: BTreeSet::from([Capability::FileTransfer]),
                    control_session_id: 77,
                },
            )
            .await
            .map_err(|e| e.to_string())?;
            let bytes = b"ClassMesh staged file bytes";
            let id = vec![9; 16];
            let offer = FileTransferOffer {
                transfer_id: id.clone(),
                filename: "lesson.pdf".into(),
                total_size: bytes.len() as u64,
                sha256: Sha256::digest(bytes).to_vec(),
                destination: FileDestinationPolicy::AppInbox as i32,
            };
            channel
                .send(&envelope(
                    2,
                    control_envelope::Payload::FileTransferOffer(offer),
                ))
                .await
                .map_err(|e| e.to_string())?;
            let accepted = channel.receive().await.map_err(|e| e.to_string())?;
            assert!(matches!(
                accepted.payload,
                Some(control_envelope::Payload::FileTransferStatus(ref status))
                if status.state == FileTransferState::Accepted as i32
                    && status.next_offset == 0
            ));
            assert_eq!(accepted.sequence, 2);
            channel
                .send(&envelope(
                    3,
                    control_envelope::Payload::FileTransferChunk(FileTransferChunk {
                        transfer_id: id.clone(),
                        offset: 0,
                        content: bytes.to_vec(),
                    }),
                ))
                .await
                .map_err(|e| e.to_string())?;
            let progress = channel.receive().await.map_err(|e| e.to_string())?;
            assert!(matches!(
                progress.payload,
                Some(control_envelope::Payload::FileTransferStatus(ref status))
                if status.state == FileTransferState::Progress as i32
                    && status.next_offset == bytes.len() as u64
            ));
            assert_eq!(progress.sequence, 3);
            channel
                .send(&envelope(
                    4,
                    control_envelope::Payload::FileTransferFinish(FileTransferFinish {
                        transfer_id: id,
                    }),
                ))
                .await
                .map_err(|e| e.to_string())?;
            let completed = channel.receive().await.map_err(|e| e.to_string())?;
            assert!(matches!(
                completed.payload,
                Some(control_envelope::Payload::FileTransferStatus(ref status))
                if status.state == FileTransferState::Completed as i32
                    && status.next_offset == bytes.len() as u64
            ));
            assert_eq!(completed.sequence, 4);
            Ok::<_, String>(())
        });

        let mut session = connect_client_session_with_retries(
            &client_endpoint,
            address,
            "classmesh.local",
            &ControlHello {
                principal_id: PrincipalId([8; 32]),
                role: ControlRole::Teacher,
                version: VERSION,
                capabilities: BTreeSet::from([Capability::FileTransfer]),
                hostname: "teacher-test".into(),
                app_version: "0.0.1".into(),
            },
            DEFAULT_IO_TIMEOUT,
            RecoveryPolicy {
                max_attempts: 1,
                base_backoff_ms: 1,
                max_backoff_ms: 1,
            },
        )
        .await?;
        let fingerprint = CredentialFingerprint(Sha256::digest(certificate.as_ref()).into());
        let mut credentials = BTreeMap::new();
        credentials.insert(fingerprint, CredentialRecord::active(fingerprint, 100));
        let mut store = AuthorizationStore::default();
        store
            .upsert(Principal {
                id: EXPECTED,
                kind: PrincipalKind::StudentDevice,
                enabled: true,
                permissions: BTreeSet::from([Permission::ReceivePresentation]),
                credentials,
            })
            .map_err(|e| format!("{e:?}"))?;
        store
            .upsert(Principal {
                id: PrincipalId([8; 32]),
                kind: PrincipalKind::Teacher,
                enabled: true,
                permissions: BTreeSet::from([Permission::ReceiveFile]),
                credentials: BTreeMap::new(),
            })
            .map_err(|e| format!("{e:?}"))?;
        let live = LiveAuthorizationStore::new(store);
        let mut inbox =
            TeacherFilePullInbox::new(&session, EXPECTED, 11, [9; 16], 1, InboxSink::default())
                .expect("valid negotiated Teacher file-pull session");
        let mut outbound_seq = 1;
        // These outer envelopes must fail without consuming the expected
        // sequence or admitting an unauthenticated cross-device transfer.
        let rejected = envelope(
            2,
            control_envelope::Payload::FileTransferStatus(FileTransferStatus {
                transfer_id: vec![9; 16],
                state: FileTransferState::Rejected as i32,
                next_offset: 0,
                diagnostic: "test".into(),
            }),
        );
        let mut wrong = rejected.clone();
        wrong.control_session_id = 78;
        assert!(matches!(
            inbox.apply_verified_frame(wrong),
            Err(TeacherFilePullReceiveError::WrongSession)
        ));
        let mut wrong = rejected.clone();
        wrong.request_id = 12;
        assert!(matches!(
            inbox.apply_verified_frame(wrong),
            Err(TeacherFilePullReceiveError::WrongRequest)
        ));
        let mut wrong = rejected.clone();
        wrong.sequence = 1;
        assert!(matches!(
            inbox.apply_verified_frame(wrong),
            Err(TeacherFilePullReceiveError::SequenceMismatch)
        ));
        let mut wrong = rejected.clone();
        wrong.protocol_version = Some(WireVersion { major: 0, minor: 7 });
        assert!(matches!(
            inbox.apply_verified_frame(wrong),
            Err(TeacherFilePullReceiveError::WrongVersion)
        ));
        let accepted = inbox
            .receive_and_reply(&mut session, &live, &mut outbound_seq, || 150)
            .await?;
        assert_eq!(accepted.state, FileTransferState::Accepted as i32);
        let progress = inbox
            .receive_and_reply(&mut session, &live, &mut outbound_seq, || 150)
            .await?;
        assert_eq!(progress.state, FileTransferState::Progress as i32);
        assert!(!inbox.sink().committed);
        let completed = inbox
            .receive_and_reply(&mut session, &live, &mut outbound_seq, || 150)
            .await?;
        assert_eq!(completed.state, FileTransferState::Completed as i32);
        assert_eq!(outbound_seq, 4);
        assert!(inbox.sink().committed);
        assert_eq!(inbox.sink().data, b"ClassMesh staged file bytes");
        assert!(matches!(
            inbox
                .receive_and_reply(&mut session, &live, &mut outbound_seq, || 150,)
                .await,
            Err(TeacherFilePullReceiveError::AlreadyCompleted)
        ));
        server_task.await??;
        Ok(())
    }
}
