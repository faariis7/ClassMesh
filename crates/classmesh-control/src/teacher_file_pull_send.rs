//! Enrolled Teacher QUIC file-pull send boundary; never trusts a UI context.
//! This sends exactly one request on the caller's exclusively owned live
//! control session. Responses are handled by the same owning dispatcher;
//! this module never starts a competing receive loop.
use std::error::Error;
use std::fmt::{Display, Formatter};

use classmesh_protocol::ControlRole;
use classmesh_protocol::control_wire::{
    ControlEnvelope, FileTransferPullRequest, ProtocolVersion as WireProtocolVersion,
    control_envelope,
};
use classmesh_protocol::file_transfer::{
    FileTransferError, file_transfer_pull_available, validate_pull_request,
};
use classmesh_security::{Permission, PrincipalId, PrincipalKind};

use crate::client_session::ClientControlSession;
use crate::live_authorization::{LiveAuthorizationError, LiveAuthorizationStore};
use crate::peer_identity::{PeerIdentityError, authenticated_peer_identity};
use crate::quic::ControlTransportError;

#[derive(Debug)]
pub enum TeacherFilePullTransportError {
    WrongRole,
    InvalidSession,
    NotNegotiated,
    InvalidRequest(FileTransferError),
    InvalidRequestId,
    SequenceExhausted,
    WrongPrincipal,
    WrongPrincipalKind,
    TeacherNotAuthorized,
    Authorization(LiveAuthorizationError),
    PeerIdentity(PeerIdentityError),
    Transport(ControlTransportError),
}

impl Display for TeacherFilePullTransportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl Error for TeacherFilePullTransportError {}

fn verify_enrolled_student(
    session: &ClientControlSession,
    authorization: &LiveAuthorizationStore,
    expected_student: PrincipalId,
    now_unix_ms: u64,
) -> Result<(), TeacherFilePullTransportError> {
    let snapshot = authorization
        .snapshot()
        .map_err(TeacherFilePullTransportError::Authorization)?;
    let store = snapshot.store();
    let peer = authenticated_peer_identity(&session.connection, store, now_unix_ms)
        .map_err(TeacherFilePullTransportError::PeerIdentity)?;
    if peer.principal_id() != expected_student {
        return Err(TeacherFilePullTransportError::WrongPrincipal);
    }
    if store.principal(expected_student).map(|p| p.kind) != Some(PrincipalKind::StudentDevice) {
        return Err(TeacherFilePullTransportError::WrongPrincipalKind);
    }
    let current_teacher = session.established.negotiated.principal_id;
    if store.principal(current_teacher).map(|p| p.kind) != Some(PrincipalKind::Teacher)
        || !store.authorize(current_teacher, Permission::ReceiveFile)
    {
        return Err(TeacherFilePullTransportError::TeacherNotAuthorized);
    }
    Ok(())
}

/// Send one validated Teacher pull request over an already enrolled QUIC client.
/// No GUI context, raw file path or unauthenticated discovery ID can authorize it.
/// The current local Teacher principal must have ReceiveFile permission in a
/// fresh trusted policy snapshot, in addition to the exact enrolled Student.
///
/// The *single owning dispatcher* supplies its current sequence and a unique
/// nonzero request ID. This call claims the next outbound sequence before I/O
/// so a failed send cannot accidentally reuse a sequence on the same session.
/// On I/O failure or live revocation, the connection closes; caller must
/// discard the old session and all UI state. No response or transfer success is
/// assumed by this send function.
pub async fn send_authenticated_file_pull_request(
    session: &mut ClientControlSession,
    authorization: &LiveAuthorizationStore,
    expected_student: PrincipalId,
    request: &FileTransferPullRequest,
    outbound_sequence: &mut u64,
    request_id: u64,
    now_unix_ms: impl Fn() -> u64,
) -> Result<(), TeacherFilePullTransportError> {
    if session.established.negotiated.role != ControlRole::Teacher {
        return Err(TeacherFilePullTransportError::WrongRole);
    }
    let established = &session.established;
    if established.control_session_id == 0 || *outbound_sequence == 0 {
        return Err(TeacherFilePullTransportError::InvalidSession);
    }
    if request_id <= 1 {
        return Err(TeacherFilePullTransportError::InvalidRequestId);
    }
    validate_pull_request(request).map_err(TeacherFilePullTransportError::InvalidRequest)?;
    if !file_transfer_pull_available(
        established.negotiated.version,
        &established.negotiated.capabilities,
    ) {
        return Err(TeacherFilePullTransportError::NotNegotiated);
    }
    verify_enrolled_student(session, authorization, expected_student, now_unix_ms())?;
    let sequence = outbound_sequence
        .checked_add(1)
        .ok_or(TeacherFilePullTransportError::SequenceExhausted)?;
    // Claim before network I/O: a partial write cannot permit a replay.
    *outbound_sequence = sequence;
    let version = established.negotiated.version;
    let envelope = ControlEnvelope {
        control_session_id: established.control_session_id,
        sequence,
        protocol_version: Some(WireProtocolVersion {
            major: u32::from(version.major),
            minor: u32::from(version.minor),
        }),
        request_id,
        payload: Some(control_envelope::Payload::FileTransferPullRequest(
            request.clone(),
        )),
    };
    if let Err(error) = session.channel.send(&envelope).await {
        session
            .connection
            .close(0_u32.into(), b"file pull request send failed");
        return Err(TeacherFilePullTransportError::Transport(error));
    }
    if let Err(error) =
        verify_enrolled_student(session, authorization, expected_student, now_unix_ms())
    {
        session
            .connection
            .close(0_u32.into(), b"file pull authorization revoked");
        return Err(error);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use classmesh_core::recovery::RecoveryPolicy;
    use classmesh_protocol::control_wire::{
        FileSourcePolicy, FileTransferPullRequest, control_envelope,
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

    use super::{TeacherFilePullTransportError, send_authenticated_file_pull_request};
    use crate::ControlHello;
    use crate::client_session::connect_client_session_with_retries;
    use crate::handshake::{ServerHelloConfig, server_hello};
    use crate::live_authorization::LiveAuthorizationStore;
    use crate::quic::{
        ControlChannel, DEFAULT_IO_TIMEOUT, accept, client_config_with_roots,
        server_config_with_certificate,
    };

    const VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 8 };
    const EXPECTED: PrincipalId = PrincipalId([7; 32]);

    fn request() -> FileTransferPullRequest {
        FileTransferPullRequest {
            transfer_id: vec![9; 16],
            source_id: vec![8; 16],
            source: FileSourcePolicy::AppOutbox as i32,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enrolled_teacher_sends_actual_pull_over_quic_only_to_authenticated_student()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let cert = generate_simple_self_signed(vec!["classmesh.local".into()])?;
        let certificate = CertificateDer::from(cert.cert);
        let private_key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let server = Endpoint::server(
            server_config_with_certificate(vec![certificate.clone()], private_key.into())?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )?;
        let server_address = server.local_addr()?;
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
            Ok::<_, String>((server, connection, channel))
        });
        let mut session = connect_client_session_with_retries(
            &client_endpoint,
            server_address,
            "classmesh.local",
            &ControlHello {
                principal_id: PrincipalId([8; 32]),
                role: ControlRole::Teacher,
                version: VERSION,
                capabilities: BTreeSet::from([Capability::FileTransfer]),
                hostname: "teacher".into(),
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
        let (_server, _connection, mut channel) = server_task.await??;
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
        let mut teacher_allowed = store.clone();
        teacher_allowed
            .upsert(Principal {
                id: PrincipalId([8; 32]),
                kind: PrincipalKind::Teacher,
                enabled: true,
                permissions: BTreeSet::from([Permission::ReceiveFile]),
                credentials: BTreeMap::new(),
            })
            .expect("authorized Teacher fixture");
        let live = LiveAuthorizationStore::new(store);
        let mut seq = 1;
        let mut invalid = request();
        invalid.source_id = vec![0; 16];
        assert!(matches!(
            send_authenticated_file_pull_request(
                &mut session,
                &live,
                EXPECTED,
                &invalid,
                &mut seq,
                11,
                || 150,
            )
            .await,
            Err(TeacherFilePullTransportError::InvalidRequest(_))
        ));
        assert_eq!(seq, 1);

        session.established.negotiated.capabilities.clear();
        assert!(matches!(
            send_authenticated_file_pull_request(
                &mut session,
                &live,
                EXPECTED,
                &request(),
                &mut seq,
                11,
                || 150,
            )
            .await,
            Err(TeacherFilePullTransportError::NotNegotiated)
        ));
        session
            .established
            .negotiated
            .capabilities
            .insert(Capability::FileTransfer);
        assert_eq!(seq, 1);
        assert!(matches!(
            send_authenticated_file_pull_request(
                &mut session,
                &live,
                EXPECTED,
                &request(),
                &mut seq,
                0,
                || 150,
            )
            .await,
            Err(TeacherFilePullTransportError::InvalidRequestId)
        ));
        assert_eq!(seq, 1);
        // A different device cannot be sent the staged source ID.
        assert!(matches!(
            send_authenticated_file_pull_request(
                &mut session,
                &live,
                PrincipalId([6; 32]),
                &request(),
                &mut seq,
                11,
                || 150,
            )
            .await,
            Err(TeacherFilePullTransportError::WrongPrincipal)
        ));
        assert_eq!(seq, 1);
        // A valid Student certificate does not authorize a Teacher that lacks
        // the ReceiveFile permission on the live local policy.
        assert!(matches!(
            send_authenticated_file_pull_request(
                &mut session,
                &live,
                EXPECTED,
                &request(),
                &mut seq,
                11,
                || 150,
            )
            .await,
            Err(TeacherFilePullTransportError::TeacherNotAuthorized)
        ));
        assert_eq!(seq, 1);
        live.publish_if_version(1, teacher_allowed)
            .expect("publish authorized Teacher policy");
        send_authenticated_file_pull_request(
            &mut session,
            &live,
            EXPECTED,
            &request(),
            &mut seq,
            11,
            || 150,
        )
        .await?;
        assert_eq!(seq, 2);
        let envelope = channel.receive().await?;
        assert_eq!(envelope.control_session_id, 77);
        assert_eq!(envelope.sequence, 2);
        assert_eq!(envelope.request_id, 11);
        assert!(matches!(
            envelope.payload,
            Some(control_envelope::Payload::FileTransferPullRequest(ref req))
                if *req == request()
        ));
        // A newer trusted policy may revoke the peer while the session is
        // connected; no second file identifier may leave after that update.
        live.publish_if_version(2, AuthorizationStore::default())
            .expect("publish newer trusted test policy");
        assert!(matches!(
            send_authenticated_file_pull_request(
                &mut session,
                &live,
                EXPECTED,
                &request(),
                &mut seq,
                12,
                || 150,
            )
            .await,
            Err(TeacherFilePullTransportError::PeerIdentity(_))
        ));
        assert_eq!(seq, 2);
        Ok(())
    }
}
