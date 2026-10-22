//! Live, authenticated Teacher-side QUIC control receive boundary.
//! No unsolicited diagnostics are promoted to network-quality samples.

use std::error::Error;
use std::fmt::{Display, Formatter};

use classmesh_protocol::control_wire::{ControlEnvelope, control_envelope};
use classmesh_protocol::{Capability, ControlRole};
use classmesh_security::{PrincipalId, PrincipalKind};

use crate::client_session::ClientControlSession;
use crate::live_authorization::{LiveAuthorizationError, LiveAuthorizationStore};
use crate::peer_identity::{PeerIdentityError, authenticated_peer_identity};
use crate::quic::ControlTransportError;

/// Returns either a verified playback envelope or another verified control
/// message for the owning session dispatcher. It never drops an unrelated
/// control message or authorizes presentation/quality changes.
#[derive(Debug)]
#[must_use]
pub struct AuthenticatedTeacherControlMessage {
    envelope: ControlEnvelope,
    is_playback: bool,
}

impl AuthenticatedTeacherControlMessage {
    /// A playback diagnostic can only be promoted after verifying the live
    /// enrolled QUIC peer identity, negotiated capability, and exact session.
    #[must_use]
    pub fn receiver_playback(&self) -> Option<&ControlEnvelope> {
        self.is_playback.then_some(&self.envelope)
    }

    /// Give non-playback messages back to the single owning control dispatcher.
    /// The caller must not treat arbitrary messages as authenticated actions:
    /// those need their separate per-command authorization checks.
    #[must_use]
    pub fn into_envelope(self) -> ControlEnvelope {
        self.envelope
    }
}

#[derive(Debug)]
pub enum AuthenticatedTeacherReceiveError {
    WrongRole,
    InvalidSession,
    WrongPrincipal,
    WrongPrincipalKind,
    NotNegotiated,
    SessionMismatch,
    PeerIdentity(PeerIdentityError),
    Authorization(LiveAuthorizationError),
    Transport(ControlTransportError),
}

impl Display for AuthenticatedTeacherReceiveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for AuthenticatedTeacherReceiveError {}

/// Receive once from an existing, already enrolled Teacher -> Student
/// QUIC connection. The active caller owns the channel exclusively; it must
/// dispatch unrelated control envelopes returned by this method.
///
/// The verified TLS certificate resolves to the expected live StudentDevice
/// principal in a fresh LiveAuthorizationStore snapshot. It revalidates after I/O and
/// fails closed if it no longer matches. On errors the owning caller must
/// revoke its old playback UI projection instead of reusing stale counters.
///
/// The now_unix_ms source must return trusted, fresh wall time on each
/// invocation. It is sampled before and after network I/O so a credential
/// expiring during the read cannot be admitted with a pre-read timestamp.
/// This does not authenticate an endpoint created with untrusted TLS settings,
/// and does not connect a GUI or enable Phase 10 telemetry by default.
pub async fn receive_authenticated_teacher_control(
    session: &mut ClientControlSession,
    authorization: &LiveAuthorizationStore,
    expected_student: PrincipalId,
    now_unix_ms: impl Fn() -> u64,
) -> Result<AuthenticatedTeacherControlMessage, AuthenticatedTeacherReceiveError> {
    if session.established.negotiated.role != ControlRole::Teacher {
        return Err(AuthenticatedTeacherReceiveError::WrongRole);
    }
    if session.established.control_session_id == 0 {
        return Err(AuthenticatedTeacherReceiveError::InvalidSession);
    }
    let verify_peer = |session: &ClientControlSession| {
        // Never reuse a policy snapshot across awaited network I/O.
        let snapshot = authorization
            .snapshot()
            .map_err(AuthenticatedTeacherReceiveError::Authorization)?;
        let store = snapshot.store();
        let peer = authenticated_peer_identity(&session.connection, store, now_unix_ms())
            .map_err(AuthenticatedTeacherReceiveError::PeerIdentity)?;
        if peer.principal_id() != expected_student {
            return Err(AuthenticatedTeacherReceiveError::WrongPrincipal);
        }
        if store.principal(expected_student).map(|p| p.kind) != Some(PrincipalKind::StudentDevice) {
            return Err(AuthenticatedTeacherReceiveError::WrongPrincipalKind);
        }
        Ok(())
    };
    verify_peer(session)?;
    let envelope = session
        .channel
        .receive()
        .await
        .map_err(AuthenticatedTeacherReceiveError::Transport)?;
    verify_peer(session)?;

    if envelope.control_session_id != session.established.control_session_id {
        return Err(AuthenticatedTeacherReceiveError::SessionMismatch);
    }
    let is_playback = matches!(
        envelope.payload,
        Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(_))
    );
    if is_playback {
        let contract = &session.established.negotiated;
        if contract.version.major != 0
            || contract.version.minor < 8
            || !contract
                .capabilities
                .contains(&Capability::ReceiverPlaybackDiagnostics)
        {
            return Err(AuthenticatedTeacherReceiveError::NotNegotiated);
        }
    }
    Ok(AuthenticatedTeacherControlMessage {
        envelope,
        is_playback,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use classmesh_core::recovery::RecoveryPolicy;
    use classmesh_protocol::control_wire::{
        ControlEnvelope, ProtocolVersion as WireVersion, ReceiverPlaybackDiagnostic,
        control_envelope,
    };
    use classmesh_protocol::{Capability, ControlRole, ProtocolVersion};
    use classmesh_security::{
        AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
        PrincipalId, PrincipalKind,
    };
    use quinn::{Connection, Endpoint};
    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::ControlHello;
    use crate::client_session::{ClientControlSession, connect_client_session_with_retries};
    use crate::handshake::{ServerHelloConfig, server_hello};
    use crate::quic::{
        ControlChannel, DEFAULT_IO_TIMEOUT, accept, client_config_with_roots,
        server_config_with_certificate,
    };

    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;
    const VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 8 };
    const EXPECTED: PrincipalId = PrincipalId([7; 32]);
    const SESSION: u64 = 55;

    struct Pair {
        _client_endpoint: Endpoint,
        _server_endpoint: Endpoint,
        _server_connection: Connection,
        server_channel: ControlChannel,
        client: ClientControlSession,
        authorization: LiveAuthorizationStore,
    }

    async fn pair(with_capability: bool) -> Result<Pair, Box<dyn Error + Send + Sync>> {
        let cert = generate_simple_self_signed(vec!["classmesh.local".to_owned()])?;
        let certificate = CertificateDer::from(cert.cert);
        let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let server = Endpoint::server(
            server_config_with_certificate(vec![certificate.clone()], key.into())?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )?;
        let server_address = server.local_addr()?;
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone())?;
        let mut client_endpoint =
            Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        client_endpoint.set_default_client_config(client_config_with_roots(roots)?);
        let capabilities = if with_capability {
            BTreeSet::from([Capability::ReceiverPlaybackDiagnostics])
        } else {
            BTreeSet::new()
        };
        let server_caps = capabilities.clone();
        let server_task = tokio::spawn(async move {
            let conn = accept(&server).await.map_err(|e| e.to_string())?;
            let mut channel = ControlChannel::accept(&conn, DEFAULT_IO_TIMEOUT)
                .await
                .map_err(|e| e.to_string())?;
            server_hello(
                &mut channel,
                &ServerHelloConfig {
                    local_version: VERSION,
                    local_capabilities: server_caps,
                    control_session_id: SESSION,
                },
            )
            .await
            .map_err(|e| e.to_string())?;
            Ok::<_, String>((server, conn, channel))
        });
        let client = connect_client_session_with_retries(
            &client_endpoint,
            server_address,
            "classmesh.local",
            &ControlHello {
                principal_id: PrincipalId([8; 32]),
                role: ControlRole::Teacher,
                version: VERSION,
                capabilities,
                hostname: "teacher-test".to_owned(),
                app_version: "0.0.1".to_owned(),
            },
            DEFAULT_IO_TIMEOUT,
            RecoveryPolicy {
                max_attempts: 1,
                base_backoff_ms: 1,
                max_backoff_ms: 1,
            },
        )
        .await?;
        let (server_endpoint, server_connection, server_channel) = server_task.await??;
        let fingerprint = CredentialFingerprint(Sha256::digest(certificate.as_ref()).into());
        let mut credentials = BTreeMap::new();
        credentials.insert(fingerprint, CredentialRecord::active(fingerprint, 100));
        let mut authorization = AuthorizationStore::default();
        authorization
            .upsert(Principal {
                id: EXPECTED,
                kind: PrincipalKind::StudentDevice,
                enabled: true,
                permissions: BTreeSet::from([Permission::ReceivePresentation]),
                credentials,
            })
            .map_err(|error| format!("test authorization setup failed: {error:?}"))?;
        Ok(Pair {
            _client_endpoint: client_endpoint,
            _server_endpoint: server_endpoint,
            _server_connection: server_connection,
            server_channel,
            client,
            authorization: LiveAuthorizationStore::new(authorization),
        })
    }

    fn report(session: u64) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: session,
            sequence: 2,
            request_id: 0,
            protocol_version: Some(WireVersion { major: 0, minor: 8 }),
            payload: Some(control_envelope::Payload::ReceiverPlaybackDiagnostic(
                ReceiverPlaybackDiagnostic {
                    presentation_id: 21,
                    stream_id: 31,
                    epoch: 41,
                    receiver_generation: 1,
                    sequence: 1,
                    interval_ms: 5_000,
                    authenticated_frames: 100,
                    rejected_frames: 1,
                    decoded_frames: 90,
                    presented_frames: 89,
                    present_errors: 2,
                    decode_errors: 3,
                    keyframe_waits: 4,
                    queue_drops: 5,
                },
            )),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_quic_playback_requires_verified_enrolled_service_and_v08_capability() -> TestResult
    {
        let mut pair = pair(true).await?;
        pair.server_channel.send(&report(SESSION)).await?;
        let message = receive_authenticated_teacher_control(
            &mut pair.client,
            &pair.authorization,
            EXPECTED,
            || 150,
        )
        .await?;
        assert!(message.receiver_playback().is_some());
        assert_eq!(message.into_envelope().control_session_id, SESSION);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_or_revoked_service_cannot_consume_next_quic_diagnostic() -> TestResult {
        let mut pair = pair(true).await?;
        pair.server_channel.send(&report(SESSION)).await?;
        assert!(matches!(
            receive_authenticated_teacher_control(
                &mut pair.client,
                &pair.authorization,
                PrincipalId([9; 32]),
                || 150
            )
            .await,
            Err(AuthenticatedTeacherReceiveError::WrongPrincipal)
        ));
        let empty = LiveAuthorizationStore::new(AuthorizationStore::default());
        assert!(matches!(
            receive_authenticated_teacher_control(&mut pair.client, &empty, EXPECTED, || 150).await,
            Err(AuthenticatedTeacherReceiveError::PeerIdentity(_))
        ));
        assert!(
            receive_authenticated_teacher_control(
                &mut pair.client,
                &pair.authorization,
                EXPECTED,
                || 150
            )
            .await?
            .receiver_playback()
            .is_some()
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unnegotiated_playback_is_rejected_but_other_control_is_not_dropped() -> TestResult {
        let mut no_cap = pair(false).await?;
        no_cap.server_channel.send(&report(SESSION)).await?;
        assert!(matches!(
            receive_authenticated_teacher_control(
                &mut no_cap.client,
                &no_cap.authorization,
                EXPECTED,
                || 150
            )
            .await,
            Err(AuthenticatedTeacherReceiveError::NotNegotiated)
        ));
        let mut pair = pair(true).await?;
        let mut other = report(SESSION);
        other.payload = None;
        pair.server_channel.send(&other).await?;
        let message = receive_authenticated_teacher_control(
            &mut pair.client,
            &pair.authorization,
            EXPECTED,
            || 150,
        )
        .await?;
        assert!(message.receiver_playback().is_none());
        assert_eq!(message.into_envelope().control_session_id, SESSION);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn credential_expiry_during_quic_receive_is_rechecked_before_delivery() -> TestResult {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let mut pair = pair(true).await?;
        let chain = pair
            .client
            .connection
            .peer_identity()
            .ok_or("missing mTLS verified certificate")?
            .downcast::<Vec<CertificateDer<'static>>>()
            .map_err(|_| "wrong peer certificate chain type")?;
        let fingerprint = CredentialFingerprint(Sha256::digest(chain[0].as_ref()).into());
        let mut credentials = BTreeMap::new();
        credentials.insert(
            fingerprint,
            CredentialRecord {
                expires_at_unix_ms: Some(200),
                ..CredentialRecord::active(fingerprint, 100)
            },
        );
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
        pair.server_channel.send(&report(SESSION)).await?;
        let store = LiveAuthorizationStore::new(store);
        let polls = AtomicUsize::new(0);
        assert!(matches!(
            receive_authenticated_teacher_control(&mut pair.client, &store, EXPECTED, || {
                if polls.fetch_add(1, Ordering::SeqCst) == 0 {
                    150
                } else {
                    250
                }
            })
            .await,
            Err(AuthenticatedTeacherReceiveError::PeerIdentity(_))
        ));
        assert_eq!(polls.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn policy_revoked_during_receive_cannot_authorize_queued_playback() -> TestResult {
        let mut pair = pair(true).await?;
        let (received, sent) = tokio::join!(
            receive_authenticated_teacher_control(
                &mut pair.client,
                &pair.authorization,
                EXPECTED,
                || 150
            ),
            async {
                // Poll the reader first so it has already passed the first
                // identity check before publishing the revocation.
                let version = pair.authorization.snapshot().unwrap().version();
                pair.authorization
                    .publish_if_version(version, AuthorizationStore::default())
                    .expect("publish empty policy");
                pair.server_channel.send(&report(SESSION)).await
            }
        );
        sent?;
        assert!(matches!(
            received,
            Err(AuthenticatedTeacherReceiveError::PeerIdentity(_))
        ));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cross_session_envelope_cannot_be_promoted() -> TestResult {
        let mut pair = pair(true).await?;
        pair.server_channel.send(&report(SESSION + 1)).await?;
        assert!(matches!(
            receive_authenticated_teacher_control(
                &mut pair.client,
                &pair.authorization,
                EXPECTED,
                || 150
            )
            .await,
            Err(AuthenticatedTeacherReceiveError::SessionMismatch)
        ));
        Ok(())
    }
}
