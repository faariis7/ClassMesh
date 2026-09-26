use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

use classmesh_protocol::ProtocolVersion;
use classmesh_security::group_media::GroupMediaEpoch;
use classmesh_security::group_media_coordinator::{
    GroupMediaCoordinator, MAX_GROUP_MEDIA_RECEIVERS,
};
use classmesh_security::{AuthorizationStore, PrincipalId};

use crate::client_session::ClientControlSession;
use crate::group_media_session::{
    BoundGroupMediaReceiverSession, GroupMediaSessionError, PendingPresentationKeyAck,
    PresentationKeyGrantRequest,
};
use crate::quic::ControlTransportError;

#[derive(Debug)]
pub enum TeacherGroupMediaDeliveryError {
    InvalidReceiverLimit,
    ReceiverLimitExceeded,
    DuplicateReceiver,
    ReceiverNotRegistered,
    SessionBindingMismatch,
    PendingAckExists,
    Binding(GroupMediaSessionError),
    Transport(ControlTransportError),
}

impl Display for TeacherGroupMediaDeliveryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidReceiverLimit => {
                formatter.write_str("invalid Teacher group-media receiver limit")
            }
            Self::ReceiverLimitExceeded => {
                formatter.write_str("Teacher group-media receiver limit exceeded")
            }
            Self::DuplicateReceiver => {
                formatter.write_str("Teacher group-media receiver session already registered")
            }
            Self::ReceiverNotRegistered => {
                formatter.write_str("Teacher group-media receiver session is not registered")
            }
            Self::SessionBindingMismatch => {
                formatter.write_str("Teacher group-media client session binding mismatch")
            }
            Self::PendingAckExists => {
                formatter.write_str("Teacher group-media receiver already has a pending key ACK")
            }
            Self::Binding(error) => write!(formatter, "Teacher group-media binding: {error}"),
            Self::Transport(error) => write!(formatter, "Teacher group-media transport: {error}"),
        }
    }
}

impl Error for TeacherGroupMediaDeliveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Binding(error) => Some(error),
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

impl From<GroupMediaSessionError> for TeacherGroupMediaDeliveryError {
    fn from(value: GroupMediaSessionError) -> Self {
        Self::Binding(value)
    }
}

impl From<ControlTransportError> for TeacherGroupMediaDeliveryError {
    fn from(value: ControlTransportError) -> Self {
        Self::Transport(value)
    }
}

#[derive(Debug)]
struct ReceiverDeliverySession {
    connection_stable_id: usize,
    control_session_id: u64,
    protocol_version: ProtocolVersion,
    pending_ack: Option<PendingPresentationKeyAck>,
}

/// Bounded Teacher-side Phase 7E key-delivery state.
///
/// Each registered receiver is pinned to the exact QUIC connection used to authenticate
/// its StudentDevice certificate, in addition to the control-session ID and negotiated
/// protocol version. Key grants are rebound to the live TLS peer immediately before send
/// and are sent only through the bundled ClientControlSession channel.
#[derive(Debug)]
pub struct TeacherGroupMediaDeliveryManager {
    receivers: BTreeMap<PrincipalId, ReceiverDeliverySession>,
    max_receivers: usize,
}

impl Default for TeacherGroupMediaDeliveryManager {
    fn default() -> Self {
        Self {
            receivers: BTreeMap::new(),
            max_receivers: MAX_GROUP_MEDIA_RECEIVERS,
        }
    }
}

impl TeacherGroupMediaDeliveryManager {
    pub fn with_limit(max_receivers: usize) -> Result<Self, TeacherGroupMediaDeliveryError> {
        if max_receivers == 0 || max_receivers > MAX_GROUP_MEDIA_RECEIVERS {
            return Err(TeacherGroupMediaDeliveryError::InvalidReceiverLimit);
        }

        Ok(Self {
            receivers: BTreeMap::new(),
            max_receivers,
        })
    }

    pub fn register_client_session(
        &mut self,
        session: &ClientControlSession,
        receiver: PrincipalId,
        authorization: &AuthorizationStore,
        now_unix_ms: u64,
    ) -> Result<(), TeacherGroupMediaDeliveryError> {
        if self.receivers.contains_key(&receiver) {
            return Err(TeacherGroupMediaDeliveryError::DuplicateReceiver);
        }
        if self.receivers.len() >= self.max_receivers {
            return Err(TeacherGroupMediaDeliveryError::ReceiverLimitExceeded);
        }

        let bound = BoundGroupMediaReceiverSession::bind_client(
            session,
            receiver,
            authorization,
            now_unix_ms,
        )?;

        self.receivers.insert(
            receiver,
            ReceiverDeliverySession {
                connection_stable_id: session.connection.stable_id(),
                control_session_id: bound.control_session_id(),
                protocol_version: session.established.negotiated.version,
                pending_ack: None,
            },
        );
        Ok(())
    }

    pub async fn send_key(
        &mut self,
        receiver: PrincipalId,
        session: &mut ClientControlSession,
        coordinator: &mut GroupMediaCoordinator,
        authorization: &AuthorizationStore,
        request: PresentationKeyGrantRequest,
        now_unix_ms: u64,
    ) -> Result<GroupMediaEpoch, TeacherGroupMediaDeliveryError> {
        let state = self
            .receivers
            .get(&receiver)
            .ok_or(TeacherGroupMediaDeliveryError::ReceiverNotRegistered)?;

        if state.pending_ack.is_some() {
            return Err(TeacherGroupMediaDeliveryError::PendingAckExists);
        }
        if state.connection_stable_id != session.connection.stable_id()
            || state.control_session_id != session.established.control_session_id
            || state.protocol_version != session.established.negotiated.version
        {
            return Err(TeacherGroupMediaDeliveryError::SessionBindingMismatch);
        }

        let bound = BoundGroupMediaReceiverSession::bind_client(
            session,
            receiver,
            authorization,
            now_unix_ms,
        )?;
        if bound.control_session_id() != state.control_session_id {
            return Err(TeacherGroupMediaDeliveryError::SessionBindingMismatch);
        }

        let (sensitive, pending) =
            bound.issue_key_grant(coordinator, authorization, request, now_unix_ms)?;
        let epoch = pending.epoch();
        sensitive.send(&mut session.channel).await?;

        let state = self
            .receivers
            .get_mut(&receiver)
            .ok_or(TeacherGroupMediaDeliveryError::ReceiverNotRegistered)?;
        state.pending_ack = Some(pending);
        Ok(epoch)
    }

    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.receivers.len()
    }

    #[must_use]
    pub fn has_pending_ack(&self, receiver: PrincipalId) -> bool {
        self.receivers
            .get(&receiver)
            .is_some_and(|state| state.pending_ack.is_some())
    }

    pub fn remove_receiver(&mut self, receiver: PrincipalId) -> bool {
        self.receivers.remove(&receiver).is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use classmesh_core::recovery::RecoveryPolicy;
    use classmesh_protocol::control_wire::control_envelope;
    use classmesh_protocol::{Capability, ControlRole, ProtocolVersion};
    use classmesh_security::group_media_coordinator::{
        GroupMediaCoordinator, GroupMediaReceiverInstallState, MAX_GROUP_MEDIA_RECEIVERS,
    };
    use classmesh_security::{
        AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
        PrincipalId, PrincipalKind,
    };
    use quinn::{Connection, Endpoint};
    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use sha2::{Digest, Sha256};
    use zeroize::Zeroize;

    use crate::ControlHello;
    use crate::client_session::{ClientControlSession, connect_client_session_with_retries};
    use crate::group_media_session::PresentationKeyGrantRequest;
    use crate::handshake::{ServerHelloConfig, server_hello};
    use crate::quic::{
        ControlChannel, DEFAULT_IO_TIMEOUT, accept, client_config_with_roots,
        server_config_with_certificate,
    };

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

    const VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 4 };

    struct SessionPair {
        _client_endpoint: Endpoint,
        _server_endpoint: Endpoint,
        _server_connection: Connection,
        server_channel: ControlChannel,
        client: ClientControlSession,
        certificate: CertificateDer<'static>,
    }

    fn principal(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    fn capabilities() -> BTreeSet<Capability> {
        BTreeSet::from([
            Capability::TeacherPresentation,
            Capability::SframeGroupMedia,
        ])
    }

    fn teacher_hello() -> ControlHello {
        ControlHello {
            principal_id: principal(8),
            role: ControlRole::Teacher,
            version: VERSION,
            capabilities: capabilities(),
            hostname: "teacher-test".to_owned(),
            app_version: "0.0.1".to_owned(),
        }
    }

    async fn session_pair(control_session_id: u64) -> TestResult<SessionPair> {
        let certified = generate_simple_self_signed(vec!["classmesh.local".to_owned()])?;
        let certificate = CertificateDer::from(certified.cert);
        let private_key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());

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
            let connection = accept(&server).await.map_err(|error| error.to_string())?;
            let mut channel = ControlChannel::accept(&connection, DEFAULT_IO_TIMEOUT)
                .await
                .map_err(|error| error.to_string())?;
            server_hello(
                &mut channel,
                &ServerHelloConfig {
                    local_version: VERSION,
                    local_capabilities: capabilities(),
                    control_session_id,
                },
            )
            .await
            .map_err(|error| error.to_string())?;

            Ok::<_, String>((server, connection, channel))
        });

        let client = connect_client_session_with_retries(
            &client_endpoint,
            server_address,
            "classmesh.local",
            &teacher_hello(),
            DEFAULT_IO_TIMEOUT,
            RecoveryPolicy {
                max_attempts: 1,
                base_backoff_ms: 1,
                max_backoff_ms: 1,
            },
        )
        .await?;

        let (server_endpoint, server_connection, server_channel) =
            server_task.await.map_err(|error| error.to_string())??;

        Ok(SessionPair {
            _client_endpoint: client_endpoint,
            _server_endpoint: server_endpoint,
            _server_connection: server_connection,
            server_channel,
            client,
            certificate,
        })
    }

    fn authorization(
        receiver: PrincipalId,
        certificates: &[CertificateDer<'static>],
    ) -> AuthorizationStore {
        let mut credentials = BTreeMap::new();
        for certificate in certificates {
            let fingerprint = CredentialFingerprint(Sha256::digest(certificate.as_ref()).into());
            credentials.insert(fingerprint, CredentialRecord::active(fingerprint, 100));
        }

        let mut store = AuthorizationStore::default();
        store
            .upsert(Principal {
                id: receiver,
                kind: PrincipalKind::StudentDevice,
                enabled: true,
                permissions: BTreeSet::from([Permission::ReceivePresentation]),
                credentials,
            })
            .expect("student receiver principal");
        store
    }

    fn coordinator(
        authorization: &AuthorizationStore,
        receiver: PrincipalId,
    ) -> GroupMediaCoordinator {
        let mut coordinator = GroupMediaCoordinator::default();
        coordinator
            .register_receiver(authorization, receiver)
            .expect("receiver should register");
        coordinator.begin_epoch().expect("epoch should start");
        coordinator
    }

    #[test]
    fn delivery_manager_rejects_invalid_receiver_limits() {
        assert!(matches!(
            TeacherGroupMediaDeliveryManager::with_limit(0),
            Err(TeacherGroupMediaDeliveryError::InvalidReceiverLimit)
        ));
        assert!(matches!(
            TeacherGroupMediaDeliveryManager::with_limit(MAX_GROUP_MEDIA_RECEIVERS + 1),
            Err(TeacherGroupMediaDeliveryError::InvalidReceiverLimit)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_receiver_has_one_pending_ack_and_send_uses_registered_connection() -> TestResult {
        let receiver = principal(7);
        let mut pair = session_pair(77).await?;
        let authorization = authorization(receiver, &[pair.certificate.clone()]);
        let mut coordinator = coordinator(&authorization, receiver);
        let mut delivery = TeacherGroupMediaDeliveryManager::with_limit(2)?;

        delivery.register_client_session(&pair.client, receiver, &authorization, 150)?;
        assert_eq!(delivery.receiver_count(), 1);

        let epoch = delivery
            .send_key(
                receiver,
                &mut pair.client,
                &mut coordinator,
                &authorization,
                PresentationKeyGrantRequest::new(55, 7, 44, 2),
                150,
            )
            .await?;
        assert!(delivery.has_pending_ack(receiver));
        assert_eq!(
            coordinator.receiver_state(receiver),
            Some(GroupMediaReceiverInstallState::KeyIssued(epoch))
        );

        let mut received = pair.server_channel.receive().await?;
        let Some(control_envelope::Payload::PresentationKeyGrant(grant)) =
            received.payload.as_mut()
        else {
            return Err("expected PresentationKeyGrant".into());
        };
        assert_eq!(grant.presentation_id, 55);
        assert_eq!(grant.stream_id, 7);
        assert_eq!(grant.epoch, epoch.get());
        assert_eq!(grant.key_material.len(), 32);
        grant.key_material.zeroize();

        assert!(matches!(
            delivery
                .send_key(
                    receiver,
                    &mut pair.client,
                    &mut coordinator,
                    &authorization,
                    PresentationKeyGrantRequest::new(55, 7, 45, 3),
                    150,
                )
                .await,
            Err(TeacherGroupMediaDeliveryError::PendingAckExists)
        ));

        assert!(delivery.remove_receiver(receiver));
        assert_eq!(delivery.receiver_count(), 0);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn same_student_and_control_session_on_another_connection_is_rejected() -> TestResult {
        let receiver = principal(7);
        let first = session_pair(77).await?;
        let mut second = session_pair(77).await?;
        let authorization = authorization(
            receiver,
            &[first.certificate.clone(), second.certificate.clone()],
        );
        let mut coordinator = coordinator(&authorization, receiver);
        let mut delivery = TeacherGroupMediaDeliveryManager::with_limit(2)?;

        delivery.register_client_session(&first.client, receiver, &authorization, 150)?;

        assert!(matches!(
            delivery
                .send_key(
                    receiver,
                    &mut second.client,
                    &mut coordinator,
                    &authorization,
                    PresentationKeyGrantRequest::new(55, 7, 44, 2),
                    150,
                )
                .await,
            Err(TeacherGroupMediaDeliveryError::SessionBindingMismatch)
        ));
        assert_eq!(
            coordinator.receiver_state(receiver),
            Some(GroupMediaReceiverInstallState::AwaitingKey)
        );
        assert!(!delivery.has_pending_ack(receiver));
        Ok(())
    }
}
