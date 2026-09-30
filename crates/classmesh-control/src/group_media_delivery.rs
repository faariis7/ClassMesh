use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;

use classmesh_core::adaptation::{StreamProfile, StreamProfileError};

use classmesh_protocol::ProtocolVersion;
use classmesh_protocol::control_wire::ControlEnvelope;
use classmesh_security::group_media::GroupMediaEpoch;
use classmesh_security::group_media_coordinator::{
    GroupMediaCoordinator, GroupMediaReceiverInstallState, MAX_GROUP_MEDIA_RECEIVERS,
};
use classmesh_security::{AuthorizationStore, PrincipalId};

use crate::authorization::AuthenticatedControlGuard;
use crate::client_session::ClientControlSession;
use crate::group_media_session::{
    BoundGroupMediaReceiverSession, GroupMediaSessionError, PendingPresentationKeyAck,
    PresentationKeyAckError, PresentationKeyGrantRequest,
};
use crate::presentation_fallback::{
    PresentationFallbackChange, PresentationFallbackCoordinator, PresentationFallbackError,
};
use crate::presentation_state::PresentationOwnership;
use crate::quic::ControlTransportError;
use crate::stream::ValidatedPresentationUnicastFallbackOffer;

#[derive(Debug)]
pub enum TeacherGroupMediaDeliveryError {
    InvalidReceiverLimit,
    ReceiverLimitExceeded,
    DuplicateReceiver,
    ReceiverNotRegistered,
    SessionBindingMismatch,
    PendingAckExists,
    MissingPendingAck,
    SenderTarget(PresentationSenderTargetError),
    Fallback(PresentationFallbackError),
    Binding(GroupMediaSessionError),
    Ack(PresentationKeyAckError),
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
            Self::MissingPendingAck => {
                formatter.write_str("Teacher group-media receiver has no pending key ACK")
            }
            Self::SenderTarget(error) => {
                write!(formatter, "Teacher presentation sender target: {error:?}")
            }
            Self::Fallback(error) => {
                write!(formatter, "Teacher presentation fallback: {error:?}")
            }
            Self::Binding(error) => write!(formatter, "Teacher group-media binding: {error}"),
            Self::Ack(error) => write!(formatter, "Teacher group-media ACK: {error}"),
            Self::Transport(error) => write!(formatter, "Teacher group-media transport: {error}"),
        }
    }
}

impl Error for TeacherGroupMediaDeliveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Binding(error) => Some(error),
            Self::Ack(error) => Some(error),
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

impl From<PresentationKeyAckError> for TeacherGroupMediaDeliveryError {
    fn from(value: PresentationKeyAckError) -> Self {
        Self::Ack(value)
    }
}

impl From<ControlTransportError> for TeacherGroupMediaDeliveryError {
    fn from(value: ControlTransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<PresentationFallbackError> for TeacherGroupMediaDeliveryError {
    fn from(value: PresentationFallbackError) -> Self {
        Self::Fallback(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationSenderTargetError {
    MissingActivePresentation,
    InvalidProfile(StreamProfileError),
    StreamMismatch { expected: u32, received: u64 },
    ProfileMismatch,
    InvalidPort,
    FallbackNotEnabled,
    EpochNotActive,
    ReceiverEpochNotInstalled,
}

impl From<StreamProfileError> for PresentationSenderTargetError {
    fn from(value: StreamProfileError) -> Self {
        Self::InvalidProfile(value)
    }
}

impl From<PresentationSenderTargetError> for TeacherGroupMediaDeliveryError {
    fn from(value: PresentationSenderTargetError) -> Self {
        Self::SenderTarget(value)
    }
}

pub struct PresentationUnicastSenderTargetRequest<'a> {
    receiver: PrincipalId,
    session: &'a ClientControlSession,
    now_unix_ms: u64,
    profile: StreamProfile,
    epoch: GroupMediaEpoch,
    offer: &'a ValidatedPresentationUnicastFallbackOffer,
}

impl<'a> PresentationUnicastSenderTargetRequest<'a> {
    #[must_use]
    pub const fn new(
        receiver: PrincipalId,
        session: &'a ClientControlSession,
        now_unix_ms: u64,
        profile: StreamProfile,
        epoch: GroupMediaEpoch,
        offer: &'a ValidatedPresentationUnicastFallbackOffer,
    ) -> Self {
        Self {
            receiver,
            session,
            now_unix_ms,
            profile,
            epoch,
            offer,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationUnicastSenderTarget {
    pub receiver: PrincipalId,
    pub destination: SocketAddr,
    pub presentation_id: u64,
    pub stream_id: u32,
    pub profile: StreamProfile,
    pub epoch: GroupMediaEpoch,
}

pub struct PresentationKeyAckRequest<'a> {
    receiver: PrincipalId,
    session: &'a ClientControlSession,
    envelope: &'a ControlEnvelope,
}

impl<'a> PresentationKeyAckRequest<'a> {
    #[must_use]
    pub const fn new(
        receiver: PrincipalId,
        session: &'a ClientControlSession,
        envelope: &'a ControlEnvelope,
    ) -> Self {
        Self {
            receiver,
            session,
            envelope,
        }
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
        let bound = self.bound_client(receiver, session, authorization, now_unix_ms)?;
        if self
            .receivers
            .get(&receiver)
            .is_some_and(|state| state.pending_ack.is_some())
        {
            return Err(TeacherGroupMediaDeliveryError::PendingAckExists);
        }

        let (sensitive, pending) =
            bound.issue_key_grant(coordinator, authorization, request, now_unix_ms)?;
        let epoch = pending.epoch();

        // Correlate before the first await. A cancelled or ambiguous transport write
        // must leave this receiver fail-closed rather than permitting another issuance.
        self.receivers
            .get_mut(&receiver)
            .expect("receiver binding was validated above")
            .pending_ack = Some(pending);

        sensitive.send(&mut session.channel).await?;
        Ok(epoch)
    }

    pub fn accept_key_ack(
        &mut self,
        request: PresentationKeyAckRequest<'_>,
        guard: &mut AuthenticatedControlGuard,
        authorization: &AuthorizationStore,
        coordinator: &mut GroupMediaCoordinator,
        now_unix_ms: u64,
    ) -> Result<(), TeacherGroupMediaDeliveryError> {
        self.bound_client(
            request.receiver,
            request.session,
            authorization,
            now_unix_ms,
        )?;

        let state = self
            .receivers
            .get_mut(&request.receiver)
            .ok_or(TeacherGroupMediaDeliveryError::ReceiverNotRegistered)?;
        {
            let pending = state
                .pending_ack
                .as_mut()
                .ok_or(TeacherGroupMediaDeliveryError::MissingPendingAck)?;

            // Replay/sequence state is global to the caller-owned authenticated
            // control session; this manager never creates a feature-local counter.
            pending.accept(
                guard,
                authorization,
                coordinator,
                request.envelope,
                now_unix_ms,
            )?;
        }

        state.pending_ack = None;
        Ok(())
    }

    pub(crate) fn validate_registered_client(
        &self,
        receiver: PrincipalId,
        session: &ClientControlSession,
        authorization: &AuthorizationStore,
        now_unix_ms: u64,
    ) -> Result<(), TeacherGroupMediaDeliveryError> {
        self.bound_client(receiver, session, authorization, now_unix_ms)
            .map(|_| ())
    }

    fn bound_client(
        &self,
        receiver: PrincipalId,
        session: &ClientControlSession,
        authorization: &AuthorizationStore,
        now_unix_ms: u64,
    ) -> Result<BoundGroupMediaReceiverSession, TeacherGroupMediaDeliveryError> {
        let state = self
            .receivers
            .get(&receiver)
            .ok_or(TeacherGroupMediaDeliveryError::ReceiverNotRegistered)?;

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

        Ok(bound)
    }

    pub fn request_unicast_fallback(
        &self,
        fallback: &mut PresentationFallbackCoordinator,
        receiver: PrincipalId,
        session: &ClientControlSession,
        authorization: &AuthorizationStore,
        now_unix_ms: u64,
    ) -> Result<PresentationFallbackChange, TeacherGroupMediaDeliveryError> {
        self.validate_registered_client(receiver, session, authorization, now_unix_ms)?;
        fallback
            .request_unicast(receiver, &session.established.negotiated.capabilities)
            .map_err(Into::into)
    }

    pub fn remove_receiver_with_fallback(
        &mut self,
        fallback: &mut PresentationFallbackCoordinator,
        receiver: PrincipalId,
    ) -> bool {
        fallback.restore_multicast(receiver);
        self.remove_receiver(receiver)
    }

    pub fn build_unicast_sender_target(
        &self,
        fallback: &PresentationFallbackCoordinator,
        coordinator: &GroupMediaCoordinator,
        authorization: &AuthorizationStore,
        ownership: &PresentationOwnership,
        request: PresentationUnicastSenderTargetRequest<'_>,
    ) -> Result<PresentationUnicastSenderTarget, TeacherGroupMediaDeliveryError> {
        let owner = ownership
            .owner()
            .ok_or(PresentationSenderTargetError::MissingActivePresentation)?;
        let profile = request
            .profile
            .validate()
            .map_err(PresentationSenderTargetError::from)?;
        let owner_stream_id = u32::try_from(owner.stream_id).map_err(|_| {
            PresentationSenderTargetError::StreamMismatch {
                expected: fallback.stream_id(),
                received: owner.stream_id,
            }
        })?;
        let stream_id = u32::try_from(request.offer.stream_id).map_err(|_| {
            PresentationSenderTargetError::StreamMismatch {
                expected: fallback.stream_id(),
                received: request.offer.stream_id,
            }
        })?;
        if owner_stream_id == 0
            || owner_stream_id != fallback.stream_id()
            || stream_id != owner_stream_id
        {
            return Err(PresentationSenderTargetError::StreamMismatch {
                expected: fallback.stream_id(),
                received: request.offer.stream_id,
            }
            .into());
        }
        if request.offer.profile != profile {
            return Err(PresentationSenderTargetError::ProfileMismatch.into());
        }
        if request.offer.port == 0 {
            return Err(PresentationSenderTargetError::InvalidPort.into());
        }

        self.validate_registered_client(
            request.receiver,
            request.session,
            authorization,
            request.now_unix_ms,
        )?;
        if !fallback.is_unicast_fallback(request.receiver) {
            return Err(PresentationSenderTargetError::FallbackNotEnabled.into());
        }
        if coordinator.active_epoch() != Some(request.epoch) {
            return Err(PresentationSenderTargetError::EpochNotActive.into());
        }
        if coordinator.receiver_state(request.receiver)
            != Some(GroupMediaReceiverInstallState::Installed(request.epoch))
        {
            return Err(PresentationSenderTargetError::ReceiverEpochNotInstalled.into());
        }

        Ok(PresentationUnicastSenderTarget {
            receiver: request.receiver,
            destination: SocketAddr::new(
                request.session.connection.remote_address().ip(),
                request.offer.port,
            ),
            presentation_id: owner.presentation_id,
            stream_id: owner_stream_id,
            profile,
            epoch: request.epoch,
        })
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

    use classmesh_core::adaptation::StreamProfile;
    use classmesh_core::recovery::RecoveryPolicy;
    use classmesh_protocol::control_wire::{
        ControlEnvelope, PresentationKeyAck, ProtocolVersion as WireProtocolVersion,
        control_envelope,
    };
    use classmesh_protocol::feedback::FeedbackMessage;
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
    use crate::authorization::AuthenticatedControlGuard;
    use crate::client_session::{ClientControlSession, connect_client_session_with_retries};
    use crate::group_media_feedback::{
        PresentationFeedbackError, PresentationFeedbackRequest,
        accept_and_coordinate_presentation_feedback, accept_presentation_feedback,
        build_presentation_feedback_envelope,
    };
    use crate::group_media_session::PresentationKeyGrantRequest;
    use crate::handshake::{ServerHelloConfig, server_hello};
    use crate::peer_identity::authenticated_peer_identity;
    use crate::presentation_recovery::{
        PresentationRecoveryCoordinator, PresentationRecoveryOutcome,
    };
    use crate::presentation_state::PresentationOwnership;
    use crate::quic::{
        ControlChannel, DEFAULT_IO_TIMEOUT, accept, client_config_with_roots,
        server_config_with_certificate,
    };
    use crate::stream::ValidatedPresentationUnicastFallbackOffer;

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
            Capability::UdpUnicast,
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

    fn active_ownership(presentation_id: u64, stream_id: u64) -> PresentationOwnership {
        let mut ownership = PresentationOwnership::default();
        ownership
            .start(principal(99), 900, presentation_id, stream_id)
            .expect("presentation ownership starts");
        ownership
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
    async fn authenticated_receiver_fallback_is_session_bound_and_removed_with_delivery_session()
    -> TestResult {
        use crate::presentation_fallback::{
            PresentationFallbackChange, PresentationFallbackCoordinator,
        };

        let receiver = principal(7);
        let pair = session_pair(77).await?;
        let authorization = authorization(receiver, std::slice::from_ref(&pair.certificate));
        let mut delivery = TeacherGroupMediaDeliveryManager::with_limit(2)?;
        delivery.register_client_session(&pair.client, receiver, &authorization, 150)?;
        let mut fallback =
            PresentationFallbackCoordinator::with_limit(7, 1).expect("valid fallback policy");

        assert_eq!(
            delivery.request_unicast_fallback(
                &mut fallback,
                receiver,
                &pair.client,
                &authorization,
                150,
            )?,
            PresentationFallbackChange::Enabled
        );
        assert!(fallback.is_unicast_fallback(receiver));

        assert!(delivery.remove_receiver_with_fallback(&mut fallback, receiver));
        assert_eq!(delivery.receiver_count(), 0);
        assert!(!fallback.is_unicast_fallback(receiver));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn admitted_installed_fallback_builds_peer_bound_unicast_sender_target() -> TestResult {
        use crate::presentation_fallback::PresentationFallbackCoordinator;

        let receiver = principal(7);
        let pair = session_pair(77).await?;
        let authorization = authorization(receiver, std::slice::from_ref(&pair.certificate));
        let mut delivery = TeacherGroupMediaDeliveryManager::with_limit(2)?;
        delivery.register_client_session(&pair.client, receiver, &authorization, 150)?;

        let mut fallback =
            PresentationFallbackCoordinator::with_limit(7, 1).expect("valid fallback policy");
        delivery.request_unicast_fallback(
            &mut fallback,
            receiver,
            &pair.client,
            &authorization,
            150,
        )?;

        let mut coordinator = coordinator(&authorization, receiver);
        let grant = coordinator.issue_key(&authorization, receiver)?;
        let epoch = grant.epoch();
        drop(grant);
        coordinator.mark_installed(&authorization, receiver, epoch)?;

        let ownership = active_ownership(55, 7);
        let profile = StreamProfile::new(1920, 1080, 30, 5_000);
        let offer = ValidatedPresentationUnicastFallbackOffer {
            stream_id: 7,
            profile,
            port: 50_000,
        };
        let target = delivery.build_unicast_sender_target(
            &fallback,
            &coordinator,
            &authorization,
            &ownership,
            PresentationUnicastSenderTargetRequest::new(
                receiver,
                &pair.client,
                150,
                profile,
                epoch,
                &offer,
            ),
        )?;

        assert_eq!(target.receiver, receiver);
        assert_eq!(target.presentation_id, 55);
        assert_eq!(target.stream_id, 7);
        assert_eq!(target.profile, profile);
        assert_eq!(target.epoch, epoch);
        assert_eq!(
            target.destination.ip(),
            pair.client.connection.remote_address().ip()
        );
        assert_eq!(target.destination.port(), 50_000);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unicast_sender_target_rejects_profile_or_install_state_drift() -> TestResult {
        use crate::presentation_fallback::PresentationFallbackCoordinator;

        let receiver = principal(7);
        let pair = session_pair(77).await?;
        let authorization = authorization(receiver, std::slice::from_ref(&pair.certificate));
        let mut delivery = TeacherGroupMediaDeliveryManager::with_limit(2)?;
        delivery.register_client_session(&pair.client, receiver, &authorization, 150)?;

        let mut fallback =
            PresentationFallbackCoordinator::with_limit(7, 1).expect("valid fallback policy");
        delivery.request_unicast_fallback(
            &mut fallback,
            receiver,
            &pair.client,
            &authorization,
            150,
        )?;

        let coordinator = coordinator(&authorization, receiver);
        let epoch = coordinator.active_epoch().expect("active epoch");
        let ownership = active_ownership(55, 7);
        let profile = StreamProfile::new(1920, 1080, 30, 5_000);
        let drifted = ValidatedPresentationUnicastFallbackOffer {
            stream_id: 7,
            profile: StreamProfile::new(1280, 720, 30, 2_500),
            port: 50_000,
        };

        assert!(
            delivery
                .build_unicast_sender_target(
                    &fallback,
                    &coordinator,
                    &authorization,
                    &ownership,
                    PresentationUnicastSenderTargetRequest::new(
                        receiver,
                        &pair.client,
                        150,
                        profile,
                        epoch,
                        &drifted,
                    ),
                )
                .is_err()
        );

        let exact = ValidatedPresentationUnicastFallbackOffer {
            stream_id: 7,
            profile,
            port: 50_000,
        };
        assert!(
            delivery
                .build_unicast_sender_target(
                    &fallback,
                    &coordinator,
                    &authorization,
                    &ownership,
                    PresentationUnicastSenderTargetRequest::new(
                        receiver,
                        &pair.client,
                        150,
                        profile,
                        epoch,
                        &exact,
                    ),
                )
                .is_err(),
            "receiver must install the exact active epoch before sender attachment"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unicast_sender_target_requires_active_presentation_ownership() -> TestResult {
        use crate::presentation_fallback::PresentationFallbackCoordinator;

        let receiver = principal(7);
        let pair = session_pair(77).await?;
        let authorization = authorization(receiver, std::slice::from_ref(&pair.certificate));
        let mut delivery = TeacherGroupMediaDeliveryManager::with_limit(2)?;
        delivery.register_client_session(&pair.client, receiver, &authorization, 150)?;

        let mut fallback =
            PresentationFallbackCoordinator::with_limit(7, 1).expect("valid fallback policy");
        delivery.request_unicast_fallback(
            &mut fallback,
            receiver,
            &pair.client,
            &authorization,
            150,
        )?;

        let mut coordinator = coordinator(&authorization, receiver);
        let grant = coordinator.issue_key(&authorization, receiver)?;
        let epoch = grant.epoch();
        drop(grant);
        coordinator.mark_installed(&authorization, receiver, epoch)?;

        let ownership = PresentationOwnership::default();
        let profile = StreamProfile::new(1920, 1080, 30, 5_000);
        let offer = ValidatedPresentationUnicastFallbackOffer {
            stream_id: 7,
            profile,
            port: 50_000,
        };

        assert!(
            delivery
                .build_unicast_sender_target(
                    &fallback,
                    &coordinator,
                    &authorization,
                    &ownership,
                    PresentationUnicastSenderTargetRequest::new(
                        receiver,
                        &pair.client,
                        150,
                        profile,
                        epoch,
                        &offer,
                    ),
                )
                .is_err(),
            "sender target must derive presentation/stream from active ownership"
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fallback_rejects_same_student_on_another_connection_before_policy_state_changes()
    -> TestResult {
        use crate::presentation_fallback::PresentationFallbackCoordinator;

        let receiver = principal(7);
        let first = session_pair(77).await?;
        let second = session_pair(77).await?;
        let authorization = authorization(
            receiver,
            &[first.certificate.clone(), second.certificate.clone()],
        );
        let mut delivery = TeacherGroupMediaDeliveryManager::with_limit(2)?;
        delivery.register_client_session(&first.client, receiver, &authorization, 150)?;
        let mut fallback =
            PresentationFallbackCoordinator::with_limit(7, 1).expect("valid fallback policy");

        assert!(matches!(
            delivery.request_unicast_fallback(
                &mut fallback,
                receiver,
                &second.client,
                &authorization,
                150,
            ),
            Err(TeacherGroupMediaDeliveryError::SessionBindingMismatch)
        ));
        assert_eq!(fallback.unicast_receiver_count(), 0);
        Ok(())
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_send_keeps_one_pending_ack_fail_closed() -> TestResult {
        let receiver = principal(7);
        let mut pair = session_pair(77).await?;
        let authorization = authorization(receiver, &[pair.certificate.clone()]);
        let mut coordinator = coordinator(&authorization, receiver);
        let mut delivery = TeacherGroupMediaDeliveryManager::with_limit(2)?;

        delivery.register_client_session(&pair.client, receiver, &authorization, 150)?;
        pair._server_connection.close(0u32.into(), b"test shutdown");
        let _ = pair.client.connection.closed().await;

        assert!(matches!(
            delivery
                .send_key(
                    receiver,
                    &mut pair.client,
                    &mut coordinator,
                    &authorization,
                    PresentationKeyGrantRequest::new(55, 7, 44, 2),
                    150,
                )
                .await,
            Err(TeacherGroupMediaDeliveryError::Transport(_))
        ));
        assert!(delivery.has_pending_ack(receiver));
        assert!(matches!(
            coordinator.receiver_state(receiver),
            Some(GroupMediaReceiverInstallState::KeyIssued(_))
        ));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ack_consumes_global_sequence_and_clears_only_on_success() -> TestResult {
        let receiver = principal(7);
        let mut pair = session_pair(77).await?;
        let authorization = authorization(receiver, &[pair.certificate.clone()]);
        let mut coordinator = coordinator(&authorization, receiver);
        let mut delivery = TeacherGroupMediaDeliveryManager::with_limit(2)?;

        delivery.register_client_session(&pair.client, receiver, &authorization, 150)?;
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

        let mut grant_envelope = pair.server_channel.receive().await?;
        let Some(control_envelope::Payload::PresentationKeyGrant(grant)) =
            grant_envelope.payload.as_mut()
        else {
            return Err("expected PresentationKeyGrant".into());
        };
        grant.key_material.zeroize();

        let identity = authenticated_peer_identity(&pair.client.connection, &authorization, 150)
            .map_err(|error| format!("peer identity: {error:?}"))?;
        let mut guard = AuthenticatedControlGuard::new(identity, 77, VERSION, 1);

        let ack = |sequence: u64, request_id: u64| ControlEnvelope {
            control_session_id: 77,
            sequence,
            protocol_version: Some(WireProtocolVersion {
                major: u32::from(VERSION.major),
                minor: u32::from(VERSION.minor),
            }),
            request_id,
            payload: Some(control_envelope::Payload::PresentationKeyAck(
                PresentationKeyAck {
                    presentation_id: 55,
                    stream_id: 7,
                    epoch: epoch.get(),
                },
            )),
        };

        assert!(matches!(
            delivery.accept_key_ack(
                PresentationKeyAckRequest::new(receiver, &pair.client, &ack(2, 999)),
                &mut guard,
                &authorization,
                &mut coordinator,
                150,
            ),
            Err(TeacherGroupMediaDeliveryError::Ack(_))
        ));
        assert_eq!(guard.last_sequence(), 2);
        assert!(delivery.has_pending_ack(receiver));
        assert_eq!(
            coordinator.receiver_state(receiver),
            Some(GroupMediaReceiverInstallState::KeyIssued(epoch))
        );

        delivery.accept_key_ack(
            PresentationKeyAckRequest::new(receiver, &pair.client, &ack(3, 44)),
            &mut guard,
            &authorization,
            &mut coordinator,
            150,
        )?;
        assert_eq!(guard.last_sequence(), 3);
        assert!(!delivery.has_pending_ack(receiver));
        assert_eq!(
            coordinator.receiver_state(receiver),
            Some(GroupMediaReceiverInstallState::Installed(epoch))
        );
        Ok(())
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn presentation_feedback_is_authenticated_sequence_and_stream_bound() -> TestResult {
        let receiver = principal(7);
        let pair = session_pair(77).await?;
        let authorization = authorization(receiver, std::slice::from_ref(&pair.certificate));
        let mut delivery = TeacherGroupMediaDeliveryManager::with_limit(2)?;
        delivery.register_client_session(&pair.client, receiver, &authorization, 150)?;

        let identity = authenticated_peer_identity(&pair.client.connection, &authorization, 150)
            .map_err(|error| format!("peer identity: {error:?}"))?;
        let mut guard = AuthenticatedControlGuard::new(identity, 77, VERSION, 1);

        let feedback = FeedbackMessage::Nack {
            stream_id: 7,
            frame_id: 91,
            missing_packet_indices: vec![1, 4],
        };
        let envelope = build_presentation_feedback_envelope(77, VERSION, 2, &feedback)?;
        let accepted = accept_presentation_feedback(
            &delivery,
            PresentationFeedbackRequest::new(receiver, &pair.client, &envelope, 7),
            &mut guard,
            &authorization,
            150,
        )?;
        assert_eq!(accepted, feedback);
        assert_eq!(guard.last_sequence(), 2);

        let wrong_stream = build_presentation_feedback_envelope(
            77,
            VERSION,
            3,
            &FeedbackMessage::RequestKeyframe {
                stream_id: 8,
                after_frame_id: 91,
            },
        )?;
        assert!(matches!(
            accept_presentation_feedback(
                &delivery,
                PresentationFeedbackRequest::new(receiver, &pair.client, &wrong_stream, 7),
                &mut guard,
                &authorization,
                150,
            ),
            Err(PresentationFeedbackError::StreamMismatch {
                expected: 7,
                received: 8,
            })
        ));
        assert_eq!(guard.last_sequence(), 3);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authenticated_feedback_enters_one_stream_wide_recovery_throttle() -> TestResult {
        let receiver = principal(7);
        let pair = session_pair(77).await?;
        let authorization = authorization(receiver, std::slice::from_ref(&pair.certificate));
        let mut delivery = TeacherGroupMediaDeliveryManager::with_limit(2)?;
        delivery.register_client_session(&pair.client, receiver, &authorization, 150)?;

        let identity = authenticated_peer_identity(&pair.client.connection, &authorization, 150)
            .map_err(|error| format!("peer identity: {error:?}"))?;
        let mut guard = AuthenticatedControlGuard::new(identity, 77, VERSION, 1);
        let mut recovery =
            PresentationRecoveryCoordinator::new(7, 250_000).expect("valid recovery coordinator");

        let nack = build_presentation_feedback_envelope(
            77,
            VERSION,
            2,
            &FeedbackMessage::Nack {
                stream_id: 7,
                frame_id: 90,
                missing_packet_indices: vec![1, 4],
            },
        )?;
        assert_eq!(
            accept_and_coordinate_presentation_feedback(
                &delivery,
                PresentationFeedbackRequest::new(receiver, &pair.client, &nack, 7),
                &mut guard,
                &authorization,
                150,
                &mut recovery,
                1_000_000,
            )?,
            PresentationRecoveryOutcome::NackObserved {
                frame_id: 90,
                missing_packets: 2,
            }
        );
        assert_eq!(recovery.granted_keyframes(), 0);

        let first = build_presentation_feedback_envelope(
            77,
            VERSION,
            3,
            &FeedbackMessage::RequestKeyframe {
                stream_id: 7,
                after_frame_id: 91,
            },
        )?;
        assert_eq!(
            accept_and_coordinate_presentation_feedback(
                &delivery,
                PresentationFeedbackRequest::new(receiver, &pair.client, &first, 7),
                &mut guard,
                &authorization,
                150,
                &mut recovery,
                1_010_000,
            )?,
            PresentationRecoveryOutcome::KeyframeGranted { after_frame_id: 91 }
        );

        let simultaneous = build_presentation_feedback_envelope(
            77,
            VERSION,
            4,
            &FeedbackMessage::RequestKeyframe {
                stream_id: 7,
                after_frame_id: 92,
            },
        )?;
        assert_eq!(
            accept_and_coordinate_presentation_feedback(
                &delivery,
                PresentationFeedbackRequest::new(receiver, &pair.client, &simultaneous, 7),
                &mut guard,
                &authorization,
                150,
                &mut recovery,
                1_020_000,
            )?,
            PresentationRecoveryOutcome::KeyframeSuppressed { after_frame_id: 92 }
        );
        assert_eq!(recovery.granted_keyframes(), 1);
        assert_eq!(recovery.suppressed_keyframes(), 1);
        assert_eq!(guard.last_sequence(), 4);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn presentation_feedback_rejects_same_student_on_another_connection_before_replay_state()
    -> TestResult {
        let receiver = principal(7);
        let first = session_pair(77).await?;
        let second = session_pair(77).await?;
        let authorization = authorization(
            receiver,
            &[first.certificate.clone(), second.certificate.clone()],
        );
        let mut delivery = TeacherGroupMediaDeliveryManager::with_limit(2)?;
        delivery.register_client_session(&first.client, receiver, &authorization, 150)?;

        let identity = authenticated_peer_identity(&second.client.connection, &authorization, 150)
            .map_err(|error| format!("peer identity: {error:?}"))?;
        let mut guard = AuthenticatedControlGuard::new(identity, 77, VERSION, 1);
        let envelope = build_presentation_feedback_envelope(
            77,
            VERSION,
            2,
            &FeedbackMessage::RequestKeyframe {
                stream_id: 7,
                after_frame_id: 91,
            },
        )?;

        assert!(matches!(
            accept_presentation_feedback(
                &delivery,
                PresentationFeedbackRequest::new(receiver, &second.client, &envelope, 7),
                &mut guard,
                &authorization,
                150,
            ),
            Err(PresentationFeedbackError::Delivery(
                TeacherGroupMediaDeliveryError::SessionBindingMismatch
            ))
        ));
        assert_eq!(guard.last_sequence(), 1);
        Ok(())
    }
}
