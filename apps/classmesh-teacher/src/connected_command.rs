//! Authenticated Teacher interaction send path over the already-owned QUIC session.
//! No new listener, credentials, enrollment, or concurrent control-channel reader.

use std::sync::mpsc::{Receiver, TryRecvError};

use classmesh_control::NegotiatedHello;
use classmesh_control::client_session::ClientControlSession;
use classmesh_control::handshake::EstablishedControlSession;
use classmesh_control::live_authorization::{LiveAuthorizationError, LiveAuthorizationStore};
use classmesh_control::peer_identity::{PeerIdentityError, authenticated_peer_identity};
use classmesh_control::quic::{ControlChannel, ControlSendHalf, ControlTransportError};
use classmesh_protocol::control_wire::TeacherInteractionKind;
use classmesh_protocol::control_wire::{
    ControlEnvelope, ProtocolVersion as WireVersion, control_envelope,
};
use classmesh_protocol::teacher_interaction::{self, TeacherInteractionError};
use classmesh_protocol::{ControlRole, teacher_interaction::TEACHER_INTERACTION_MIN_VERSION};
use classmesh_security::{PrincipalId, PrincipalKind};
use classmesh_video::monitoring_scheduler::MonitoringSourceId;
use quinn::Connection;

use crate::receiver_playback_diagnostics::TeacherPlaybackBinding;
use crate::receiver_playback_session::TeacherPlaybackSessionOwner;
use crate::ui_shell::{TeacherInteractionUiAction, TeacherUiAction};

/// No local GUI snapshot grants permission. The active enrolled QUIC peer,
/// live authorization snapshot and Service remain the trust authorities.
#[derive(Debug)]
pub enum TeacherCommandSendError {
    Retired,
    SourceMismatch,
    SessionMismatch,
    RouteChanged,
    WrongRole,
    InvalidCounters,
    InvalidRequest(TeacherInteractionError),
    CapabilityUnavailable,
    Authorization(LiveAuthorizationError),
    PeerIdentity(PeerIdentityError),
    UnauthorizedPeer,
    Transport(ControlTransportError),
}

fn prepare_teacher_interaction(
    owner: &TeacherPlaybackSessionOwner,
    negotiated: &NegotiatedHello,
    action: &TeacherInteractionUiAction,
    sequence: u64,
    request_id: u64,
) -> Result<ControlEnvelope, TeacherCommandSendError> {
    if !owner.is_active() {
        return Err(TeacherCommandSendError::Retired);
    }
    if owner.source_id() != action.source_id {
        return Err(TeacherCommandSendError::SourceMismatch);
    }
    if owner.binding().control_session_id == 0
        || owner.binding().control_session_id != action.control_session_id
    {
        return Err(TeacherCommandSendError::SessionMismatch);
    }
    if negotiated.role != ControlRole::Teacher {
        return Err(TeacherCommandSendError::WrongRole);
    }
    if sequence == 0 || request_id == 0 {
        return Err(TeacherCommandSendError::InvalidCounters);
    }
    let kind = teacher_interaction::validate_request(&action.request)
        .map_err(TeacherCommandSendError::InvalidRequest)?;
    let version = negotiated.version;
    if version.major != TEACHER_INTERACTION_MIN_VERSION.major
        || version.minor < TEACHER_INTERACTION_MIN_VERSION.minor
    {
        return Err(TeacherCommandSendError::CapabilityUnavailable);
    }
    let available = match kind {
        TeacherInteractionKind::Message => {
            teacher_interaction::teacher_message_available(version, &negotiated.capabilities)
        }
        TeacherInteractionKind::OpenTarget => {
            teacher_interaction::open_target_available(version, &negotiated.capabilities)
        }
        TeacherInteractionKind::Unspecified => false,
    };
    if !available {
        return Err(TeacherCommandSendError::CapabilityUnavailable);
    }
    Ok(ControlEnvelope {
        control_session_id: owner.binding().control_session_id,
        sequence,
        request_id,
        protocol_version: Some(WireVersion {
            major: u32::from(version.major),
            minor: u32::from(version.minor),
        }),
        payload: Some(control_envelope::Payload::TeacherInteractionRequest(
            action.request.clone(),
        )),
    })
}

pub(crate) fn verify_current_student(
    owner: &TeacherPlaybackSessionOwner,
    connection: &Connection,
    authorization: &LiveAuthorizationStore,
    now_ms: u64,
) -> Result<(), TeacherCommandSendError> {
    let snapshot = authorization
        .snapshot()
        .map_err(TeacherCommandSendError::Authorization)?;
    let peer = authenticated_peer_identity(connection, snapshot.store(), now_ms)
        .map_err(TeacherCommandSendError::PeerIdentity)?;
    if peer.principal_id() != owner.expected_student()
        || snapshot
            .store()
            .principal(peer.principal_id())
            .map(|p| p.kind)
            != Some(PrincipalKind::StudentDevice)
    {
        return Err(TeacherCommandSendError::UnauthorizedPeer);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TeacherCommandRoute {
    expected_student: PrincipalId,
    source_id: MonitoringSourceId,
    binding: TeacherPlaybackBinding,
    teacher_principal: PrincipalId,
    connection_id: usize,
}

/// Per-session outgoing sequence ledger: never replay or retry an ambiguous send.
/// The channel is exclusively borrowed; the caller must arbitrate the same
/// single incoming QUIC reader and must NOT spawn another one.
#[derive(Debug)]
pub struct TeacherCommandSender {
    next_sequence: u64,
    next_request_id: u64,
    bound: Option<TeacherCommandRoute>,
    retired: bool,
}

impl Default for TeacherCommandSender {
    fn default() -> Self {
        Self {
            next_sequence: 1,
            next_request_id: 1,
            bound: None,
            retired: false,
        }
    }
}

enum TeacherWriter<'a> {
    Whole(&'a mut ControlChannel),
    Half(&'a mut ControlSendHalf),
}

impl TeacherWriter<'_> {
    async fn send(&mut self, envelope: &ControlEnvelope) -> Result<(), ControlTransportError> {
        match self {
            Self::Whole(channel) => channel.send(envelope).await,
            Self::Half(channel) => channel.send(envelope).await,
        }
    }
}

impl TeacherCommandSender {
    fn ensure_route(&mut self, route: TeacherCommandRoute) -> Result<(), TeacherCommandSendError> {
        if self.retired {
            return Err(TeacherCommandSendError::Retired);
        }
        if self.bound.is_some_and(|old| old != route) {
            self.retired = true;
            return Err(TeacherCommandSendError::RouteChanged);
        }
        self.bound = Some(route);
        Ok(())
    }

    /// Send a validated action to the actual enrolled StudentDevice over the
    /// *existing* authenticated QUIC control channel. The server separately
    /// enforces current Teacher permission and Worker process ownership.
    /// This is an opt-in runtime API, NOT a new GUI startup/enrollment path.
    /// Send using an unsplit already-authenticated session (legacy callers).
    pub async fn send(
        &mut self,
        owner: &TeacherPlaybackSessionOwner,
        session: &mut ClientControlSession,
        authorization: &LiveAuthorizationStore,
        action: &TeacherInteractionUiAction,
        now_ms: impl Fn() -> u64,
    ) -> Result<u64, TeacherCommandSendError> {
        self.send_over(
            owner,
            (&session.connection, &session.established),
            TeacherWriter::Whole(&mut session.channel),
            authorization,
            action,
            now_ms,
        )
        .await
    }

    /// Send over the *same* post-Hello authenticated QUIC stream while its
    /// single verified receive half remains pending in a separate owner.
    /// The caller must retire both halves on terminal read/write failure.
    pub async fn send_on_split(
        &mut self,
        owner: &TeacherPlaybackSessionOwner,
        session: (&Connection, &EstablishedControlSession),
        sender: &mut ControlSendHalf,
        authorization: &LiveAuthorizationStore,
        action: &TeacherInteractionUiAction,
        now_ms: impl Fn() -> u64,
    ) -> Result<u64, TeacherCommandSendError> {
        self.send_over(
            owner,
            session,
            TeacherWriter::Half(sender),
            authorization,
            action,
            now_ms,
        )
        .await
    }

    async fn send_over(
        &mut self,
        owner: &TeacherPlaybackSessionOwner,
        session: (&Connection, &EstablishedControlSession),
        mut writer: TeacherWriter<'_>,
        authorization: &LiveAuthorizationStore,
        action: &TeacherInteractionUiAction,
        now_ms: impl Fn() -> u64,
    ) -> Result<u64, TeacherCommandSendError> {
        let (connection, established) = session;
        if self.retired {
            return Err(TeacherCommandSendError::Retired);
        }
        if established.control_session_id != owner.binding().control_session_id {
            self.retire(connection);
            return Err(TeacherCommandSendError::SessionMismatch);
        }
        let frame = prepare_teacher_interaction(
            owner,
            &established.negotiated,
            action,
            self.next_sequence,
            self.next_request_id,
        )?;
        let (Some(next_sequence), Some(next_request_id)) = (
            self.next_sequence.checked_add(1),
            self.next_request_id.checked_add(1),
        ) else {
            self.retire(connection);
            return Err(TeacherCommandSendError::InvalidCounters);
        };
        if let Err(error) = verify_current_student(owner, connection, authorization, now_ms()) {
            self.retire(connection);
            return Err(error);
        }
        let route = TeacherCommandRoute {
            expected_student: owner.expected_student(),
            source_id: owner.source_id(),
            binding: owner.binding(),
            teacher_principal: established.negotiated.principal_id,
            connection_id: connection.stable_id(),
        };
        if let Err(error) = self.ensure_route(route) {
            self.retire(connection);
            return Err(error);
        }
        // Reserve both identifiers *before* the network write. A partial write
        // can never be retried on this session with the same sequence/request.
        self.next_sequence = next_sequence;
        self.next_request_id = next_request_id;
        if let Err(error) = writer.send(&frame).await {
            self.retire(connection);
            return Err(TeacherCommandSendError::Transport(error));
        }
        if let Err(error) = verify_current_student(owner, connection, authorization, now_ms()) {
            self.retire(connection);
            return Err(error);
        }
        Ok(frame.request_id)
    }

    fn retire(&mut self, connection: &Connection) {
        self.retired = true;
        connection.close(0u32.into(), b"teacher command session retired");
    }
}

/// A one-shot, non-blocking transfer from the native UI's bounded action
/// mailbox to the authenticated session's *existing* QUIC owner. Non-network
/// actions are returned unchanged for the central dispatcher; no second
/// network reader or local source of authority is created here.
#[derive(Debug)]
pub enum QueuedTeacherUiAction {
    Empty,
    Closed,
    Local(TeacherUiAction),
    Interaction(TeacherInteractionUiAction),
}

pub fn next_queued_teacher_ui_action(actions: &Receiver<TeacherUiAction>) -> QueuedTeacherUiAction {
    match actions.try_recv() {
        Ok(TeacherUiAction::TeacherInteraction(action)) => {
            QueuedTeacherUiAction::Interaction(action)
        }
        Ok(action) => QueuedTeacherUiAction::Local(action),
        Err(TryRecvError::Empty) => QueuedTeacherUiAction::Empty,
        Err(TryRecvError::Disconnected) => QueuedTeacherUiAction::Closed,
    }
}

/// `Written` means only that the authenticated QUIC send completed, not that
/// the Student Service accepted or executed the request. Its authoritative
/// acknowledgement must be correlated by the sole incoming reader.
#[derive(Debug)]
pub enum TeacherUiCommandDispatch {
    Empty,
    Closed,
    Local(TeacherUiAction),
    Written(u64),
}

/// Call only from the owner of the authenticated client session between
/// reads; never concurrently with a second session reader. Invalid or stale
/// requests are rejected by `TeacherCommandSender`, and failed writes cannot
/// be requeued or retried under an ambiguous sequence number.
pub async fn dispatch_next_queued_teacher_ui_action(
    actions: &Receiver<TeacherUiAction>,
    owner: &TeacherPlaybackSessionOwner,
    session: &mut ClientControlSession,
    authorization: &LiveAuthorizationStore,
    sender: &mut TeacherCommandSender,
    now_ms: impl Fn() -> u64,
) -> Result<TeacherUiCommandDispatch, TeacherCommandSendError> {
    match next_queued_teacher_ui_action(actions) {
        QueuedTeacherUiAction::Empty => Ok(TeacherUiCommandDispatch::Empty),
        QueuedTeacherUiAction::Closed => Ok(TeacherUiCommandDispatch::Closed),
        QueuedTeacherUiAction::Local(action) => Ok(TeacherUiCommandDispatch::Local(action)),
        QueuedTeacherUiAction::Interaction(action) => sender
            .send(owner, session, authorization, &action, now_ms)
            .await
            .map(TeacherUiCommandDispatch::Written),
    }
}

#[cfg(test)]
mod queued_ui_action_tests {
    use super::*;
    use crate::ui_shell::{TeacherInteractionUiAction, TeacherUiAction};
    use classmesh_protocol::control_wire::{
        TeacherInteractionRequest, TeacherMessage, teacher_interaction_request,
    };
    use std::sync::mpsc::sync_channel;

    #[test]
    fn queued_ui_actions_are_delivered_once_and_non_network_intents_are_preserved() {
        let (tx, rx) = sync_channel(2);
        assert!(matches!(
            next_queued_teacher_ui_action(&rx),
            QueuedTeacherUiAction::Empty
        ));
        tx.try_send(TeacherUiAction::SelectDevice(Some(MonitoringSourceId(7))))
            .unwrap();
        assert!(matches!(
            next_queued_teacher_ui_action(&rx),
            QueuedTeacherUiAction::Local(TeacherUiAction::SelectDevice(Some(MonitoringSourceId(
                7
            ))))
        ));
        let interaction = TeacherInteractionUiAction {
            source_id: MonitoringSourceId(7),
            control_session_id: 55,
            request: TeacherInteractionRequest {
                action: Some(teacher_interaction_request::Action::Message(
                    TeacherMessage {
                        text_utf8: "Classroom message".to_owned(),
                    },
                )),
            },
        };
        tx.try_send(TeacherUiAction::TeacherInteraction(interaction.clone()))
            .unwrap();
        match next_queued_teacher_ui_action(&rx) {
            QueuedTeacherUiAction::Interaction(received) => assert_eq!(received, interaction),
            other => panic!("expected exact session-bound interaction; got {other:?}"),
        }
        assert!(matches!(
            next_queued_teacher_ui_action(&rx),
            QueuedTeacherUiAction::Empty
        ));
        drop(tx);
        assert!(matches!(
            next_queued_teacher_ui_action(&rx),
            QueuedTeacherUiAction::Closed
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receiver_playback_diagnostics::TeacherPlaybackBinding;
    use crate::receiver_playback_session::TeacherPlaybackSessionOwner;
    use crate::ui_shell::TeacherInteractionUiAction;
    use classmesh_control::NegotiatedHello;
    use classmesh_protocol::control_wire::{
        TeacherInteractionRequest, TeacherMessage, control_envelope, teacher_interaction_request,
    };
    use classmesh_protocol::{Capability, ControlRole, ProtocolVersion};
    use classmesh_security::PrincipalId;
    use classmesh_video::monitoring_scheduler::MonitoringSourceId;
    use std::collections::BTreeSet;

    const SOURCE: MonitoringSourceId = MonitoringSourceId(7);
    const STUDENT: PrincipalId = PrincipalId([7; 32]);
    const SESSION: u64 = 55;

    fn owner() -> TeacherPlaybackSessionOwner {
        TeacherPlaybackSessionOwner::new(
            STUDENT,
            SOURCE,
            TeacherPlaybackBinding {
                control_session_id: SESSION,
                presentation_id: 2,
                stream_id: 3,
                epoch: 4,
            },
        )
        .unwrap()
    }

    fn negotiated() -> NegotiatedHello {
        NegotiatedHello {
            principal_id: PrincipalId([8; 32]),
            role: ControlRole::Teacher,
            version: ProtocolVersion { major: 0, minor: 8 },
            capabilities: BTreeSet::from([Capability::TeacherMessage]),
        }
    }

    fn action() -> TeacherInteractionUiAction {
        TeacherInteractionUiAction {
            source_id: SOURCE,
            control_session_id: SESSION,
            request: TeacherInteractionRequest {
                action: Some(teacher_interaction_request::Action::Message(
                    TeacherMessage {
                        text_utf8: "Classroom message".into(),
                    },
                )),
            },
        }
    }

    #[test]
    fn bound_teacher_action_produces_exact_wire_contract() {
        let frame = prepare_teacher_interaction(&owner(), &negotiated(), &action(), 1, 9).unwrap();
        assert_eq!(frame.control_session_id, SESSION);
        assert_eq!(frame.sequence, 1);
        assert_eq!(frame.request_id, 9);
        assert_eq!(frame.protocol_version.unwrap().minor, 8);
        assert!(matches!(
            frame.payload,
            Some(control_envelope::Payload::TeacherInteractionRequest(_))
        ));
    }

    #[test]
    fn stale_source_session_role_and_capability_are_refused() {
        let o = owner();
        let n = negotiated();
        let a = action();
        let mut wrong_source = a.clone();
        wrong_source.source_id = MonitoringSourceId(9);
        assert!(matches!(
            prepare_teacher_interaction(&o, &n, &wrong_source, 1, 1),
            Err(TeacherCommandSendError::SourceMismatch)
        ));
        let mut wrong_session = a.clone();
        wrong_session.control_session_id = SESSION + 1;
        assert!(matches!(
            prepare_teacher_interaction(&o, &n, &wrong_session, 1, 1),
            Err(TeacherCommandSendError::SessionMismatch)
        ));
        let mut wrong_role = n.clone();
        wrong_role.role = ControlRole::StudentDevice;
        assert!(matches!(
            prepare_teacher_interaction(&o, &wrong_role, &a, 1, 1),
            Err(TeacherCommandSendError::WrongRole)
        ));
        let mut missing_cap = n.clone();
        missing_cap.capabilities.clear();
        assert!(matches!(
            prepare_teacher_interaction(&o, &missing_cap, &a, 1, 1),
            Err(TeacherCommandSendError::CapabilityUnavailable)
        ));
    }

    #[test]
    fn sender_retirement_rejects_stale_connection_or_roster_route() {
        let mut sender = TeacherCommandSender::default();
        let route = TeacherCommandRoute {
            expected_student: STUDENT,
            source_id: SOURCE,
            binding: owner().binding(),
            teacher_principal: PrincipalId([8; 32]),
            connection_id: 4,
        };
        assert!(sender.ensure_route(route).is_ok());
        assert!(sender.ensure_route(route).is_ok());
        let replacement = TeacherCommandRoute {
            connection_id: 5,
            ..route
        };
        assert!(matches!(
            sender.ensure_route(replacement),
            Err(TeacherCommandSendError::RouteChanged)
        ));
        assert!(matches!(
            sender.ensure_route(route),
            Err(TeacherCommandSendError::Retired)
        ));
    }

    #[test]
    fn invalid_or_replayed_message_must_not_leave_a_sendable_envelope() {
        let o = owner();
        let n = negotiated();
        let mut a = action();
        a.request.action = None;
        assert!(matches!(
            prepare_teacher_interaction(&o, &n, &a, 1, 1),
            Err(TeacherCommandSendError::InvalidRequest(_))
        ));
        assert!(matches!(
            prepare_teacher_interaction(&o, &n, &action(), 0, 1),
            Err(TeacherCommandSendError::InvalidCounters)
        ));
        assert!(matches!(
            prepare_teacher_interaction(&o, &n, &action(), 1, 0),
            Err(TeacherCommandSendError::InvalidCounters)
        ));
        let mut retired = owner();
        assert!(retired.retire_exact(SOURCE, retired.binding()));
        assert!(matches!(
            prepare_teacher_interaction(&retired, &n, &action(), 1, 1),
            Err(TeacherCommandSendError::Retired)
        ));
    }
}

#[cfg(test)]
mod authenticated_quic_tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::error::Error;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use classmesh_control::ControlHello;
    use classmesh_control::client_session::connect_client_session_with_retries;
    use classmesh_control::handshake::{ServerHelloConfig, server_hello};
    use classmesh_control::live_authorization::LiveAuthorizationStore;
    use classmesh_control::quic::{
        ControlChannel, DEFAULT_IO_TIMEOUT, accept, enrolled_client_config, enrolled_server_config,
    };
    use classmesh_control::teacher_playback_receive::{
        AuthenticatedTeacherReceiveError, TeacherControlSequenceGuard,
        receive_guarded_authenticated_teacher_control_on_split,
    };
    use classmesh_core::recovery::RecoveryPolicy;
    use classmesh_protocol::control_wire::{
        TeacherInteractionRequest, TeacherMessage, control_envelope, teacher_interaction_request,
    };
    use classmesh_protocol::{Capability, ControlRole, ProtocolVersion};
    use classmesh_security::{
        AuthorizationStore, CredentialFingerprint, CredentialRecord, Principal, PrincipalId,
        PrincipalKind,
    };
    use classmesh_video::monitoring_scheduler::MonitoringSourceId;
    use quinn::Endpoint;
    use rcgen::generate_simple_self_signed;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls::sign::{CertifiedKey, SingleCertAndKey};
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::receiver_playback_diagnostics::TeacherPlaybackBinding;
    use crate::receiver_playback_session::TeacherPlaybackSessionOwner;
    use crate::ui_shell::TeacherInteractionUiAction;

    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;
    const STUDENT: PrincipalId = PrincipalId([7; 32]);
    const SESSION: u64 = 55;
    const SOURCE: MonitoringSourceId = MonitoringSourceId(7);
    const VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 8 };

    fn action(source: MonitoringSourceId) -> TeacherInteractionUiAction {
        TeacherInteractionUiAction {
            source_id: source,
            control_session_id: SESSION,
            request: TeacherInteractionRequest {
                action: Some(teacher_interaction_request::Action::Message(
                    TeacherMessage {
                        text_utf8: "Hello classroom".to_owned(),
                    },
                )),
            },
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_enrolled_quic_sender_preserves_source_sequence_and_revocation() -> TestResult {
        let server_identity = generate_simple_self_signed(vec!["classmesh.local".to_owned()])?;
        let server_cert = CertificateDer::from(server_identity.cert);
        let server_key = PrivatePkcs8KeyDer::from(server_identity.signing_key.serialize_der());
        let client_identity = generate_simple_self_signed(vec!["teacher.classmesh".to_owned()])?;
        let client_cert = CertificateDer::from(client_identity.cert);
        let client_key = PrivatePkcs8KeyDer::from(client_identity.signing_key.serialize_der());

        let mut client_roots = RootCertStore::empty();
        client_roots.add(client_cert.clone())?;
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(client_roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()?;
        let server = Endpoint::server(
            enrolled_server_config(vec![server_cert.clone()], server_key.into(), verifier)?,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )?;
        let address = server.local_addr()?;

        let mut roots = RootCertStore::empty();
        roots.add(server_cert.clone())?;
        let certified_key = CertifiedKey::from_der(
            vec![client_cert],
            client_key.into(),
            &rustls::crypto::ring::default_provider(),
        )?;
        let mut client = Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        client.set_default_client_config(enrolled_client_config(
            roots,
            Arc::new(SingleCertAndKey::from(certified_key)),
        )?);

        let fingerprint = CredentialFingerprint(Sha256::digest(server_cert.as_ref()).into());
        let mut credentials = BTreeMap::new();
        credentials.insert(fingerprint, CredentialRecord::active(fingerprint, 100));
        let mut store = AuthorizationStore::default();
        store
            .upsert(Principal {
                id: STUDENT,
                kind: PrincipalKind::StudentDevice,
                enabled: true,
                permissions: BTreeSet::new(),
                credentials,
            })
            .map_err(|error| format!("{error:?}"))?;
        let live_auth = LiveAuthorizationStore::new(store);
        let negotiated = BTreeSet::from([Capability::TeacherMessage]);
        let server_task = tokio::spawn(async move {
            let conn = accept(&server).await.map_err(|e| e.to_string())?;
            let mut channel = ControlChannel::accept(&conn, DEFAULT_IO_TIMEOUT)
                .await
                .map_err(|e| e.to_string())?;
            server_hello(
                &mut channel,
                &ServerHelloConfig {
                    local_version: VERSION,
                    local_capabilities: negotiated,
                    control_session_id: SESSION,
                },
            )
            .await
            .map_err(|e| e.to_string())?;
            let first = channel.receive().await.map_err(|e| e.to_string())?;
            // Do not reply until the second outbound command arrives. This
            // forces a single in-flight verified receive while send proceeds.
            let second = channel.receive().await.map_err(|e| e.to_string())?;
            channel
                .send(&ControlEnvelope {
                    control_session_id: SESSION,
                    sequence: 7,
                    request_id: 7,
                    protocol_version: Some(WireVersion { major: 0, minor: 8 }),
                    payload: Some(control_envelope::Payload::Heartbeat(
                        classmesh_protocol::control_wire::Heartbeat {
                            monotonic_time_us: 7,
                            control_session_id: SESSION,
                            media: 1,
                        },
                    )),
                })
                .await
                .map_err(|e| e.to_string())?;
            channel
                .send(&ControlEnvelope {
                    control_session_id: SESSION,
                    sequence: 7,
                    request_id: 7,
                    protocol_version: Some(WireVersion { major: 0, minor: 8 }),
                    payload: Some(control_envelope::Payload::Heartbeat(
                        classmesh_protocol::control_wire::Heartbeat {
                            monotonic_time_us: 7,
                            control_session_id: SESSION,
                            media: 1,
                        },
                    )),
                })
                .await
                .map_err(|e| e.to_string())?;
            Ok::<_, String>((server, conn, first, second))
        });

        let mut session = connect_client_session_with_retries(
            &client,
            address,
            "classmesh.local",
            &ControlHello {
                principal_id: PrincipalId([8; 32]),
                role: ControlRole::Teacher,
                version: VERSION,
                capabilities: BTreeSet::from([Capability::TeacherMessage]),
                hostname: "teacher-native-connection".to_owned(),
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
        let owner = TeacherPlaybackSessionOwner::new(
            STUDENT,
            SOURCE,
            TeacherPlaybackBinding {
                control_session_id: SESSION,
                presentation_id: 2,
                stream_id: 3,
                epoch: 4,
            },
        )
        .map_err(|e| format!("{e:?}"))?;
        let mut sender = TeacherCommandSender::default();

        assert!(matches!(
            sender
                .send(
                    &owner,
                    &mut session,
                    &live_auth,
                    &action(MonitoringSourceId(9)),
                    || 150
                )
                .await,
            Err(TeacherCommandSendError::SourceMismatch)
        ));
        let (ui_sender, ui_actions) = std::sync::mpsc::sync_channel(2);
        assert!(matches!(
            dispatch_next_queued_teacher_ui_action(
                &ui_actions,
                &owner,
                &mut session,
                &live_auth,
                &mut sender,
                || 150
            )
            .await
            .map_err(|e| format!("{e:?}"))?,
            TeacherUiCommandDispatch::Empty
        ));
        ui_sender.try_send(TeacherUiAction::SelectDevice(Some(SOURCE)))?;
        assert!(matches!(
            dispatch_next_queued_teacher_ui_action(
                &ui_actions,
                &owner,
                &mut session,
                &live_auth,
                &mut sender,
                || 150
            )
            .await
            .map_err(|e| format!("{e:?}"))?,
            TeacherUiCommandDispatch::Local(TeacherUiAction::SelectDevice(Some(SOURCE)))
        ));
        ui_sender.try_send(TeacherUiAction::TeacherInteraction(action(SOURCE)))?;
        assert!(matches!(
            dispatch_next_queued_teacher_ui_action(
                &ui_actions,
                &owner,
                &mut session,
                &live_auth,
                &mut sender,
                || 150
            )
            .await
            .map_err(|e| format!("{e:?}"))?,
            TeacherUiCommandDispatch::Written(1)
        ));
        let mut split = session.into_split();
        let mut receive_guard = TeacherControlSequenceGuard::default();
        let bound_action = action(SOURCE);
        let (write, read) = tokio::join!(
            sender.send_on_split(
                &owner,
                (&split.connection, &split.established),
                &mut split.sender,
                &live_auth,
                &bound_action,
                || 150
            ),
            receive_guarded_authenticated_teacher_control_on_split(
                &split.connection,
                &split.established,
                &mut split.receiver,
                &live_auth,
                STUDENT,
                || 150,
                &mut receive_guard
            ),
        );
        assert_eq!(write.map_err(|e| format!("{e:?}"))?, 2);
        let verified = read.map_err(|e| format!("{e:?}"))?;
        assert!(verified.receiver_playback().is_none());
        assert!(matches!(
            verified.envelope().payload,
            Some(control_envelope::Payload::Heartbeat(_))
        ));
        assert!(matches!(
            receive_guarded_authenticated_teacher_control_on_split(
                &split.connection,
                &split.established,
                &mut split.receiver,
                &live_auth,
                STUDENT,
                || 150,
                &mut receive_guard
            )
            .await,
            Err(AuthenticatedTeacherReceiveError::ReplayedSequence)
        ));
        let (server, server_conn, first, second) = server_task.await??;
        assert_eq!(
            (first.sequence, first.request_id, first.control_session_id),
            (1, 1, SESSION)
        );
        assert_eq!(
            (
                second.sequence,
                second.request_id,
                second.control_session_id
            ),
            (2, 2, SESSION)
        );
        assert!(matches!(
            first.payload,
            Some(control_envelope::Payload::TeacherInteractionRequest(_))
        ));
        assert!(matches!(
            second.payload,
            Some(control_envelope::Payload::TeacherInteractionRequest(_))
        ));

        let generation = live_auth
            .snapshot()
            .map_err(|e| format!("{e:?}"))?
            .version();
        live_auth
            .publish_if_version(generation, AuthorizationStore::default())
            .map_err(|e| format!("{e:?}"))?;
        assert!(matches!(
            sender
                .send_on_split(
                    &owner,
                    (&split.connection, &split.established),
                    &mut split.sender,
                    &live_auth,
                    &action(SOURCE),
                    || 150
                )
                .await,
            Err(TeacherCommandSendError::PeerIdentity(_))
        ));
        assert!(matches!(
            sender
                .send_on_split(
                    &owner,
                    (&split.connection, &split.established),
                    &mut split.sender,
                    &live_auth,
                    &action(SOURCE),
                    || 150
                )
                .await,
            Err(TeacherCommandSendError::Retired)
        ));
        server_conn.close(0u32.into(), b"test end");
        server.close(0u32.into(), b"test end");
        split.connection.close(0u32.into(), b"test end");
        client.close(0u32.into(), b"test end");
        client.wait_idle().await;
        Ok(())
    }
}
