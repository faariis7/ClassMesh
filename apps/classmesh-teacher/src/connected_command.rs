//! Authenticated Teacher interaction send path over the already-owned QUIC session.
//! No new listener, credentials, enrollment, or concurrent control-channel reader.

use std::sync::mpsc::{Receiver, TryRecvError};

use classmesh_control::NegotiatedHello;
use classmesh_control::client_session::ClientControlSession;
use classmesh_control::handshake::{EstablishedControlSession, FIRST_POST_HELLO_SEQUENCE};
use classmesh_control::live_authorization::{LiveAuthorizationError, LiveAuthorizationStore};
use classmesh_control::peer_identity::{PeerIdentityError, authenticated_peer_identity};
use classmesh_control::quic::{ControlChannel, ControlSendHalf, ControlTransportError};
use classmesh_protocol::control_wire::TeacherInteractionKind;
use classmesh_protocol::control_wire::{
    ControlEnvelope, Heartbeat, MediaHealth, ProtocolVersion as WireVersion, control_envelope,
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

/// Expected StudentDevice, enrolled monitoring source and exact QUIC session.
/// The route describes what to verify. It never grants authorization itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeacherControlRoute {
    expected_student: PrincipalId,
    source_id: MonitoringSourceId,
    control_session_id: u64,
    playback_binding: Option<TeacherPlaybackBinding>,
    active: bool,
}

impl TeacherControlRoute {
    pub fn new(
        expected_student: PrincipalId,
        source_id: MonitoringSourceId,
        control_session_id: u64,
    ) -> Result<Self, TeacherCommandSendError> {
        if control_session_id == 0 {
            return Err(TeacherCommandSendError::SessionMismatch);
        }
        if source_id.0 == 0 || expected_student == PrincipalId([0; 32]) {
            return Err(TeacherCommandSendError::SourceMismatch);
        }
        Ok(Self {
            expected_student,
            source_id,
            control_session_id,
            playback_binding: None,
            active: true,
        })
    }

    #[must_use]
    pub const fn control_session_id(self) -> u64 {
        self.control_session_id
    }

    #[must_use]
    pub const fn expected_student(self) -> PrincipalId {
        self.expected_student
    }

    #[must_use]
    pub const fn source_id(self) -> MonitoringSourceId {
        self.source_id
    }

    #[must_use]
    pub const fn is_active(self) -> bool {
        self.active
    }
}

impl From<&TeacherPlaybackSessionOwner> for TeacherControlRoute {
    fn from(owner: &TeacherPlaybackSessionOwner) -> Self {
        Self {
            expected_student: owner.expected_student(),
            source_id: owner.source_id(),
            control_session_id: owner.binding().control_session_id,
            playback_binding: Some(owner.binding()),
            active: owner.is_active(),
        }
    }
}

fn prepare_teacher_interaction(
    route: TeacherControlRoute,
    negotiated: &NegotiatedHello,
    action: &TeacherInteractionUiAction,
    sequence: u64,
    request_id: u64,
) -> Result<ControlEnvelope, TeacherCommandSendError> {
    if !route.active {
        return Err(TeacherCommandSendError::Retired);
    }
    if route.source_id != action.source_id {
        return Err(TeacherCommandSendError::SourceMismatch);
    }
    if route.control_session_id == 0 || route.control_session_id != action.control_session_id {
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
        control_session_id: route.control_session_id,
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
    expected_student: PrincipalId,
    connection: &Connection,
    authorization: &LiveAuthorizationStore,
    now_ms: u64,
) -> Result<(), TeacherCommandSendError> {
    let snapshot = authorization
        .snapshot()
        .map_err(TeacherCommandSendError::Authorization)?;
    let peer = authenticated_peer_identity(connection, snapshot.store(), now_ms)
        .map_err(TeacherCommandSendError::PeerIdentity)?;
    if peer.principal_id() != expected_student
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
    control: TeacherControlRoute,
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
            next_sequence: FIRST_POST_HELLO_SEQUENCE,
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
            owner.into(),
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
        self.send_control_on_split(owner.into(), session, sender, authorization, action, now_ms)
            .await
    }

    /// Write an interaction on an authenticated control session before any presentation exists.
    pub async fn send_control_on_split(
        &mut self,
        route: TeacherControlRoute,
        session: (&Connection, &EstablishedControlSession),
        sender: &mut ControlSendHalf,
        authorization: &LiveAuthorizationStore,
        action: &TeacherInteractionUiAction,
        now_ms: impl Fn() -> u64,
    ) -> Result<u64, TeacherCommandSendError> {
        self.send_over(
            route,
            session,
            TeacherWriter::Half(sender),
            authorization,
            action,
            now_ms,
        )
        .await
    }

    /// Send control-plane liveness on the same stream and sequence ledger as commands.
    pub async fn send_heartbeat_on_split(
        &mut self,
        route: TeacherControlRoute,
        session: (&Connection, &EstablishedControlSession),
        sender: &mut ControlSendHalf,
        authorization: &LiveAuthorizationStore,
        monotonic_time_us: u64,
        now_ms: impl Fn() -> u64,
    ) -> Result<(), TeacherCommandSendError> {
        let version = session.1.negotiated.version;
        let frame = ControlEnvelope {
            control_session_id: route.control_session_id,
            sequence: self.next_sequence,
            request_id: 0,
            protocol_version: Some(WireVersion {
                major: u32::from(version.major),
                minor: u32::from(version.minor),
            }),
            payload: Some(control_envelope::Payload::Heartbeat(Heartbeat {
                monotonic_time_us,
                control_session_id: route.control_session_id,
                media: MediaHealth::Idle as i32,
            })),
        };
        self.write_reserved(
            route,
            session,
            TeacherWriter::Half(sender),
            authorization,
            &frame,
            now_ms,
        )
        .await
    }

    async fn send_over(
        &mut self,
        route: TeacherControlRoute,
        session: (&Connection, &EstablishedControlSession),
        writer: TeacherWriter<'_>,
        authorization: &LiveAuthorizationStore,
        action: &TeacherInteractionUiAction,
        now_ms: impl Fn() -> u64,
    ) -> Result<u64, TeacherCommandSendError> {
        if self.retired {
            return Err(TeacherCommandSendError::Retired);
        }
        if session.1.control_session_id != route.control_session_id {
            self.retire(session.0);
            return Err(TeacherCommandSendError::SessionMismatch);
        }
        let frame = prepare_teacher_interaction(
            route,
            &session.1.negotiated,
            action,
            self.next_sequence,
            self.next_request_id,
        )?;
        let Some(next_request_id) = self.next_request_id.checked_add(1) else {
            self.retire(session.0);
            return Err(TeacherCommandSendError::InvalidCounters);
        };
        self.write_reserved(route, session, writer, authorization, &frame, now_ms)
            .await?;
        self.next_request_id = next_request_id;
        Ok(frame.request_id)
    }

    #[cfg(windows)]
    pub(crate) async fn send_presentation(
        &mut self,
        route: TeacherControlRoute,
        session: (&Connection, &EstablishedControlSession),
        sender: &mut ControlSendHalf,
        authorization: &LiveAuthorizationStore,
        payload: control_envelope::Payload,
        now: impl Fn() -> u64,
    ) -> Result<u64, TeacherCommandSendError> {
        if !matches!(
            payload,
            control_envelope::Payload::PresentationStart(_)
                | control_envelope::Payload::PresentationStop(_)
                | control_envelope::Payload::StreamOffer(_)
        ) || !session
            .1
            .negotiated
            .capabilities
            .contains(&classmesh_protocol::Capability::TeacherPresentation)
        {
            return Err(TeacherCommandSendError::CapabilityUnavailable);
        }
        let request = self.presentation_request(session.0)?;
        let version = session.1.negotiated.version;
        let frame = ControlEnvelope {
            control_session_id: route.control_session_id(),
            sequence: self.next_sequence,
            request_id: request,
            protocol_version: Some(WireVersion {
                major: version.major.into(),
                minor: version.minor.into(),
            }),
            payload: Some(payload),
        };
        self.write_reserved(
            route,
            session,
            TeacherWriter::Half(sender),
            authorization,
            &frame,
            now,
        )
        .await?;
        Ok(request)
    }

    #[cfg(windows)]
    pub(crate) async fn send_presentation_key(
        &mut self,
        route: TeacherControlRoute,
        session: (&Connection, &EstablishedControlSession),
        sender: &mut ControlSendHalf,
        authorization: &LiveAuthorizationStore,
        build: impl FnOnce(
            u64,
            u64,
        ) -> std::io::Result<
            classmesh_control::group_media_session::SensitivePresentationKeyEnvelope,
        >,
        now: impl Fn() -> u64,
    ) -> std::io::Result<u64> {
        let map_error = |error| std::io::Error::other(format!("presentation control: {error:?}"));
        let request = self.presentation_request(session.0).map_err(map_error)?;
        let sequence = self.next_sequence;
        self.reserve_sequence(route, session, authorization, &now)
            .map_err(map_error)?;
        let write = build(request, sequence)?.send_on_split(sender).await;
        self.finish_write(route, session.0, authorization, write, &now)
            .map_err(map_error)?;
        Ok(request)
    }

    #[cfg(windows)]
    fn presentation_request(
        &mut self,
        connection: &Connection,
    ) -> Result<u64, TeacherCommandSendError> {
        let request = self.next_request_id;
        let Some(next) = request.checked_add(1) else {
            self.retire(connection);
            return Err(TeacherCommandSendError::InvalidCounters);
        };
        self.next_request_id = next;
        Ok(request)
    }

    async fn write_reserved(
        &mut self,
        route: TeacherControlRoute,
        session: (&Connection, &EstablishedControlSession),
        mut writer: TeacherWriter<'_>,
        authorization: &LiveAuthorizationStore,
        frame: &ControlEnvelope,
        now_ms: impl Fn() -> u64,
    ) -> Result<(), TeacherCommandSendError> {
        self.reserve_sequence(route, session, authorization, &now_ms)?;
        let write = writer.send(frame).await;
        self.finish_write(route, session.0, authorization, write, &now_ms)
    }

    fn reserve_sequence(
        &mut self,
        route: TeacherControlRoute,
        session: (&Connection, &EstablishedControlSession),
        authorization: &LiveAuthorizationStore,
        now_ms: &impl Fn() -> u64,
    ) -> Result<(), TeacherCommandSendError> {
        let (connection, established) = session;
        if self.retired || !route.active {
            return Err(TeacherCommandSendError::Retired);
        }
        if established.control_session_id != route.control_session_id
            || route.control_session_id == 0
        {
            self.retire(connection);
            return Err(TeacherCommandSendError::SessionMismatch);
        }
        if established.negotiated.role != ControlRole::Teacher {
            self.retire(connection);
            return Err(TeacherCommandSendError::WrongRole);
        }
        if let Err(error) =
            verify_current_student(route.expected_student, connection, authorization, now_ms())
        {
            self.retire(connection);
            return Err(error);
        }
        let bound = TeacherCommandRoute {
            control: route,
            teacher_principal: established.negotiated.principal_id,
            connection_id: connection.stable_id(),
        };
        if let Err(error) = self.ensure_route(bound) {
            self.retire(connection);
            return Err(error);
        }
        let Some(next_sequence) = self.next_sequence.checked_add(1) else {
            self.retire(connection);
            return Err(TeacherCommandSendError::InvalidCounters);
        };
        // Reserve before I/O: a failed or ambiguous write permanently retires the sender.
        self.next_sequence = next_sequence;
        Ok(())
    }

    fn finish_write(
        &mut self,
        route: TeacherControlRoute,
        connection: &Connection,
        authorization: &LiveAuthorizationStore,
        write: Result<(), ControlTransportError>,
        now_ms: &impl Fn() -> u64,
    ) -> Result<(), TeacherCommandSendError> {
        if let Err(error) = write {
            self.retire(connection);
            return Err(TeacherCommandSendError::Transport(error));
        }
        if let Err(error) =
            verify_current_student(route.expected_student, connection, authorization, now_ms())
        {
            self.retire(connection);
            return Err(error);
        }
        Ok(())
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
        let frame =
            prepare_teacher_interaction((&owner()).into(), &negotiated(), &action(), 1, 9).unwrap();
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
            prepare_teacher_interaction((&o).into(), &n, &wrong_source, 1, 1),
            Err(TeacherCommandSendError::SourceMismatch)
        ));
        let mut wrong_session = a.clone();
        wrong_session.control_session_id = SESSION + 1;
        assert!(matches!(
            prepare_teacher_interaction((&o).into(), &n, &wrong_session, 1, 1),
            Err(TeacherCommandSendError::SessionMismatch)
        ));
        let mut wrong_role = n.clone();
        wrong_role.role = ControlRole::StudentDevice;
        assert!(matches!(
            prepare_teacher_interaction((&o).into(), &wrong_role, &a, 1, 1),
            Err(TeacherCommandSendError::WrongRole)
        ));
        let mut missing_cap = n.clone();
        missing_cap.capabilities.clear();
        assert!(matches!(
            prepare_teacher_interaction((&o).into(), &missing_cap, &a, 1, 1),
            Err(TeacherCommandSendError::CapabilityUnavailable)
        ));
    }

    #[test]
    fn sender_retirement_rejects_stale_connection_or_roster_route() {
        let mut sender = TeacherCommandSender::default();
        let route = TeacherCommandRoute {
            control: (&owner()).into(),
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
            prepare_teacher_interaction((&o).into(), &n, &a, 1, 1),
            Err(TeacherCommandSendError::InvalidRequest(_))
        ));
        assert!(matches!(
            prepare_teacher_interaction((&o).into(), &n, &action(), 0, 1),
            Err(TeacherCommandSendError::InvalidCounters)
        ));
        assert!(matches!(
            prepare_teacher_interaction((&o).into(), &n, &action(), 1, 0),
            Err(TeacherCommandSendError::InvalidCounters)
        ));
        let mut retired = owner();
        assert!(retired.retire_exact(SOURCE, retired.binding()));
        assert!(matches!(
            prepare_teacher_interaction((&retired).into(), &n, &action(), 1, 1),
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
    use classmesh_control::authorization::{AuthenticatedControlGuard, CommandAuthorizationError};
    use classmesh_control::client_session::connect_client_session_with_retries;
    use classmesh_control::dispatch::{
        PrivilegedControlCommand, PrivilegedDispatchError, dispatch_privileged_command,
    };
    use classmesh_control::handshake::{ServerHelloConfig, server_hello_enrolled};
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
        AuthorizationStore, CredentialFingerprint, CredentialRecord, Permission, Principal,
        PrincipalId, PrincipalKind,
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
    const TEACHER: PrincipalId = PrincipalId([8; 32]);
    const STUDENT: PrincipalId = PrincipalId([7; 32]);
    const SESSION: u64 = 55;
    const SOURCE: MonitoringSourceId = MonitoringSourceId(7);
    const VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 8 };

    fn test_capabilities() -> BTreeSet<Capability> {
        BTreeSet::from([Capability::TeacherMessage, Capability::TeacherPresentation])
    }

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

        let teacher_fingerprint =
            CredentialFingerprint(Sha256::digest(client_cert.as_ref()).into());
        let mut enrolled_teachers = AuthorizationStore::default();
        enrolled_teachers
            .upsert(Principal {
                id: TEACHER,
                kind: PrincipalKind::Teacher,
                enabled: true,
                permissions: BTreeSet::from([
                    Permission::SendTeacherMessage,
                    Permission::StartPresentation,
                ]),
                credentials: BTreeMap::from([(
                    teacher_fingerprint,
                    CredentialRecord::active(teacher_fingerprint, 100),
                )]),
            })
            .map_err(|error| format!("{error:?}"))?;
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
        let negotiated = test_capabilities();
        let server_task = tokio::spawn(async move {
            let conn = accept(&server).await.map_err(|e| e.to_string())?;
            let mut channel = ControlChannel::accept(&conn, DEFAULT_IO_TIMEOUT)
                .await
                .map_err(|e| e.to_string())?;
            let (_, peer) = server_hello_enrolled(
                &conn,
                &mut channel,
                &ServerHelloConfig {
                    local_version: VERSION,
                    local_capabilities: negotiated,
                    control_session_id: SESSION,
                },
                &enrolled_teachers,
                150,
            )
            .await
            .map_err(|e| e.to_string())?;
            assert_eq!(peer.identity.principal_id(), TEACHER);
            let mut guard = AuthenticatedControlGuard::new(peer.identity, SESSION, VERSION, 1);
            let first = channel.receive().await.map_err(|e| e.to_string())?;
            assert!(
                matches!(
                    dispatch_privileged_command(&mut guard, &enrolled_teachers, &first, 150),
                    Ok(PrivilegedControlCommand::TeacherInteraction(_))
                ),
                "first command must pass the enrolled Service command dispatcher"
            );
            assert!(
                matches!(
                    dispatch_privileged_command(&mut guard, &enrolled_teachers, &first, 150),
                    Err(PrivilegedDispatchError::Authorization(
                        CommandAuthorizationError::NonIncreasingSequence { .. }
                    ))
                ),
                "a replay must be refused before execution"
            );
            // Do not reply until the second outbound command arrives. This
            // forces a single in-flight verified receive while send proceeds.
            let second = channel.receive().await.map_err(|e| e.to_string())?;
            assert!(matches!(
                dispatch_privileged_command(&mut guard, &enrolled_teachers, &second, 150),
                Ok(PrivilegedControlCommand::TeacherInteraction(_))
            ));
            #[cfg(windows)]
            {
                for (offset, present_start) in [(0, true), (1, false)] {
                    let frame = channel.receive().await.map_err(|e| e.to_string())?;
                    assert_eq!(
                        (frame.sequence, frame.request_id, frame.control_session_id),
                        (4 + offset, 3 + offset, SESSION)
                    );
                    let admitted =
                        dispatch_privileged_command(&mut guard, &enrolled_teachers, &frame, 150);
                    if present_start {
                        assert!(matches!(
                            admitted,
                            Ok(PrivilegedControlCommand::PresentationStart(_))
                        ));
                    } else {
                        assert!(matches!(
                            admitted,
                            Ok(PrivilegedControlCommand::PresentationStop(_))
                        ));
                    }
                }
            }
            let mut unpermitted =
                AuthenticatedControlGuard::new(peer.identity, SESSION, VERSION, 1);
            assert!(matches!(
                dispatch_privileged_command(
                    &mut unpermitted,
                    &AuthorizationStore::default(),
                    &first,
                    150
                ),
                Err(PrivilegedDispatchError::Authorization(
                    CommandAuthorizationError::Unauthorized { .. }
                ))
            ));
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
                capabilities: test_capabilities(),
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
            async {
                let written = sender
                    .send_on_split(
                        &owner,
                        (&split.connection, &split.established),
                        &mut split.sender,
                        &live_auth,
                        &bound_action,
                        || 150,
                    )
                    .await?;
                #[cfg(windows)]
                {
                    use classmesh_protocol::control_wire::{PresentationStart, PresentationStop};
                    let route = TeacherControlRoute::from(&owner);
                    let session = (&split.connection, &split.established);
                    let start = sender
                        .send_presentation(
                            route,
                            session,
                            &mut split.sender,
                            &live_auth,
                            control_envelope::Payload::PresentationStart(PresentationStart {
                                presentation_id: 10,
                                stream_id: 11,
                            }),
                            || 150,
                        )
                        .await?;
                    let stop = sender
                        .send_presentation(
                            route,
                            session,
                            &mut split.sender,
                            &live_auth,
                            control_envelope::Payload::PresentationStop(PresentationStop {
                                presentation_id: 10,
                            }),
                            || 150,
                        )
                        .await?;
                    assert_eq!((start, stop), (3, 4));
                }
                Ok::<_, TeacherCommandSendError>(written)
            },
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
            (2, 1, SESSION)
        );
        assert_eq!(
            (
                second.sequence,
                second.request_id,
                second.control_session_id
            ),
            (3, 2, SESSION)
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
