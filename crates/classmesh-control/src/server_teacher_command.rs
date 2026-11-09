//! Enrolled Service-side Teacher QUIC command ingress. No SCM or Worker activation.
//! Only an enrolled mTLS connection and authenticated Hello may construct this receiver.
use crate::peer_identity::AuthenticatedPeerIdentity;
use classmesh_protocol::control_wire::{
    ControlEnvelope, TeacherInteractionKind, TeacherInteractionResult, TeacherInteractionState,
    control_envelope,
};
use classmesh_protocol::teacher_interaction::validate_request;
use classmesh_protocol::{ControlRole, ProtocolVersion};
use classmesh_security::{PrincipalId, PrincipalKind};
use quinn::Connection;

use crate::authorization::AuthenticatedControlGuard;
use crate::dispatch::{
    PrivilegedControlCommand, PrivilegedDispatchError, dispatch_privileged_command,
};
use crate::handshake::{
    EstablishedAuthenticatedPeer, EstablishedControlSession, HandshakeError, ServerHelloConfig,
    server_hello_enrolled,
};
use crate::live_authorization::{LiveAuthorizationError, LiveAuthorizationStore};
use crate::peer_identity::{PeerIdentityError, authenticated_peer_identity};
use crate::quic::{ControlChannel, ControlTransportError};

#[derive(Debug)]
pub enum ServiceTeacherCommandError {
    Handshake(HandshakeError),
    WrongRole,
    WrongPrincipalKind,
    InvalidSession,
    PeerIdentity(PeerIdentityError),
    Authorization(LiveAuthorizationError),
    Transport(ControlTransportError),
    Dispatch(PrivilegedDispatchError),
    FileTransferDisabled,
    SessionRetired,
    NotTeacherInteraction,
    InvalidWorkerOutcome,
    MismatchedWorkerOutcome,
}

/// Service-owned proof returned only after the Worker dispatcher completes.
/// Correlation is checked against the authenticated ingress, never against
/// identifiers supplied by an untrusted Teacher payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorrelatedWorkerOutcome {
    pub request_id: u64,
    pub request_sequence: u64,
    pub source_principal_id: PrincipalId,
    pub state: TeacherInteractionState,
}

fn validate_worker_outcome(
    outcome: CorrelatedWorkerOutcome,
    request_id: u64,
    request_sequence: u64,
    source_principal_id: PrincipalId,
) -> Result<TeacherInteractionState, ServiceTeacherCommandError> {
    if outcome.request_id != request_id
        || outcome.request_sequence != request_sequence
        || outcome.source_principal_id != source_principal_id
    {
        return Err(ServiceTeacherCommandError::MismatchedWorkerOutcome);
    }
    match outcome.state {
        TeacherInteractionState::Completed
        | TeacherInteractionState::Rejected
        | TeacherInteractionState::Failed => Ok(outcome.state),
        _ => Err(ServiceTeacherCommandError::InvalidWorkerOutcome),
    }
}

#[derive(Default)]
struct ExecutionState {
    retired: bool,
}

impl ExecutionState {
    fn retire(&mut self) {
        self.retired = true;
    }

    fn begin_inflight(&mut self) -> Result<(), ServiceTeacherCommandError> {
        self.ensure_active()?;
        self.retired = true;
        Ok(())
    }

    fn finish_inflight(&mut self) {
        self.retired = false;
    }

    fn ensure_active(&self) -> Result<(), ServiceTeacherCommandError> {
        if self.retired {
            Err(ServiceTeacherCommandError::SessionRetired)
        } else {
            Ok(())
        }
    }
}

/// Session-owned command receiver. A reconnect or new Hello must construct a
/// new receiver, never reset the replay sequence of an existing one.
pub struct ServiceTeacherCommandReceiver {
    connection: Connection,
    channel: ControlChannel,
    guard: AuthenticatedControlGuard,
    execution_state: ExecutionState,
    next_reply_sequence: u64,
}

impl ServiceTeacherCommandReceiver {
    /// Accept an enrolled Teacher Hello and bind the resulting session to this
    /// exact QUIC connection and channel. The Service must supply a TLS endpoint
    /// requiring enrolled client certificates; no unauthenticated Hello fallback.
    pub async fn accept_enrolled(
        connection: Connection,
        mut channel: ControlChannel,
        config: &ServerHelloConfig,
        authorization: &LiveAuthorizationStore,
        now_unix_ms: u64,
    ) -> Result<Self, ServiceTeacherCommandError> {
        let snapshot = authorization
            .snapshot()
            .map_err(ServiceTeacherCommandError::Authorization)?;
        let (established, peer) = server_hello_enrolled(
            &connection,
            &mut channel,
            config,
            snapshot.store(),
            now_unix_ms,
        )
        .await
        .map_err(ServiceTeacherCommandError::Handshake)?;
        Self::new(
            connection,
            channel,
            &established,
            peer,
            authorization,
            now_unix_ms,
        )
    }

    /// `established` and `peer` MUST come from `server_hello_enrolled` on this
    /// very connection/channel, with enrolled mTLS client verification enabled.
    /// The constructor rechecks the live credential before any command is read.
    pub fn new(
        connection: Connection,
        channel: ControlChannel,
        established: &EstablishedControlSession,
        peer: EstablishedAuthenticatedPeer,
        authorization: &LiveAuthorizationStore,
        now_unix_ms: u64,
    ) -> Result<Self, ServiceTeacherCommandError> {
        if established.negotiated.role != ControlRole::Teacher {
            return Err(ServiceTeacherCommandError::WrongRole);
        }
        if established.control_session_id == 0
            || peer.control_session_id != established.control_session_id
            || peer.identity.principal_id() != established.negotiated.principal_id
        {
            return Err(ServiceTeacherCommandError::InvalidSession);
        }
        let snapshot = authorization
            .snapshot()
            .map_err(ServiceTeacherCommandError::Authorization)?;
        let current = authenticated_peer_identity(&connection, snapshot.store(), now_unix_ms)
            .map_err(ServiceTeacherCommandError::PeerIdentity)?;
        if current != peer.identity {
            return Err(ServiceTeacherCommandError::InvalidSession);
        }
        if snapshot
            .store()
            .principal(current.principal_id())
            .map(|p| p.kind)
            != Some(PrincipalKind::Teacher)
        {
            return Err(ServiceTeacherCommandError::WrongPrincipalKind);
        }
        let guard = AuthenticatedControlGuard::new(
            current,
            established.control_session_id,
            ProtocolVersion {
                major: established.negotiated.version.major,
                minor: established.negotiated.version.minor,
            },
            1,
        );
        Ok(Self {
            connection,
            channel,
            guard,
            execution_state: ExecutionState::default(),
            next_reply_sequence: 2, // Server HelloAck owns sequence 1.
        })
    }

    /// Every ingress failure is terminal: an already consumed frame must never
    /// be retried on the same authenticated connection after a policy, replay,
    /// dispatch or transport failure. This includes revocation after Worker IO.
    pub async fn receive_dispatch_and_reply<F, Fut, E>(
        &mut self,
        authorization: &LiveAuthorizationStore,
        now_unix_ms: impl Fn() -> u64,
        dispatch: F,
    ) -> Result<Result<TeacherInteractionState, E>, ServiceTeacherCommandError>
    where
        F: FnOnce(
            AuthenticatedPeerIdentity,
            u64,
            u64,
            classmesh_protocol::control_wire::TeacherInteractionRequest,
        ) -> Fut,
        Fut: std::future::Future<Output = Result<CorrelatedWorkerOutcome, E>>,
    {
        let result = self
            .receive_dispatch_and_reply_inner(authorization, now_unix_ms, dispatch)
            .await;
        if result.is_err() {
            self.retire_connection(b"teacher command ingress rejected");
        }
        result
    }

    /// A Worker-owned dispatcher must return a real terminal outcome; never mint
    /// an Accepted result merely because the QUIC message was received.
    /// The authenticated identity is bound to the incoming QUIC peer, not
    /// supplied by the Teacher's request payload.
    async fn receive_dispatch_and_reply_inner<F, Fut, E>(
        &mut self,
        authorization: &LiveAuthorizationStore,
        now_unix_ms: impl Fn() -> u64,
        dispatch: F,
    ) -> Result<Result<TeacherInteractionState, E>, ServiceTeacherCommandError>
    where
        F: FnOnce(
            AuthenticatedPeerIdentity,
            u64,
            u64,
            classmesh_protocol::control_wire::TeacherInteractionRequest,
        ) -> Fut,
        Fut: std::future::Future<Output = Result<CorrelatedWorkerOutcome, E>>,
    {
        // Mark the receiver unavailable before the first cancellable await.
        // Dropping this future must not allow replay on the same session.
        self.execution_state.begin_inflight()?;
        self.verify(authorization, now_unix_ms())?;
        let envelope = self
            .channel
            .receive()
            .await
            .map_err(ServiceTeacherCommandError::Transport)?;
        self.verify(authorization, now_unix_ms())?;
        let snapshot = authorization
            .snapshot()
            .map_err(ServiceTeacherCommandError::Authorization)?;
        let command = dispatch_privileged_command(
            &mut self.guard,
            snapshot.store(),
            &envelope,
            now_unix_ms(),
        )
        .map_err(ServiceTeacherCommandError::Dispatch)?;
        let PrivilegedControlCommand::TeacherInteraction(request) = command else {
            return Err(ServiceTeacherCommandError::NotTeacherInteraction);
        };
        let kind = validate_request(&request).map_err(|e| {
            ServiceTeacherCommandError::Dispatch(
                PrivilegedDispatchError::InvalidTeacherInteraction(e),
            )
        })?;
        let peer = self.guard.peer();
        let result = dispatch(peer, envelope.request_id, envelope.sequence, request).await;
        // A dispatcher failure cannot be interpreted as acceptance. Retire the
        // session and do not send a fabricated Worker completion response.
        let state = match result {
            Ok(outcome) => match validate_worker_outcome(
                outcome,
                envelope.request_id,
                envelope.sequence,
                peer.principal_id(),
            ) {
                Ok(state) => state,
                Err(error) => {
                    self.retire_connection(b"uncorrelated worker outcome");
                    return Err(error);
                }
            },
            Err(error) => {
                self.retire_connection(b"worker dispatch failed");
                return Ok(Err(error));
            }
        };
        self.verify(authorization, now_unix_ms())?;
        // Reserve the next sequence before writing: never emit an ACK that
        // cannot be recorded as consumed by this session.
        let following_sequence = reserve_reply_sequence(self.next_reply_sequence)?;
        let response = correlated_teacher_result(
            self.guard.control_session_id(),
            self.guard.protocol_version(),
            self.next_reply_sequence,
            envelope.request_id,
            kind,
            state,
        );
        if let Err(error) = self.channel.send(&response).await {
            self.retire_connection(b"worker result send failed");
            return Err(ServiceTeacherCommandError::Transport(error));
        }
        self.next_reply_sequence = following_sequence;
        if let Err(error) = self.verify(authorization, now_unix_ms()) {
            self.retire_connection(b"teacher authorization changed");
            return Err(error);
        }
        self.execution_state.finish_inflight();
        Ok(Ok(state))
    }

    fn retire_connection(&mut self, reason: &'static [u8]) {
        self.execution_state.retire();
        self.connection.close(0u32.into(), reason);
    }

    /// Revalidate mTLS identity and current policy both before and after IO.
    /// The returned opaque command is permission-checked; no Worker command is
    /// executed by this library. Failures retire the caller's session.
    pub async fn receive_authorized(
        &mut self,
        authorization: &LiveAuthorizationStore,
        now_unix_ms: impl Fn() -> u64,
    ) -> Result<PrivilegedControlCommand, ServiceTeacherCommandError> {
        self.ensure_active()?;
        self.verify(authorization, now_unix_ms())?;
        let envelope = self
            .channel
            .receive()
            .await
            .map_err(ServiceTeacherCommandError::Transport)?;
        self.verify(authorization, now_unix_ms())?;
        // File transfer remains explicitly disabled for the MVP. Never grant
        // it merely because a Teacher credential has other control permissions.
        if is_file_transfer(&envelope) {
            self.guard.validate_envelope(&envelope).map_err(|e| {
                ServiceTeacherCommandError::Dispatch(PrivilegedDispatchError::Authorization(e))
            })?;
            return Err(ServiceTeacherCommandError::FileTransferDisabled);
        }
        let snapshot = authorization
            .snapshot()
            .map_err(ServiceTeacherCommandError::Authorization)?;
        dispatch_privileged_command(&mut self.guard, snapshot.store(), &envelope, now_unix_ms())
            .map_err(ServiceTeacherCommandError::Dispatch)
    }

    /// Run one authenticated command through a Service-owned async executor.
    /// The executor receives only an already authorized command; it must apply
    /// its own Worker/session ownership checks before performing side effects.
    /// An executor error is terminal for this receiver: callers must drop the
    /// connection rather than retrying a consumed command or replaying it.
    pub async fn receive_and_execute<F, Fut, E>(
        &mut self,
        authorization: &LiveAuthorizationStore,
        now_unix_ms: impl Fn() -> u64,
        execute: F,
    ) -> Result<Result<(), E>, ServiceTeacherCommandError>
    where
        F: FnOnce(PrivilegedControlCommand) -> Fut,
        Fut: std::future::Future<Output = Result<(), E>>,
    {
        let command = self.receive_authorized(authorization, now_unix_ms).await?;
        let result = execute(command).await;
        if result.is_err() {
            self.execution_state.retire();
            self.connection
                .close(0u32.into(), b"teacher command execution failed");
        }
        Ok(result)
    }

    fn ensure_active(&self) -> Result<(), ServiceTeacherCommandError> {
        self.execution_state.ensure_active()
    }

    fn verify(
        &self,
        authorization: &LiveAuthorizationStore,
        now: u64,
    ) -> Result<(), ServiceTeacherCommandError> {
        let snapshot = authorization
            .snapshot()
            .map_err(ServiceTeacherCommandError::Authorization)?;
        let current = authenticated_peer_identity(&self.connection, snapshot.store(), now)
            .map_err(ServiceTeacherCommandError::PeerIdentity)?;
        if current != self.guard.peer() {
            return Err(ServiceTeacherCommandError::InvalidSession);
        }
        if snapshot
            .store()
            .principal(current.principal_id())
            .map(|p| p.kind)
            != Some(PrincipalKind::Teacher)
        {
            return Err(ServiceTeacherCommandError::WrongPrincipalKind);
        }
        Ok(())
    }
}

fn reserve_reply_sequence(current: u64) -> Result<u64, ServiceTeacherCommandError> {
    current
        .checked_add(1)
        .ok_or(ServiceTeacherCommandError::SessionRetired)
}

fn correlated_teacher_result(
    session_id: u64,
    version: ProtocolVersion,
    sequence: u64,
    request_id: u64,
    kind: TeacherInteractionKind,
    state: TeacherInteractionState,
) -> ControlEnvelope {
    ControlEnvelope {
        control_session_id: session_id,
        protocol_version: Some(classmesh_protocol::control_wire::ProtocolVersion {
            major: u32::from(version.major),
            minor: u32::from(version.minor),
        }),
        sequence,
        request_id,
        payload: Some(control_envelope::Payload::TeacherInteractionResult(
            TeacherInteractionResult {
                kind: kind as i32,
                state: state as i32,
                diagnostic: String::new(),
            },
        )),
    }
}

fn is_file_transfer(envelope: &ControlEnvelope) -> bool {
    matches!(
        envelope.payload,
        Some(
            control_envelope::Payload::FileTransferOffer(_)
                | control_envelope::Payload::FileTransferChunk(_)
                | control_envelope::Payload::FileTransferFinish(_)
                | control_envelope::Payload::FileTransferCancel(_)
                | control_envelope::Payload::FileTransferPullRequest(_)
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use classmesh_protocol::control_wire::{FileTransferCancel, Heartbeat};

    #[test]
    fn correlated_worker_result_preserves_session_request_and_sequence() {
        let envelope = correlated_teacher_result(
            91,
            ProtocolVersion { major: 0, minor: 6 },
            2,
            784,
            TeacherInteractionKind::Message,
            TeacherInteractionState::Completed,
        );
        assert_eq!(
            (
                envelope.control_session_id,
                envelope.sequence,
                envelope.request_id
            ),
            (91, 2, 784)
        );
        let Some(control_envelope::Payload::TeacherInteractionResult(result)) = envelope.payload
        else {
            panic!("wrong payload")
        };
        assert_eq!(result.kind, TeacherInteractionKind::Message as i32);
        assert_eq!(result.state, TeacherInteractionState::Completed as i32);
        assert!(result.diagnostic.is_empty());
    }

    #[test]
    fn worker_result_must_match_authenticated_source_and_request() {
        let outcome = CorrelatedWorkerOutcome {
            request_id: 784,
            request_sequence: 7,
            source_principal_id: PrincipalId([42; 32]),
            state: TeacherInteractionState::Completed,
        };
        assert!(matches!(
            validate_worker_outcome(outcome, 784, 7, PrincipalId([42; 32])),
            Ok(TeacherInteractionState::Completed)
        ));
        for (request_id, sequence, principal) in [(785, 7, 42), (784, 8, 42), (784, 7, 43)] {
            assert!(matches!(
                validate_worker_outcome(
                    outcome,
                    request_id,
                    sequence,
                    PrincipalId([principal; 32])
                ),
                Err(ServiceTeacherCommandError::MismatchedWorkerOutcome)
            ));
        }
        assert!(matches!(
            validate_worker_outcome(
                CorrelatedWorkerOutcome {
                    state: TeacherInteractionState::Accepted,
                    ..outcome
                },
                784,
                7,
                PrincipalId([42; 32])
            ),
            Err(ServiceTeacherCommandError::InvalidWorkerOutcome)
        ));
    }

    #[test]
    fn failed_execution_retires_receiver_without_replay() {
        let mut state = ExecutionState::default();
        assert!(state.ensure_active().is_ok());
        state.retire();
        assert!(matches!(
            state.ensure_active(),
            Err(ServiceTeacherCommandError::SessionRetired)
        ));
        state.retire();
        assert!(matches!(
            state.ensure_active(),
            Err(ServiceTeacherCommandError::SessionRetired)
        ));
    }

    #[test]
    fn cancelled_inflight_command_cannot_reuse_authenticated_session() {
        let mut state = ExecutionState::default();
        state.begin_inflight().unwrap();
        assert!(matches!(
            state.begin_inflight(),
            Err(ServiceTeacherCommandError::SessionRetired)
        ));
        state.finish_inflight();
        state.begin_inflight().unwrap();
        state.retire();
        assert!(matches!(
            state.begin_inflight(),
            Err(ServiceTeacherCommandError::SessionRetired)
        ));
    }

    #[test]
    fn exhausted_reply_sequence_must_fail_before_sending_any_ack() {
        assert!(matches!(
            reserve_reply_sequence(u64::MAX),
            Err(ServiceTeacherCommandError::SessionRetired)
        ));
        assert_eq!(reserve_reply_sequence(2).unwrap(), 3);
    }

    #[test]
    fn file_transfer_is_disabled_but_heartbeat_is_not_misclassified() {
        let mut envelope = ControlEnvelope {
            control_session_id: 9,
            sequence: 2,
            protocol_version: None,
            request_id: 1,
            payload: Some(control_envelope::Payload::FileTransferCancel(
                FileTransferCancel::default(),
            )),
        };
        assert!(is_file_transfer(&envelope));
        envelope.payload = Some(control_envelope::Payload::Heartbeat(Heartbeat::default()));
        assert!(!is_file_transfer(&envelope));
    }
}
