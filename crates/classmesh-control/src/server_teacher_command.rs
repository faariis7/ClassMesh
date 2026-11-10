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
use std::future::Future;
use std::time::Duration;

// Bound a stalled ACK write: never leave a Worker-completed command
// indefinitely in-flight on a blocked QUIC stream.
const WORKER_ACK_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
// A Worker that never returns a terminal outcome must not pin the authenticated
// QUIC session indefinitely. Timeout is a failure, never a synthetic ACK.
const WORKER_DISPATCH_TIMEOUT: Duration = Duration::from_secs(300);
// An authenticated but idle peer cannot hold a command receiver forever.
const TEACHER_COMMAND_RECEIVE_TIMEOUT: Duration = Duration::from_secs(30);

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
    AuthorizationChangedDuringDispatch,
    AckWriteTimedOut,
    WorkerDispatchTimedOut,
    CommandReceiveTimedOut,
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
        let hello_generation = snapshot.version();
        let (established, peer) = server_hello_enrolled(
            &connection,
            &mut channel,
            config,
            snapshot.store(),
            now_unix_ms,
        )
        .await
        .map_err(|error| {
            // A failed enrolled Hello must not leave an authenticated-looking
            // transport available for another command on this connection.
            connection.close(0u32.into(), b"teacher enrolled hello failed");
            ServiceTeacherCommandError::Handshake(error)
        })?;
        // A credential revoked and re-enrolled while Hello was in flight
        // cannot reuse the previously negotiated authenticated session.
        if let Err(error) = verify_policy_generation(authorization, hello_generation) {
            connection.close(0u32.into(), b"teacher hello authorization changed");
            return Err(error);
        }
        let receiver = Self::new(
            connection.clone(),
            channel,
            &established,
            peer,
            authorization,
            now_unix_ms,
        )
        .inspect_err(|_| {
            // Post-Hello credential/identity rejection is terminal for this
            // QUIC connection; no fresh Hello may reuse its transport.
            connection.close(0u32.into(), b"teacher session admission failed");
        })?;
        if let Err(error) = verify_policy_generation(authorization, hello_generation) {
            receiver
                .connection
                .close(0u32.into(), b"teacher hello authorization changed");
            return Err(error);
        }
        Ok(receiver)
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
        // Capture the epoch before the cancellable QUIC read. A revoked and
        // re-enrolled Teacher must not dispatch an already buffered request.
        let ingress_generation = authorization
            .snapshot()
            .map_err(ServiceTeacherCommandError::Authorization)?
            .version();
        let envelope =
            bounded_command_receive(self.channel.receive(), TEACHER_COMMAND_RECEIVE_TIMEOUT)
                .await?;
        verify_policy_generation(authorization, ingress_generation)?;
        self.verify(authorization, now_unix_ms())?;
        let snapshot = authorization
            .snapshot()
            .map_err(ServiceTeacherCommandError::Authorization)?;
        verify_policy_generation(authorization, ingress_generation)?;
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
        let policy_generation = snapshot.version();
        verify_policy_generation(authorization, ingress_generation)?;
        let peer = self.guard.peer();
        let result = bounded_worker_dispatch(
            dispatch(peer, envelope.request_id, envelope.sequence, request),
            WORKER_DISPATCH_TIMEOUT,
        )
        .await?;
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
        verify_policy_generation(authorization, policy_generation)?;
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
        match bounded_ack_write(self.channel.send(&response), WORKER_ACK_WRITE_TIMEOUT).await {
            Ok(()) => {}
            Err(error) => {
                self.retire_connection(b"worker result send failed or timed out");
                return Err(error);
            }
        }
        self.next_reply_sequence = following_sequence;
        if let Err(error) = self
            .verify(authorization, now_unix_ms())
            .and_then(|()| verify_policy_generation(authorization, policy_generation))
        {
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
        self.execution_state.begin_inflight()?;
        let result = self
            .receive_authorized_inner(authorization, now_unix_ms)
            .await;
        match result {
            Ok(command) => {
                self.execution_state.finish_inflight();
                Ok(command)
            }
            Err(error) => {
                self.retire_connection(b"teacher authorized ingress failed");
                Err(error)
            }
        }
    }

    async fn receive_authorized_inner(
        &mut self,
        authorization: &LiveAuthorizationStore,
        now_unix_ms: impl Fn() -> u64,
    ) -> Result<PrivilegedControlCommand, ServiceTeacherCommandError> {
        self.verify(authorization, now_unix_ms())?;
        // Pin the policy epoch before blocking on QUIC. A revoke/re-enroll
        // during the read must not admit a buffered command under a newly
        // restored credential, even when its principal ID is unchanged.
        let ingress_generation = authorization
            .snapshot()
            .map_err(ServiceTeacherCommandError::Authorization)?
            .version();
        // The alternate authorized ingress must obey the same idle deadline as
        // the correlated Worker path; otherwise a silent enrolled peer can pin
        // a Service receiver indefinitely after Hello.
        let envelope =
            bounded_command_receive(self.channel.receive(), TEACHER_COMMAND_RECEIVE_TIMEOUT)
                .await?;
        verify_policy_generation(authorization, ingress_generation)?;
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
        verify_policy_generation(authorization, ingress_generation)?;
        let command = dispatch_privileged_command(
            &mut self.guard,
            snapshot.store(),
            &envelope,
            now_unix_ms(),
        )
        .map_err(ServiceTeacherCommandError::Dispatch)?;
        verify_policy_generation(authorization, ingress_generation)?;
        Ok(command)
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
        // Cancellation during Worker execution must retire the consumed session.
        self.execution_state.begin_inflight()?;
        let execution_generation = authorization
            .snapshot()
            .map_err(ServiceTeacherCommandError::Authorization)?
            .version();
        let result =
            execute_with_policy_fence(authorization, execution_generation, || execute(command))
                .await;
        match result {
            Ok(Ok(())) => {
                self.execution_state.finish_inflight();
                Ok(Ok(()))
            }
            Ok(Err(error)) => {
                self.retire_connection(b"teacher command execution failed");
                Ok(Err(error))
            }
            Err(error) => {
                self.retire_connection(b"teacher authorization changed during execution");
                Err(error)
            }
        }
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

/// Bind Service execution to the authorization epoch. A policy change while
/// Worker IO is in progress must never make the consumed command reusable.
async fn execute_with_policy_fence<F, Fut, E>(
    authorization: &LiveAuthorizationStore,
    expected_generation: u64,
    execute: F,
) -> Result<Result<(), E>, ServiceTeacherCommandError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), E>>,
{
    verify_policy_generation(authorization, expected_generation)?;
    let result = execute().await;
    verify_policy_generation(authorization, expected_generation)?;
    Ok(result)
}

/// Any policy publication during an in-flight Worker command invalidates the
/// reply, even if the principal remains enrolled or a later policy restores
/// identical permissions. Never send a completion from a stale policy epoch.
fn verify_policy_generation(
    authorization: &LiveAuthorizationStore,
    expected: u64,
) -> Result<(), ServiceTeacherCommandError> {
    let current = authorization
        .snapshot()
        .map_err(ServiceTeacherCommandError::Authorization)?
        .version();
    if current != expected {
        return Err(ServiceTeacherCommandError::AuthorizationChangedDuringDispatch);
    }
    Ok(())
}

async fn bounded_command_receive<
    F: Future<Output = Result<ControlEnvelope, ControlTransportError>>,
>(
    receive: F,
    timeout: Duration,
) -> Result<ControlEnvelope, ServiceTeacherCommandError> {
    tokio::time::timeout(timeout, receive)
        .await
        .map_err(|_| ServiceTeacherCommandError::CommandReceiveTimedOut)?
        .map_err(ServiceTeacherCommandError::Transport)
}

async fn bounded_worker_dispatch<F: Future>(
    dispatch: F,
    timeout: Duration,
) -> Result<F::Output, ServiceTeacherCommandError> {
    tokio::time::timeout(timeout, dispatch)
        .await
        .map_err(|_| ServiceTeacherCommandError::WorkerDispatchTimedOut)
}

async fn bounded_ack_write<F>(send: F, timeout: Duration) -> Result<(), ServiceTeacherCommandError>
where
    F: Future<Output = Result<(), ControlTransportError>>,
{
    tokio::time::timeout(timeout, send)
        .await
        .map_err(|_| ServiceTeacherCommandError::AckWriteTimedOut)?
        .map_err(ServiceTeacherCommandError::Transport)
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

    #[tokio::test]
    async fn stalled_authenticated_command_receive_expires_without_dispatch() {
        let result = bounded_command_receive(
            std::future::pending::<Result<ControlEnvelope, ControlTransportError>>(),
            Duration::from_millis(10),
        )
        .await;
        assert!(matches!(
            result,
            Err(ServiceTeacherCommandError::CommandReceiveTimedOut)
        ));
    }

    #[tokio::test]
    async fn stalled_worker_dispatch_must_not_mint_terminal_ack() {
        let result = bounded_worker_dispatch(
            std::future::pending::<CorrelatedWorkerOutcome>(),
            Duration::from_millis(10),
        )
        .await;
        assert!(matches!(
            result,
            Err(ServiceTeacherCommandError::WorkerDispatchTimedOut)
        ));
    }

    #[tokio::test]
    async fn stalled_worker_ack_write_must_time_out_without_success() {
        let result = bounded_ack_write(
            std::future::pending::<Result<(), ControlTransportError>>(),
            Duration::from_millis(10),
        )
        .await;
        assert!(matches!(
            result,
            Err(ServiceTeacherCommandError::AckWriteTimedOut)
        ));
    }

    #[tokio::test]
    async fn executor_policy_republication_must_fail_closed() {
        let authorization = LiveAuthorizationStore::new(Default::default());
        let epoch = authorization.snapshot().unwrap().version();
        let result = execute_with_policy_fence(&authorization, epoch, || async {
            authorization
                .publish_if_version(epoch, Default::default())
                .unwrap();
            Ok::<(), ()>(())
        })
        .await;
        assert!(matches!(
            result,
            Err(ServiceTeacherCommandError::AuthorizationChangedDuringDispatch)
        ));
    }

    #[test]
    fn policy_republication_during_worker_dispatch_invalidates_ack_even_if_restored() {
        let authorization = LiveAuthorizationStore::new(Default::default());
        let initial = authorization.snapshot().unwrap().version();
        assert!(verify_policy_generation(&authorization, initial).is_ok());
        let updated = authorization
            .publish_if_version(initial, Default::default())
            .unwrap();
        assert!(matches!(
            verify_policy_generation(&authorization, initial),
            Err(ServiceTeacherCommandError::AuthorizationChangedDuringDispatch)
        ));
        assert!(verify_policy_generation(&authorization, updated).is_ok());
    }

    #[test]
    fn buffered_ingress_must_reject_revocation_and_reenrollment_during_receive() {
        let authorization = LiveAuthorizationStore::new(Default::default());
        let ingress_generation = authorization.snapshot().unwrap().version();
        let revoked_generation = authorization
            .publish_if_version(ingress_generation, Default::default())
            .unwrap();
        authorization
            .publish_if_version(revoked_generation, Default::default())
            .unwrap();
        assert!(matches!(
            verify_policy_generation(&authorization, ingress_generation),
            Err(ServiceTeacherCommandError::AuthorizationChangedDuringDispatch)
        ));
    }

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
    fn cancelled_ingress_or_executor_cannot_reuse_consumed_session() {
        let mut ingress = ExecutionState::default();
        ingress.begin_inflight().unwrap();
        // Dropping the async operation leaves the session retired.
        assert!(matches!(
            ingress.begin_inflight(),
            Err(ServiceTeacherCommandError::SessionRetired)
        ));
        let mut executor = ExecutionState::default();
        executor.begin_inflight().unwrap();
        assert!(matches!(
            executor.ensure_active(),
            Err(ServiceTeacherCommandError::SessionRetired)
        ));
        executor.finish_inflight();
        assert!(executor.ensure_active().is_ok());
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
