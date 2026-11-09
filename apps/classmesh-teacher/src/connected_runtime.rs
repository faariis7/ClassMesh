//! The owning authenticated Teacher control-session receiver drives the native UI.
//!
//! This module does not enroll credentials, create a QUIC endpoint, connect a
//! socket or mint authority. A caller supplies an *already authenticated*
//! StudentDevice control session and the trusted roster-bound receiver owner.
//! Exactly one reader owns that session. It never turns Hello/reconnect alone
//! into a live playback UI state.

use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::time::{Duration, Instant};

use classmesh_control::client_session::ClientControlSession;
use classmesh_control::live_authorization::LiveAuthorizationStore;
use classmesh_control::teacher_playback_receive::{
    TeacherControlSequenceGuard, receive_guarded_authenticated_teacher_control_on_split,
};
use classmesh_protocol::{
    Capability,
    control_wire::{
        ControlEnvelope, TeacherInteractionKind, TeacherInteractionState, control_envelope,
    },
    teacher_interaction,
};

use crate::connected_command::{
    QueuedTeacherUiAction, TeacherCommandSendError, TeacherCommandSender,
    next_queued_teacher_ui_action,
};
use crate::receiver_playback_session::{
    TeacherPlaybackSessionError, TeacherPlaybackSessionEvent, TeacherPlaybackSessionOwner,
};
use crate::ui_egui::TeacherUiControlEvent;
use crate::ui_shell::{TeacherInteractionUiContext, TeacherUiAction};

#[derive(Debug)]
pub enum TeacherConnectedPlaybackError {
    /// No playback UI authority without actual v0.8 negotiated capability.
    NotNegotiated,
    /// An old or substituted QUIC control session cannot bind to this owner.
    SessionMismatch,
    /// Real transport, peer authorization or replay failure; retire the route.
    Receive(Box<TeacherPlaybackSessionError>),
    /// No event was delivered. Drop this runtime's sole event sender so the
    /// native window sees terminal disconnect rather than partial readiness.
    WindowBusy,
    WindowDisconnected,
    /// Existing GUI action sender was dropped: a dead window cannot retain an
    /// apparently healthy authenticated control path.
    ActionChannelClosed,
    /// Creating the isolated network owner thread's Tokio event loop failed;
    /// the GUI must remain offline rather than treating that as a connection.
    RuntimeInitialization(std::io::Error),
    /// The UI is not allowed to mint control authority before a genuine
    /// verified playback observation established its exact source/session.
    NotBootstrapped,
    Command(TeacherCommandSendError),
}

fn send_window_event(
    sender: &SyncSender<TeacherUiControlEvent>,
    event: TeacherUiControlEvent,
) -> Result<(), TeacherConnectedPlaybackError> {
    match sender.try_send(event) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => Err(TeacherConnectedPlaybackError::WindowBusy),
        Err(TrySendError::Disconnected(_)) => {
            Err(TeacherConnectedPlaybackError::WindowDisconnected)
        }
    }
}

/// Drive the *existing* enrolled QUIC session, forwarding genuine verified
/// playback observations and returning unrelated authenticated messages to
/// the caller's original central dispatcher.
///
/// First visible auth/binding context is published only after a successful
/// authenticated live playback read and carries the exact negotiated session.
/// No fabricated playback, service availability or reconnect outcome is
/// delivered. If backpressure or transport/authentication fails, this
/// function returns an error and drops its **owned** event sender; the caller
/// must also retire the underlying client session/route. A replacement
/// session must use a fresh sender/owner and newly validated enrollment.
///
/// This deliberately does NOT run inside the shipped offline Teacher binary:
/// a caller must first obtain reviewed mTLS credentials, roster/source binding
/// and an existing authenticated client session from the real provisioning
/// owner. This is not a local-test shortcut or an enrollment implementation.
pub async fn drive_authenticated_teacher_playback(
    owner: &mut TeacherPlaybackSessionOwner,
    session: &mut ClientControlSession,
    authorization: &LiveAuthorizationStore,
    events: SyncSender<TeacherUiControlEvent>,
    mut dispatch_other: impl FnMut(ControlEnvelope) -> ControlFlow<()>,
    wall_clock_ms: impl Fn() -> u64,
    monotonic_now: impl Fn() -> Instant,
) -> Result<(), TeacherConnectedPlaybackError> {
    let binding = owner.binding();
    if session.established.control_session_id != binding.control_session_id {
        return Err(TeacherConnectedPlaybackError::SessionMismatch);
    }
    let negotiated = &session.established.negotiated;
    if negotiated.version.major != 0
        || negotiated.version.minor < 8
        || !negotiated
            .capabilities
            .contains(&Capability::ReceiverPlaybackDiagnostics)
    {
        return Err(TeacherConnectedPlaybackError::NotNegotiated);
    }

    let context = TeacherInteractionUiContext {
        source_id: owner.source_id(),
        control_session_id: binding.control_session_id,
        version: negotiated.version,
        capabilities: negotiated.capabilities.clone(),
    };
    let mut bootstrapped = false;
    loop {
        let read = owner
            .receive_next(session, authorization, &wall_clock_ms, &monotonic_now)
            .await
            .map_err(|err| TeacherConnectedPlaybackError::Receive(Box::new(err)))?;
        match read {
            TeacherPlaybackSessionEvent::OtherControl(envelope) => {
                if dispatch_other(envelope).is_break() {
                    return Ok(());
                }
            }
            TeacherPlaybackSessionEvent::Playback {
                verified,
                received_at,
                ..
            } => {
                if !bootstrapped {
                    send_window_event(
                        &events,
                        TeacherUiControlEvent::VerifiedBootstrap {
                            context: context.clone(),
                            binding,
                            source_id: owner.source_id(),
                            verified,
                            received_at,
                        },
                    )?;
                    bootstrapped = true;
                    continue;
                }
                send_window_event(
                    &events,
                    TeacherUiControlEvent::VerifiedPlayback {
                        source_id: owner.source_id(),
                        verified,
                        received_at,
                    },
                )?;
            }
        }
    }
}

/// The only dispatcher-visible outcomes of the owned duplex control runtime.
/// `CommandWritten` means a QUIC write completed, NEVER Service execution.
#[derive(Debug)]
pub enum TeacherDuplexDispatch {
    OtherControl(ControlEnvelope),
    LocalAction(TeacherUiAction),
    CommandWritten(u64),
}

/// Correlates only genuine authenticated responses with writes on this session.
#[derive(Default)]
struct PendingTeacherResults(BTreeMap<u64, TeacherInteractionKind>);

impl PendingTeacherResults {
    fn record(&mut self, request_id: u64, kind: TeacherInteractionKind) -> bool {
        if request_id == 0 || self.0.len() >= 64 || self.0.contains_key(&request_id) {
            return false;
        }
        self.0.insert(request_id, kind);
        true
    }

    fn can_send(&self) -> bool {
        self.0.len() < 64
    }

    fn verify(
        &mut self,
        envelope: &ControlEnvelope,
        session_id: u64,
    ) -> Option<TeacherInteractionState> {
        if envelope.control_session_id != session_id
            || envelope.request_id == 0
            || envelope.sequence == 0
        {
            return None;
        }
        let Some(control_envelope::Payload::TeacherInteractionResult(result)) = &envelope.payload
        else {
            return None;
        };
        let expected = self.0.get(&envelope.request_id)?;
        if teacher_interaction::validate_result(result).is_err() || result.kind != *expected as i32
        {
            return None;
        }
        let state = TeacherInteractionState::try_from(result.state).ok()?;
        if state != TeacherInteractionState::Accepted {
            self.0.remove(&envelope.request_id);
        }
        Some(state)
    }
}

/// Run real Teacher GUI observations and actions on one existing enrolled QUIC
/// connection and one sole replay-guarded network reader. The already-proven
/// Hello/control session is consumed; no new certificate, source roster, or
/// transport listener can be created here.
///
/// A single receive future remains pinned across all action-mailbox polls.
/// Dropping a partially read length-prefixed QUIC frame just to write an
/// action could desynchronize the next read, so this runtime only drops it
/// when retiring the ENTIRE connection. The caller owns independently
/// approved enrollment/provisioning and must never substitute a fake session.
/// The shipped offline Teacher UI does not invoke this path automatically.
///
/// The external dispatcher receives non-playback control envelopes untouched,
/// local-only UI actions untouched, and notification of a network write. No
/// action receipt claims remote authorization, ack, or Worker execution.
pub async fn drive_authenticated_teacher_duplex(
    owner: &mut TeacherPlaybackSessionOwner,
    session: ClientControlSession,
    authorization: &LiveAuthorizationStore,
    events: SyncSender<TeacherUiControlEvent>,
    actions: Receiver<TeacherUiAction>,
    mut dispatch: impl FnMut(TeacherDuplexDispatch) -> ControlFlow<()>,
    clocks: (impl Fn() -> u64, impl Fn() -> Instant),
) -> Result<(), TeacherConnectedPlaybackError> {
    let binding = owner.binding();
    if !owner.is_active() {
        return Err(TeacherConnectedPlaybackError::Receive(Box::new(
            TeacherPlaybackSessionError::Retired,
        )));
    }
    if session.established.control_session_id != binding.control_session_id {
        return Err(TeacherConnectedPlaybackError::SessionMismatch);
    }
    let negotiated = &session.established.negotiated;
    if negotiated.version.major != 0
        || negotiated.version.minor < 8
        || !negotiated
            .capabilities
            .contains(&Capability::ReceiverPlaybackDiagnostics)
    {
        return Err(TeacherConnectedPlaybackError::NotNegotiated);
    }
    let context = TeacherInteractionUiContext {
        source_id: owner.source_id(),
        control_session_id: binding.control_session_id,
        version: negotiated.version,
        capabilities: negotiated.capabilities.clone(),
    };
    let mut split = session.into_split();
    let mut reader_guard = TeacherControlSequenceGuard::default();
    let mut command_sender = TeacherCommandSender::default();
    let mut pending_results = PendingTeacherResults::default();
    let mut tick = tokio::time::interval(Duration::from_millis(15));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut bootstrapped = false;

    loop {
        // Keep this SAME in-flight read future alive across the whole inner
        // action loop. It owns the only receive half and replay ledger.
        let incoming = receive_guarded_authenticated_teacher_control_on_split(
            &split.connection,
            &split.established,
            &mut split.receiver,
            authorization,
            owner.expected_student(),
            &clocks.0,
            &mut reader_guard,
        );
        tokio::pin!(incoming);
        let received = loop {
            tokio::select! {
                biased;
                frame = &mut incoming => break frame,
                _ = tick.tick() => {
                    match next_queued_teacher_ui_action(&actions) {
                        QueuedTeacherUiAction::Empty => {}
                        QueuedTeacherUiAction::Closed => {
                            owner.retire_exact(owner.source_id(), binding);
                            split.connection.close(0u32.into(), b"Teacher UI action channel closed");
                            return Err(TeacherConnectedPlaybackError::ActionChannelClosed);
                        }
                        QueuedTeacherUiAction::Local(local) => {
                            if dispatch(TeacherDuplexDispatch::LocalAction(local)).is_break() {
                                owner.retire_exact(owner.source_id(), binding);
                                split.connection.close(0u32.into(), b"Teacher runtime dispatcher completed");
                                return Ok(());
                            }
                        }
                        QueuedTeacherUiAction::Interaction(action) => {
                            if !bootstrapped {
                                owner.retire_exact(owner.source_id(), binding);
                                split.connection.close(0u32.into(), b"Teacher unverified UI command");
                                return Err(TeacherConnectedPlaybackError::NotBootstrapped);
                            }
                            // Refuse before writing: every transmitted request must
                            // retain a correlation slot for its real Worker ACK.
                            if !pending_results.can_send() {
                                owner.retire_exact(owner.source_id(), binding);
                                split.connection.close(0u32.into(), b"Teacher pending results exhausted");
                                return Err(TeacherConnectedPlaybackError::NotBootstrapped);
                            }
                            match command_sender.send_on_split(
                                owner,
                                (&split.connection, &split.established),
                                &mut split.sender,
                                authorization,
                                &action,
                                &clocks.0,
                            ).await {
                                Ok(request_id) => {
                                    let kind = teacher_interaction::validate_request(&action.request)
                                        .map_err(|_| TeacherConnectedPlaybackError::NotBootstrapped)?;
                                    if !pending_results.record(request_id, kind) {
                                        owner.retire_exact(owner.source_id(), binding);
                                        split.connection.close(0u32.into(), b"Teacher pending results exhausted");
                                        return Err(TeacherConnectedPlaybackError::NotBootstrapped);
                                    }
                                    send_window_event(&events, TeacherUiControlEvent::CommandWritten {
                                        control_session_id: binding.control_session_id,
                                        request_id,
                                    })?;
                                    // This is only successful transmission. Service
                                    // authorization and ACK must arrive separately.
                                    if dispatch(TeacherDuplexDispatch::CommandWritten(request_id)).is_break() {
                                        owner.retire_exact(owner.source_id(), binding);
                                        split.connection.close(0u32.into(), b"Teacher runtime dispatcher completed");
                                        return Ok(());
                                    }
                                }
                                Err(error) => {
                                    owner.retire_exact(owner.source_id(), binding);
                                    split.connection.close(0u32.into(), b"Teacher command send rejected");
                                    return Err(TeacherConnectedPlaybackError::Command(error));
                                }
                            }
                        }
                    }
                }
            }
        };
        // The in-flight read has just completed: stop borrowing the sole
        // receive half/guard and hand its privately verified proof to owner.
        let verified = match received {
            Ok(verified) => verified,
            Err(error) => {
                owner.retire_exact(owner.source_id(), binding);
                split
                    .connection
                    .close(0u32.into(), b"Teacher authenticated receive failed");
                return Err(TeacherConnectedPlaybackError::Receive(Box::new(
                    TeacherPlaybackSessionError::Receive(error),
                )));
            }
        };
        let event = owner
            .accept_guarded_verified(verified, (clocks.1)())
            .map_err(|error| TeacherConnectedPlaybackError::Receive(Box::new(error)))?;
        match event {
            TeacherPlaybackSessionEvent::OtherControl(envelope) => {
                if let Some(state) = pending_results.verify(&envelope, binding.control_session_id) {
                    send_window_event(
                        &events,
                        TeacherUiControlEvent::CommandResult {
                            control_session_id: binding.control_session_id,
                            request_id: envelope.request_id,
                            state,
                        },
                    )?;
                }
                if dispatch(TeacherDuplexDispatch::OtherControl(envelope)).is_break() {
                    owner.retire_exact(owner.source_id(), binding);
                    split
                        .connection
                        .close(0u32.into(), b"Teacher runtime dispatcher completed");
                    return Ok(());
                }
            }
            TeacherPlaybackSessionEvent::Playback {
                verified,
                received_at,
                ..
            } => {
                let ui_event = if bootstrapped {
                    TeacherUiControlEvent::VerifiedPlayback {
                        source_id: owner.source_id(),
                        verified,
                        received_at,
                    }
                } else {
                    TeacherUiControlEvent::VerifiedBootstrap {
                        context: context.clone(),
                        binding,
                        source_id: owner.source_id(),
                        verified,
                        received_at,
                    }
                };
                if let Err(error) = send_window_event(&events, ui_event) {
                    owner.retire_exact(owner.source_id(), binding);
                    split
                        .connection
                        .close(0u32.into(), b"Teacher UI backpressure");
                    return Err(error);
                }
                bootstrapped = true;
            }
        }
    }
}

#[cfg(test)]
mod correlated_result_tests {
    use super::*;
    use classmesh_protocol::control_wire::{ProtocolVersion, TeacherInteractionResult};

    fn response(
        session: u64,
        request: u64,
        kind: TeacherInteractionKind,
        state: TeacherInteractionState,
    ) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: session,
            sequence: 9,
            request_id: request,
            protocol_version: Some(ProtocolVersion { major: 0, minor: 8 }),
            payload: Some(control_envelope::Payload::TeacherInteractionResult(
                TeacherInteractionResult {
                    kind: kind as i32,
                    state: state as i32,
                    diagnostic: String::new(),
                },
            )),
        }
    }

    #[test]
    fn pending_limit_blocks_before_network_write_and_reopens_after_terminal_ack() {
        let mut pending = PendingTeacherResults::default();
        for id in 1..=64 {
            assert!(pending.can_send());
            assert!(pending.record(id, TeacherInteractionKind::Message));
        }
        assert!(
            !pending.can_send(),
            "a 65th write must not leave an untracked command"
        );
        assert_eq!(
            pending.verify(
                &response(
                    21,
                    1,
                    TeacherInteractionKind::Message,
                    TeacherInteractionState::Completed
                ),
                21
            ),
            Some(TeacherInteractionState::Completed)
        );
        assert!(pending.can_send());
    }

    #[test]
    fn request_and_session_correlation_prevents_false_ack() {
        let mut pending = PendingTeacherResults::default();
        assert!(pending.record(7, TeacherInteractionKind::Message));
        assert_eq!(
            pending.verify(
                &response(
                    22,
                    7,
                    TeacherInteractionKind::Message,
                    TeacherInteractionState::Completed
                ),
                21
            ),
            None
        );
        assert_eq!(
            pending.verify(
                &response(
                    21,
                    8,
                    TeacherInteractionKind::Message,
                    TeacherInteractionState::Completed
                ),
                21
            ),
            None
        );
        assert_eq!(
            pending.verify(
                &response(
                    21,
                    7,
                    TeacherInteractionKind::OpenTarget,
                    TeacherInteractionState::Completed
                ),
                21
            ),
            None
        );
        assert_eq!(
            pending.verify(
                &response(
                    21,
                    7,
                    TeacherInteractionKind::Message,
                    TeacherInteractionState::Accepted
                ),
                21
            ),
            Some(TeacherInteractionState::Accepted)
        );
        assert_eq!(
            pending.verify(
                &response(
                    21,
                    7,
                    TeacherInteractionKind::Message,
                    TeacherInteractionState::Completed
                ),
                21
            ),
            Some(TeacherInteractionState::Completed)
        );
        assert_eq!(
            pending.verify(
                &response(
                    21,
                    7,
                    TeacherInteractionKind::Message,
                    TeacherInteractionState::Completed
                ),
                21
            ),
            None
        );
    }
}
