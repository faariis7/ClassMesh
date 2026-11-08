//! The owning authenticated Teacher control-session receiver drives the native UI.
//!
//! This module does not enroll credentials, create a QUIC endpoint, connect a
//! socket or mint authority. A caller supplies an *already authenticated*
//! StudentDevice control session and the trusted roster-bound receiver owner.
//! Exactly one reader owns that session. It never turns Hello/reconnect alone
//! into a live playback UI state.

use std::ops::ControlFlow;
use std::sync::mpsc::{SyncSender, TrySendError};
use std::time::Instant;

use classmesh_control::client_session::ClientControlSession;
use classmesh_control::live_authorization::LiveAuthorizationStore;
use classmesh_protocol::{Capability, control_wire::ControlEnvelope};

use crate::receiver_playback_session::{
    TeacherPlaybackSessionError, TeacherPlaybackSessionEvent, TeacherPlaybackSessionOwner,
};
use crate::ui_egui::TeacherUiControlEvent;
use crate::ui_shell::TeacherInteractionUiContext;

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
