//! Windows native GUI + an *already authenticated* QUIC Teacher owner.
//!
//! This is the production-lifecycle bridge between the existing native egui
//! window and the verified continuous duplex owner. It explicitly DOES NOT
//! enroll a Student, mint certificates, choose or approve a trusted CA,
//! establish transport, or install the protected Windows Service. The caller
//! must provide an independently provisioned and authorized Hello session and
//! current trusted roster/StudentDevice authority. Offline CLI mode stays OFF.

use std::ops::ControlFlow;
use std::sync::mpsc::sync_channel;
use std::thread::{self, JoinHandle};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use classmesh_control::client_session::ClientControlSession;
use classmesh_control::live_authorization::LiveAuthorizationStore;
use classmesh_protocol::Capability;

use crate::connected_runtime::{
    TeacherConnectedPlaybackError, TeacherDuplexDispatch, drive_authenticated_teacher_duplex,
};
use crate::receiver_playback_session::TeacherPlaybackSessionOwner;
use crate::ui_egui::{self, TeacherUiControlBridge};

/// This represents the one owned QUIC runtime thread, not a second receive
/// thread. Only the post-Hello stream's single receiver consumes control frames.
pub type EnrolledTeacherRuntimeThread = JoinHandle<Result<(), TeacherConnectedPlaybackError>>;

const UI_EVENT_CAPACITY: usize = 16;
const UI_ACTION_CAPACITY: usize = 16;

/// Fail closed before opening the native window or spawning a network thread.
/// This is a consistency preflight, not a substitute for mTLS peer, roster or
/// revocation checks inside the single authenticated QUIC owner.
fn validate_enrolled_startup(
    active: bool,
    expected_session_id: u64,
    actual_session_id: u64,
    major: u32,
    minor: u32,
    playback_capability: bool,
) -> Result<(), TeacherConnectedPlaybackError> {
    if !active || expected_session_id == 0 || expected_session_id != actual_session_id {
        return Err(TeacherConnectedPlaybackError::SessionMismatch);
    }
    if major != 0 || minor < 8 || !playback_capability {
        return Err(TeacherConnectedPlaybackError::NotNegotiated);
    }
    Ok(())
}

fn preflight_enrolled_session(
    owner: &TeacherPlaybackSessionOwner,
    session: &ClientControlSession,
) -> Result<(), TeacherConnectedPlaybackError> {
    let negotiated = &session.established.negotiated;
    validate_enrolled_startup(
        owner.is_active(),
        owner.binding().control_session_id,
        session.established.control_session_id,
        u32::from(negotiated.version.major),
        u32::from(negotiated.version.minor),
        negotiated
            .capabilities
            .contains(&Capability::ReceiverPlaybackDiagnostics),
    )
}

#[cfg(test)]
mod startup_preflight_tests {
    use super::*;

    #[test]
    fn refuses_stale_or_unnegotiated_session_before_native_window() {
        for (active, expected, actual, major, minor, capability) in [
            (false, 11, 11, 0, 8, true),
            (true, 0, 0, 0, 8, true),
            (true, 11, 12, 0, 8, true),
            (true, 11, 11, 1, 8, true),
            (true, 11, 11, 0, 7, true),
            (true, 11, 11, 0, 8, false),
        ] {
            assert!(
                validate_enrolled_startup(active, expected, actual, major, minor, capability)
                    .is_err()
            );
        }
        assert!(validate_enrolled_startup(true, 11, 11, 0, 8, true).is_ok());
    }
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

/// Start the trusted duplex owner on its own bounded lifecycle thread.
/// No event is emitted by construction: the native GUI starts disconnected,
/// and only the first real verified playback report may bootstrap the UI.
/// The required external control dispatcher handles local UI intents and all
/// authenticated non-playback replies; they are never silently discarded.
///
/// Closing/dropping the `TeacherUiControlBridge` drops its only action sender.
/// The runtime observes that closure and retires the whole QUIC connection;
/// callers MUST join the returned thread rather than leak a session owner.
pub fn start_enrolled_teacher_ui_runtime(
    owner: TeacherPlaybackSessionOwner,
    session: ClientControlSession,
    authorization: LiveAuthorizationStore,
    dispatch: impl FnMut(TeacherDuplexDispatch) -> ControlFlow<()> + Send + 'static,
) -> std::io::Result<(TeacherUiControlBridge, EnrolledTeacherRuntimeThread)> {
    let (event_tx, event_rx) = sync_channel(UI_EVENT_CAPACITY);
    let (action_tx, action_rx) = sync_channel(UI_ACTION_CAPACITY);
    let runtime_thread = thread::Builder::new()
        .name("classmesh-teacher-enrolled-quic".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(TeacherConnectedPlaybackError::RuntimeInitialization)?;
            let mut owner = owner;
            runtime.block_on(drive_authenticated_teacher_duplex(
                &mut owner,
                session,
                &authorization,
                event_tx,
                action_rx,
                dispatch,
                (unix_now_ms, Instant::now),
            ))
        })?;
    Ok((
        TeacherUiControlBridge::new(event_rx, action_tx),
        runtime_thread,
    ))
}

#[derive(Debug)]
pub enum EnrolledTeacherUiLaunchError {
    UntrustedStartup(TeacherConnectedPlaybackError),
    ThreadSpawn(std::io::Error),
    NativeWindow(eframe::Error),
    ControlRuntime(TeacherConnectedPlaybackError),
    ControlThreadPanicked,
}

impl std::fmt::Display for EnrolledTeacherUiLaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UntrustedStartup(error) => write!(f, "Teacher startup rejected: {error:?}"),
            Self::ThreadSpawn(error) => {
                write!(f, "Teacher control thread could not start: {error}")
            }
            Self::NativeWindow(error) => write!(f, "Teacher native window failed: {error}"),
            Self::ControlRuntime(error) => {
                write!(f, "Teacher authenticated control runtime: {error:?}")
            }
            Self::ControlThreadPanicked => {
                f.write_str("Teacher authenticated control thread panicked")
            }
        }
    }
}

impl std::error::Error for EnrolledTeacherUiLaunchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ThreadSpawn(error) => Some(error),
            Self::NativeWindow(error) => Some(error),
            Self::UntrustedStartup(_) | Self::ControlRuntime(_) | Self::ControlThreadPanicked => {
                None
            }
        }
    }
}

/// Run the actual Windows GUI on the caller's native event-loop thread, with
/// the one authenticated QUIC session on the joined Tokio owner thread.
///
/// There is no fallback to a fabricated session or offline-success status.
/// A normally closed window retires the action channel and owned connection.
/// If the peer loses authority, the event sender closes and the GUI reports
/// disconnection; once the window exits the error is returned to the caller.
pub fn run_teacher_ui_with_enrolled_session(
    owner: TeacherPlaybackSessionOwner,
    session: ClientControlSession,
    authorization: LiveAuthorizationStore,
    dispatch: impl FnMut(TeacherDuplexDispatch) -> ControlFlow<()> + Send + 'static,
) -> Result<(), EnrolledTeacherUiLaunchError> {
    preflight_enrolled_session(&owner, &session)
        .map_err(EnrolledTeacherUiLaunchError::UntrustedStartup)?;
    let (bridge, runtime_thread) =
        start_enrolled_teacher_ui_runtime(owner, session, authorization, dispatch)
            .map_err(EnrolledTeacherUiLaunchError::ThreadSpawn)?;
    let window = ui_egui::run_teacher_ui_with_control_bridge(bridge);
    // run_native returned: its app/bridge (and thus its final action sender)
    // was dropped. Join before reporting native launch success.
    let control = runtime_thread
        .join()
        .map_err(|_| EnrolledTeacherUiLaunchError::ControlThreadPanicked)?;
    window.map_err(EnrolledTeacherUiLaunchError::NativeWindow)?;
    match control {
        Ok(()) | Err(TeacherConnectedPlaybackError::ActionChannelClosed) => Ok(()),
        Err(error) => Err(EnrolledTeacherUiLaunchError::ControlRuntime(error)),
    }
}
