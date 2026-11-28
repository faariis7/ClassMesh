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
use classmesh_protocol::{Capability, ControlRole, teacher_interaction};

use crate::connected_command::{TeacherControlRoute, verify_current_student};
use crate::connected_runtime::{
    TeacherConnectedPlaybackError, TeacherDuplexDispatch, drive_authenticated_teacher_control,
    drive_authenticated_teacher_duplex,
};
use crate::receiver_playback_session::TeacherPlaybackSessionOwner;
use crate::ui_egui::{self, InstalledMessageTarget, TeacherUiControlBridge};

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
    usable_capability: bool,
    teacher_role: bool,
) -> Result<(), TeacherConnectedPlaybackError> {
    if !active || expected_session_id == 0 || expected_session_id != actual_session_id {
        return Err(TeacherConnectedPlaybackError::SessionMismatch);
    }
    if !teacher_role || major != 0 || minor < 8 || !usable_capability {
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
            .contains(&Capability::ReceiverPlaybackDiagnostics)
            || teacher_interaction::teacher_message_available(
                negotiated.version,
                &negotiated.capabilities,
            )
            || teacher_interaction::open_target_available(
                negotiated.version,
                &negotiated.capabilities,
            ),
        negotiated.role == ControlRole::Teacher,
    )
}

#[cfg(test)]
mod startup_preflight_tests {
    use super::*;

    #[test]
    fn closed_window_race_is_normal_only_after_gui_exit() {
        // A native window may close before authentication is published:
        // both channel-close outcomes mean the sole control owner retired.
        assert!(super::classify_runtime_after_clean_window_exit(Ok(())).is_ok());
        assert!(
            super::classify_runtime_after_clean_window_exit(Err(
                TeacherConnectedPlaybackError::ActionChannelClosed
            ))
            .is_ok()
        );
        assert!(
            super::classify_runtime_after_clean_window_exit(Err(
                TeacherConnectedPlaybackError::WindowDisconnected
            ))
            .is_ok()
        );
        // Never suppress authorization failures just because the GUI exited.
        assert!(matches!(
            super::classify_runtime_after_clean_window_exit(Err(
                TeacherConnectedPlaybackError::NotNegotiated
            )),
            Err(super::EnrolledTeacherUiLaunchError::ControlRuntime(
                TeacherConnectedPlaybackError::NotNegotiated
            ))
        ));
    }

    #[test]
    fn refuses_stale_or_unnegotiated_session_before_native_window() {
        for (active, expected, actual, major, minor, capability, teacher_role) in [
            (false, 11, 11, 0, 8, true, true),
            (true, 0, 0, 0, 8, true, true),
            (true, 11, 12, 0, 8, true, true),
            (true, 11, 11, 1, 8, true, true),
            (true, 11, 11, 0, 7, true, true),
            (true, 11, 11, 0, 8, false, true),
            (true, 11, 11, 0, 8, true, false),
        ] {
            assert!(
                validate_enrolled_startup(
                    active,
                    expected,
                    actual,
                    major,
                    minor,
                    capability,
                    teacher_role
                )
                .is_err()
            );
        }
        assert!(validate_enrolled_startup(true, 11, 11, 0, 8, true, true).is_ok());
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
    preflight_enrolled_session(&owner, &session).map_err(startup_permission_denied)?;
    start_native_runtime(
        NativeTeacherRoute::Playback(Box::new(owner)),
        session,
        authorization,
        dispatch,
    )
}

/// Start the native control bridge with approved route inputs before playback exists.
pub fn start_enrolled_teacher_control_ui_runtime(
    route: TeacherControlRoute,
    session: ClientControlSession,
    authorization: LiveAuthorizationStore,
    dispatch: impl FnMut(TeacherDuplexDispatch) -> ControlFlow<()> + Send + 'static,
) -> std::io::Result<(TeacherUiControlBridge, EnrolledTeacherRuntimeThread)> {
    preflight_control_route(route, &session, &authorization).map_err(startup_permission_denied)?;
    start_native_runtime(
        NativeTeacherRoute::Control(route),
        session,
        authorization,
        dispatch,
    )
}

fn preflight_control_route(
    route: TeacherControlRoute,
    session: &ClientControlSession,
    authorization: &LiveAuthorizationStore,
) -> Result<(), TeacherConnectedPlaybackError> {
    let negotiated = &session.established.negotiated;
    validate_enrolled_startup(
        route.is_active(),
        route.control_session_id(),
        session.established.control_session_id,
        u32::from(negotiated.version.major),
        u32::from(negotiated.version.minor),
        teacher_interaction::teacher_message_available(
            negotiated.version,
            &negotiated.capabilities,
        ) || teacher_interaction::open_target_available(
            negotiated.version,
            &negotiated.capabilities,
        ),
        negotiated.role == ControlRole::Teacher,
    )?;
    verify_current_student(
        route.expected_student(),
        &session.connection,
        authorization,
        unix_now_ms(),
    )
    .map_err(TeacherConnectedPlaybackError::Command)
}

fn startup_permission_denied(error: TeacherConnectedPlaybackError) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("Teacher enrolled startup rejected: {error:?}"),
    )
}

enum NativeTeacherRoute {
    Control(TeacherControlRoute),
    Playback(Box<TeacherPlaybackSessionOwner>),
}

fn start_native_runtime(
    route: NativeTeacherRoute,
    session: ClientControlSession,
    authorization: LiveAuthorizationStore,
    dispatch: impl FnMut(TeacherDuplexDispatch) -> ControlFlow<()> + Send + 'static,
) -> std::io::Result<(TeacherUiControlBridge, EnrolledTeacherRuntimeThread)> {
    start_runtime_thread(move |event_tx, action_rx| {
        // The synchronous caller already rejected invalid authority; no
        // Tokio runtime or transport exists before that check.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(TeacherConnectedPlaybackError::RuntimeInitialization)?;
        match route {
            NativeTeacherRoute::Playback(mut owner) => {
                runtime.block_on(drive_authenticated_teacher_duplex(
                    &mut owner,
                    session,
                    &authorization,
                    event_tx,
                    action_rx,
                    dispatch,
                    (unix_now_ms, Instant::now),
                ))
            }
            NativeTeacherRoute::Control(route) => {
                runtime.block_on(drive_authenticated_teacher_control(
                    route,
                    session,
                    &authorization,
                    event_tx,
                    action_rx,
                    dispatch,
                    (unix_now_ms, Instant::now),
                ))
            }
        }
    })
}

fn start_runtime_thread(
    run: impl FnOnce(
        std::sync::mpsc::SyncSender<crate::ui_egui::TeacherUiControlEvent>,
        std::sync::mpsc::Receiver<crate::ui_shell::TeacherUiAction>,
    ) -> Result<(), TeacherConnectedPlaybackError>
    + Send
    + 'static,
) -> std::io::Result<(TeacherUiControlBridge, EnrolledTeacherRuntimeThread)> {
    let (event_tx, event_rx) = sync_channel(UI_EVENT_CAPACITY);
    let (action_tx, action_rx) = sync_channel(UI_ACTION_CAPACITY);
    let runtime_thread = thread::Builder::new()
        .name("classmesh-teacher-enrolled-quic".to_owned())
        .spawn(move || run(event_tx, action_rx))?;
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

/// A normally closed native window drops both its GUI action sender and
/// control-event receiver. The Tokio owner can observe either closure first;
/// both outcomes retire its authenticated QUIC connection. This normalization
/// is used ONLY after run_native has returned successfully and the owner was
/// joined; live authorization, transport and backpressure errors still fail.
fn classify_runtime_after_clean_window_exit(
    control: Result<(), TeacherConnectedPlaybackError>,
) -> Result<(), EnrolledTeacherUiLaunchError> {
    match control {
        Ok(())
        | Err(TeacherConnectedPlaybackError::ActionChannelClosed)
        | Err(TeacherConnectedPlaybackError::WindowDisconnected) => Ok(()),
        Err(error) => Err(EnrolledTeacherUiLaunchError::ControlRuntime(error)),
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
    run_native_window(bridge, runtime_thread, None)
}

/// Launch the actual Windows Teacher window for an independently authorized M2 route.
pub fn run_teacher_ui_with_enrolled_control(
    route: TeacherControlRoute,
    session: ClientControlSession,
    authorization: LiveAuthorizationStore,
    dispatch: impl FnMut(TeacherDuplexDispatch) -> ControlFlow<()> + Send + 'static,
) -> Result<(), EnrolledTeacherUiLaunchError> {
    preflight_control_route(route, &session, &authorization)
        .map_err(EnrolledTeacherUiLaunchError::UntrustedStartup)?;
    let (bridge, runtime_thread) = start_native_runtime(
        NativeTeacherRoute::Control(route),
        session,
        authorization,
        dispatch,
    )
    .map_err(EnrolledTeacherUiLaunchError::ThreadSpawn)?;
    run_native_window(bridge, runtime_thread, None)
}

/// Installed Live Mode and the read-only startup probe share the same
/// protected producer and preflight. Both preserve the same QUIC runtime.
pub fn run_installed_teacher(check_only: bool) -> Result<(), Box<dyn std::error::Error>> {
    use crate::connected_runtime::drive_installed_teacher_control;
    use crate::installed_presentation::{InstalledPresentation, PresentationRoute};
    use crate::trusted_startup::{PreparedTeacher, prepare_installed_teacher};

    let PreparedTeacher {
        runtime,
        endpoint,
        session,
        route,
        authorization,
        display_name,
        clock,
        presentation,
    } = prepare_installed_teacher().map_err(|error| -> Box<dyn std::error::Error> { error })?;
    preflight_control_route(route, &session, &authorization)
        .map_err(EnrolledTeacherUiLaunchError::UntrustedStartup)?;
    if clock() == u64::MAX {
        return Err(
            "protected Teacher policy changed or expired before the native launcher".into(),
        );
    }
    if check_only {
        let negotiated = &session.established.negotiated;
        let teacher_message = teacher_interaction::teacher_message_available(
            negotiated.version,
            &negotiated.capabilities,
        );
        session
            .connection
            .close(0u32.into(), b"Teacher startup probe complete");
        runtime.block_on(async {
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(3), endpoint.wait_idle()).await;
        });
        println!("Teacher protected roster, CNG identity and enrolled QUIC session verified");
        println!("TeacherMessage negotiated: {teacher_message}");
        return Ok(());
    }

    let target = InstalledMessageTarget {
        source: route.source_id(),
        session: route.control_session_id(),
        display_name,
    };
    let presentation = InstalledPresentation::new(
        presentation,
        PresentationRoute {
            route,
            authorization: std::sync::Arc::new(authorization),
            clock,
        },
    );
    let (bridge, thread) = start_runtime_thread(move |events, actions| {
        let result = runtime.block_on(drive_installed_teacher_control(
            presentation,
            session,
            events,
            actions,
        ));
        drop(endpoint);
        result
    })
    .map_err(EnrolledTeacherUiLaunchError::ThreadSpawn)?;
    run_native_window(bridge, thread, Some(target))?;
    Ok(())
}

fn run_native_window(
    bridge: TeacherUiControlBridge,
    runtime_thread: EnrolledTeacherRuntimeThread,
    target: Option<InstalledMessageTarget>,
) -> Result<(), EnrolledTeacherUiLaunchError> {
    let window = ui_egui::run_teacher_window(bridge, target);
    // run_native returned: its app/bridge (and thus its final action sender)
    // was dropped. Join before reporting native launch success.
    let control = runtime_thread
        .join()
        .map_err(|_| EnrolledTeacherUiLaunchError::ControlThreadPanicked)?;
    window.map_err(EnrolledTeacherUiLaunchError::NativeWindow)?;
    classify_runtime_after_clean_window_exit(control)
}
