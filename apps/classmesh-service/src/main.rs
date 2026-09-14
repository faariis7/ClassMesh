#[cfg(windows)]
mod windows_service_app {
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::time::Duration;

    use classmesh_windows_runtime::{
        SessionEvent, SessionId, SessionSupervisor, SupervisorAction,
    };
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType, SessionChangeParam, SessionChangeReason,
    };
    use windows_service::service_control_handler::{
        self, ServiceControlHandlerResult, ServiceStatusHandle,
    };
    use windows_service::service_dispatcher;

    const SERVICE_NAME: &str = "ClassMeshService";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    windows_service::define_windows_service!(ffi_service_main, service_main);

    #[derive(Debug, Clone, Copy)]
    enum RuntimeEvent {
        Stop,
        Session(SessionEvent),
    }

    pub fn run() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(error) = run_service() {
            // Event Log integration comes later. Avoid panicking inside the SCM callback thread.
            eprintln!("ClassMesh service failed: {error}");
        }
    }

    fn run_service() -> windows_service::Result<()> {
        let (event_tx, event_rx) = mpsc::channel::<RuntimeEvent>();
        let handler_tx = event_tx.clone();

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = handler_tx.send(RuntimeEvent::Stop);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::SessionChange(change) => {
                    if let Some(event) = map_session_change(change) {
                        let _ = handler_tx.send(RuntimeEvent::Session(event));
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
        set_running(&status_handle)?;

        let mut supervisor = SessionSupervisor::default();
        loop {
            match event_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(RuntimeEvent::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Ok(RuntimeEvent::Session(event)) => {
                    let action = supervisor.on_event(event);
                    handle_supervisor_action(action);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Future work: worker health/restart watchdog and control heartbeat live here.
                }
            }
        }

        set_stopped(&status_handle)
    }

    fn set_running(handle: &ServiceStatusHandle) -> windows_service::Result<()> {
        handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP
                | ServiceControlAccept::SHUTDOWN
                | ServiceControlAccept::SESSION_CHANGE,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
    }

    fn set_stopped(handle: &ServiceStatusHandle) -> windows_service::Result<()> {
        handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
    }

    fn map_session_change(change: SessionChangeParam) -> Option<SessionEvent> {
        let session = SessionId(change.notification.session_id);
        match change.reason {
            SessionChangeReason::ConsoleConnect => Some(SessionEvent::ConsoleConnect(session)),
            SessionChangeReason::ConsoleDisconnect => {
                Some(SessionEvent::ConsoleDisconnect(session))
            }
            SessionChangeReason::RemoteConnect => Some(SessionEvent::RemoteConnect(session)),
            SessionChangeReason::RemoteDisconnect => Some(SessionEvent::RemoteDisconnect(session)),
            SessionChangeReason::SessionLogon => Some(SessionEvent::Logon(session)),
            SessionChangeReason::SessionLogoff => Some(SessionEvent::Logoff(session)),
            SessionChangeReason::SessionLock => Some(SessionEvent::Lock(session)),
            SessionChangeReason::SessionUnlock => Some(SessionEvent::Unlock(session)),
            SessionChangeReason::SessionCreate
            | SessionChangeReason::SessionTerminate
            | SessionChangeReason::SessionRemoteControl => None,
        }
    }

    fn handle_supervisor_action(action: SupervisorAction) {
        match action {
            SupervisorAction::None => {}
            SupervisorAction::LaunchWorker(session) => {
                // The Win32 token/process launcher is intentionally the next isolated component.
                // Do not call CreateProcess from Session 0 as a substitute.
                eprintln!("worker launch requested for Windows session {}", session.0);
            }
            SupervisorAction::StopWorker(session) => {
                eprintln!("worker stop requested for Windows session {}", session.0);
            }
            SupervisorAction::SuspendMedia(session) => {
                eprintln!("media suspend requested for Windows session {}", session.0);
            }
            SupervisorAction::ResumeMedia(session) => {
                eprintln!("media resume requested for Windows session {}", session.0);
            }
            SupervisorAction::ReplaceWorker {
                old_session,
                new_session,
            } => {
                eprintln!(
                    "worker replacement requested: session {} -> {}",
                    old_session.0, new_session.0
                );
            }
        }
    }
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    windows_service_app::run()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-service is supported only on Windows");
}
