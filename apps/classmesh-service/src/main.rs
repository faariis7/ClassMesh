#[cfg(windows)]
mod windows_service_app {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::Duration;

    use classmesh_win32::{SessionProcess, launch_worker_in_session};
    use classmesh_windows_runtime::{SessionEvent, SessionId, SessionSupervisor, SupervisorAction};
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

    #[derive(Debug)]
    struct WorkerManager {
        executable: Option<PathBuf>,
        process: Option<SessionProcess>,
    }

    impl WorkerManager {
        fn new() -> Self {
            let executable = std::env::current_exe().ok().map(|service| {
                service
                    .parent()
                    .map_or_else(|| PathBuf::from("classmesh-worker.exe"), |dir| dir.join("classmesh-worker.exe"))
            });
            Self {
                executable,
                process: None,
            }
        }

        fn launch(&mut self, session: SessionId) -> bool {
            let Some(executable) = self.executable.as_deref() else {
                eprintln!("cannot resolve classmesh-worker.exe next to the service binary");
                return false;
            };

            match launch_worker_in_session(session.0, executable, &[]) {
                Ok(process) => {
                    eprintln!(
                        "ClassMesh Worker {} launched in Windows session {}",
                        process.process_id(),
                        process.session_id()
                    );
                    self.process = Some(process);
                    true
                }
                Err(error) => {
                    eprintln!("failed to launch Worker for session {}: {error}", session.0);
                    false
                }
            }
        }

        fn stop(&mut self, session: SessionId) {
            let Some(process) = self.process.as_mut() else {
                return;
            };
            if process.session_id() != session.0 {
                return;
            }
            if let Err(error) = process.terminate(0) {
                eprintln!(
                    "failed to terminate Worker {} for session {}: {error}",
                    process.process_id(),
                    session.0
                );
            }
            self.process = None;
        }

        fn stop_any(&mut self) {
            let session = self.process.as_ref().map(|process| SessionId(process.session_id()));
            if let Some(session) = session {
                self.stop(session);
            }
        }

        fn poll_exit(&mut self) -> Option<SessionId> {
            let process = self.process.as_ref()?;
            match process.is_running() {
                Ok(true) => None,
                Ok(false) => {
                    let session = SessionId(process.session_id());
                    eprintln!(
                        "ClassMesh Worker {} exited from session {}",
                        process.process_id(),
                        session.0
                    );
                    self.process = None;
                    Some(session)
                }
                Err(error) => {
                    eprintln!("Worker liveness probe failed: {error}");
                    None
                }
            }
        }
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
        let mut workers = WorkerManager::new();
        loop {
            match event_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(RuntimeEvent::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Ok(RuntimeEvent::Session(event)) => {
                    let action = supervisor.on_event(event);
                    handle_supervisor_action(action, &mut supervisor, &mut workers);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(session) = workers.poll_exit() {
                        supervisor.mark_worker_stopped(session);
                        let action = supervisor.worker_crashed(session);
                        handle_supervisor_action(action, &mut supervisor, &mut workers);
                    }
                }
            }
        }

        workers.stop_any();
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
            SessionChangeReason::ConsoleDisconnect => Some(SessionEvent::ConsoleDisconnect(session)),
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

    fn handle_supervisor_action(
        action: SupervisorAction,
        supervisor: &mut SessionSupervisor,
        workers: &mut WorkerManager,
    ) {
        match action {
            SupervisorAction::None => {}
            SupervisorAction::LaunchWorker(session) => {
                if workers.launch(session) {
                    supervisor.mark_worker_running(session);
                }
            }
            SupervisorAction::StopWorker(session) => {
                workers.stop(session);
                supervisor.mark_worker_stopped(session);
            }
            SupervisorAction::SuspendMedia(session) => {
                // Media suspension will move to authenticated IPC instead of killing the Worker.
                eprintln!("media suspend requested for Windows session {}", session.0);
            }
            SupervisorAction::ResumeMedia(session) => {
                eprintln!("media resume requested for Windows session {}", session.0);
            }
            SupervisorAction::ReplaceWorker {
                old_session,
                new_session,
            } => {
                workers.stop(old_session);
                if workers.launch(new_session) {
                    supervisor.mark_worker_running(new_session);
                }
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
