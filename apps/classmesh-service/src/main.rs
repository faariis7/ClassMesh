#[cfg(windows)]
mod windows_service_app {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    use classmesh_win32::{
        NamedPipeServer, SessionProcess, launch_worker_in_session, worker_pipe_name,
    };
    use classmesh_windows_runtime::ipc::{
        IpcControlCommand, IpcFrame, IpcFrameDecoder, IpcMessage,
    };
    use classmesh_windows_runtime::worker::{
        WorkerProcess, WorkerRestartDecision, WorkerRestartPolicy, WorkerWatchdog,
    };
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

    #[derive(Debug, Clone, Copy)]
    enum WorkerManagerEvent {
        Running(SessionId),
        RestartScheduled(SessionId),
        GiveUp(SessionId),
        None,
    }

    #[derive(Debug)]
    struct WorkerManager {
        executable: Option<PathBuf>,
        process: Option<SessionProcess>,
        pipe: Option<NamedPipeServer>,
        watchdog: WorkerWatchdog,
        pending_restart: Option<(SessionId, Instant)>,
        generation: u64,
        clock: Instant,
    }

    impl WorkerManager {
        fn new() -> Self {
            let executable = std::env::current_exe().ok().map(|service| {
                service.parent().map_or_else(
                    || PathBuf::from("classmesh-worker.exe"),
                    |dir| dir.join("classmesh-worker.exe"),
                )
            });
            Self {
                executable,
                process: None,
                pipe: None,
                watchdog: WorkerWatchdog::new(WorkerRestartPolicy::default()),
                pending_restart: None,
                generation: 0,
                clock: Instant::now(),
            }
        }

        fn launch(&mut self, session: SessionId) -> WorkerManagerEvent {
            let now_us = self.now_us();
            let Some(executable) = self.executable.as_deref() else {
                eprintln!("cannot resolve classmesh-worker.exe next to the service binary");
                let decision = self.watchdog.launch_failed(session);
                return self.apply_restart_decision(decision);
            };

            let pipe_name = worker_pipe_name(std::process::id(), session.0, self.generation);
            self.generation = self.generation.wrapping_add(1);
            let mut pipe = match NamedPipeServer::create(&pipe_name) {
                Ok(pipe) => pipe,
                Err(error) => {
                    eprintln!("failed to create Worker IPC pipe for session {}: {error}", session.0);
                    let decision = self.watchdog.launch_failed(session);
                    return self.apply_restart_decision(decision);
                }
            };

            let extra_args = [OsString::from("--pipe"), OsString::from(&pipe_name)];
            match launch_worker_in_session(session.0, executable, &extra_args) {
                Ok(mut process) => {
                    let process_id = process.process_id();
                    if let Err(error) = pipe.accept_expected(process_id, session.0) {
                        eprintln!(
                            "Worker IPC peer validation failed for pid {process_id}, session {}: {error}",
                            session.0
                        );
                        let _ = process.terminate(1);
                        let decision = self.watchdog.launch_failed(session);
                        return self.apply_restart_decision(decision);
                    }

                    if let Err(error) = authenticate_worker(&pipe, process_id, session) {
                        eprintln!(
                            "Worker IPC handshake failed for pid {process_id}, session {}: {error}",
                            session.0
                        );
                        let _ = process.terminate(1);
                        let decision = self.watchdog.launch_failed(session);
                        return self.apply_restart_decision(decision);
                    }

                    eprintln!(
                        "ClassMesh Worker {process_id} launched and IPC-bound in Windows session {}",
                        process.session_id()
                    );
                    self.watchdog.launched(WorkerProcess {
                        session,
                        process_id,
                        launched_at_us: now_us,
                    });
                    self.pipe = Some(pipe);
                    self.process = Some(process);
                    self.pending_restart = None;
                    WorkerManagerEvent::Running(session)
                }
                Err(error) => {
                    eprintln!("failed to launch Worker for session {}: {error}", session.0);
                    let decision = self.watchdog.launch_failed(session);
                    self.apply_restart_decision(decision)
                }
            }
        }

        fn stop(&mut self, session: SessionId) {
            if self
                .pending_restart
                .is_some_and(|(pending, _)| pending == session)
            {
                self.pending_restart = None;
            }
            self.watchdog.stopped_intentionally(session);

            if !self
                .process
                .as_ref()
                .is_some_and(|process| process.session_id() == session.0)
            {
                return;
            }

            if let Some(pipe) = self.pipe.as_ref()
                && let Err(error) = send_control(pipe, IpcControlCommand::Shutdown)
            {
                eprintln!("failed to request graceful Worker shutdown: {error}");
            }

            if let Some(process) = self.process.as_mut() {
                for _ in 0..25 {
                    match process.is_running() {
                        Ok(false) => break,
                        Ok(true) => thread::sleep(Duration::from_millis(10)),
                        Err(error) => {
                            eprintln!("Worker shutdown liveness probe failed: {error}");
                            break;
                        }
                    }
                }
                if process.is_running().unwrap_or(true)
                    && let Err(error) = process.terminate(0)
                {
                    eprintln!(
                        "failed to terminate Worker {} for session {}: {error}",
                        process.process_id(),
                        session.0
                    );
                }
            }

            self.pipe = None;
            self.process = None;
        }

        fn stop_any(&mut self) {
            self.pending_restart = None;
            let session = self
                .process
                .as_ref()
                .map(|process| SessionId(process.session_id()));
            if let Some(session) = session {
                self.stop(session);
            }
        }

        fn send_control(&self, session: SessionId, command: IpcControlCommand) {
            if !self
                .process
                .as_ref()
                .is_some_and(|process| process.session_id() == session.0)
            {
                eprintln!(
                    "ignoring IPC command for session {}; no matching Worker is running",
                    session.0
                );
                return;
            }

            let Some(pipe) = self.pipe.as_ref() else {
                eprintln!("Worker IPC pipe is unavailable for session {}", session.0);
                return;
            };
            if let Err(error) = send_control(pipe, command) {
                eprintln!("failed to send Worker IPC command: {error}");
            }
        }

        fn poll(&mut self) -> WorkerManagerEvent {
            let exited = self
                .process
                .as_ref()
                .and_then(|process| match process.is_running() {
                    Ok(true) => None,
                    Ok(false) => Some((SessionId(process.session_id()), process.process_id())),
                    Err(error) => {
                        eprintln!("Worker liveness probe failed: {error}");
                        None
                    }
                });

            if let Some((session, process_id)) = exited {
                eprintln!(
                    "ClassMesh Worker {process_id} exited from session {}",
                    session.0
                );
                self.pipe = None;
                self.process = None;
                let decision =
                    self.watchdog
                        .exited_unexpectedly(self.now_us(), session, process_id);
                return self.apply_restart_decision(decision);
            }

            if let Some((session, due)) = self.pending_restart
                && Instant::now() >= due
            {
                self.pending_restart = None;
                return self.launch(session);
            }

            WorkerManagerEvent::None
        }

        fn apply_restart_decision(
            &mut self,
            decision: WorkerRestartDecision,
        ) -> WorkerManagerEvent {
            match decision {
                WorkerRestartDecision::RelaunchAfter { session, delay_us } => {
                    let delay = Duration::from_micros(delay_us);
                    let due = Instant::now()
                        .checked_add(delay)
                        .unwrap_or_else(Instant::now);
                    self.pending_restart = Some((session, due));
                    eprintln!(
                        "Worker restart scheduled for session {} in {} ms",
                        session.0,
                        delay.as_millis()
                    );
                    WorkerManagerEvent::RestartScheduled(session)
                }
                WorkerRestartDecision::GiveUp { session } => {
                    self.pending_restart = None;
                    eprintln!(
                        "Worker restart limit reached for session {}; media remains unavailable while service/control stays alive",
                        session.0
                    );
                    WorkerManagerEvent::GiveUp(session)
                }
                WorkerRestartDecision::Ignore => WorkerManagerEvent::None,
            }
        }

        fn now_us(&self) -> u64 {
            u64::try_from(self.clock.elapsed().as_micros()).unwrap_or(u64::MAX)
        }
    }

    fn authenticate_worker(
        pipe: &NamedPipeServer,
        expected_process_id: u32,
        expected_session: SessionId,
    ) -> Result<(), String> {
        let hello = read_one_frame(pipe)?;
        match hello
            .message()
            .map_err(|error| format!("invalid Worker hello: {error:?}"))?
        {
            IpcMessage::WorkerHello {
                process_id,
                session_id,
            } if process_id == expected_process_id && session_id == expected_session.0 => {}
            message => {
                return Err(format!("unexpected Worker hello identity/message: {message:?}"));
            }
        }

        let ready = IpcFrame::service_ready()
            .encode()
            .map_err(|error| format!("failed to encode ServiceReady: {error:?}"))?;
        pipe.write_all(&ready)
            .map_err(|error| format!("failed to send ServiceReady: {error}"))
    }

    fn read_one_frame(pipe: &NamedPipeServer) -> Result<IpcFrame, String> {
        let mut decoder = IpcFrameDecoder::default();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = pipe
                .read(&mut buffer)
                .map_err(|error| format!("Worker IPC read failed: {error}"))?;
            if read == 0 {
                return Err("Worker IPC pipe closed during handshake".to_owned());
            }
            let mut frames = decoder
                .push_bytes(&buffer[..read])
                .map_err(|error| format!("Worker IPC frame error: {error:?}"))?;
            if !frames.is_empty() {
                return Ok(frames.remove(0));
            }
        }
    }

    fn send_control(pipe: &NamedPipeServer, command: IpcControlCommand) -> Result<(), String> {
        let bytes = IpcFrame::control(command)
            .encode()
            .map_err(|error| format!("failed to encode Worker control frame: {error:?}"))?;
        pipe.write_all(&bytes)
            .map_err(|error| format!("Worker IPC write failed: {error}"))
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
            match event_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(RuntimeEvent::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Ok(RuntimeEvent::Session(event)) => {
                    let action = supervisor.on_event(event);
                    handle_supervisor_action(action, &mut supervisor, &mut workers);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let event = workers.poll();
                    handle_worker_event(event, &mut supervisor);
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

    fn handle_supervisor_action(
        action: SupervisorAction,
        supervisor: &mut SessionSupervisor,
        workers: &mut WorkerManager,
    ) {
        match action {
            SupervisorAction::None => {}
            SupervisorAction::LaunchWorker(session) => {
                let event = workers.launch(session);
                handle_worker_event(event, supervisor);
            }
            SupervisorAction::StopWorker(session) => {
                workers.stop(session);
                supervisor.mark_worker_stopped(session);
            }
            SupervisorAction::SuspendMedia(session) => {
                workers.send_control(session, IpcControlCommand::SuspendMedia);
            }
            SupervisorAction::ResumeMedia(session) => {
                workers.send_control(session, IpcControlCommand::ResumeMedia);
            }
            SupervisorAction::ReplaceWorker {
                old_session,
                new_session,
            } => {
                workers.stop(old_session);
                let event = workers.launch(new_session);
                handle_worker_event(event, supervisor);
            }
        }
    }

    fn handle_worker_event(event: WorkerManagerEvent, supervisor: &mut SessionSupervisor) {
        match event {
            WorkerManagerEvent::Running(session) => supervisor.mark_worker_running(session),
            WorkerManagerEvent::RestartScheduled(session) => {
                let _ = supervisor.worker_crashed(session);
            }
            WorkerManagerEvent::GiveUp(session) => supervisor.mark_worker_stopped(session),
            WorkerManagerEvent::None => {}
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
