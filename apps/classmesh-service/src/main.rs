#[cfg(windows)]
mod control_runtime;

#[cfg(windows)]
mod windows_service_app {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
    use std::sync::{Arc, mpsc};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use classmesh_codec_win::capability_cache::DurableEncoderCapabilityCache;
    use classmesh_codec_win::{EncoderBenchmarkResult, EncoderCapabilityCacheKey};
    use classmesh_identity_win::{CngMachineKey, DurableMachineIdentity};
    use classmesh_protocol::control_wire::{InputEvent, StreamReconfigure};
    use classmesh_security::persistence::DurableAuthorizationState;
    use classmesh_security::{CredentialFingerprint, PrincipalId};
    use classmesh_video::{Codec, EncoderClass, EncoderProbeResult};
    use sha2::{Digest, Sha256};

    use classmesh_win32::{
        NamedPipeServer, SessionProcess, launch_worker_in_session, session_user_sid,
        worker_pipe_name,
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
    const STATE_DIRECTORY: &str = "ClassMesh\\state";
    const CONFIG_DIRECTORY: &str = "ClassMesh\\config";
    const MACHINE_IDENTITY_FILE: &str = "machine-identity.json";
    const AUTHORIZATION_FILE: &str = "authorization.json";
    const ENCODER_CAPABILITY_CACHE_FILE: &str = "encoder-capability.json";
    const CONTROL_RUNTIME_CONFIG_FILE: &str = "control-runtime.json";
    const INPUT_QUEUE_CAPACITY: usize = 256;
    const INPUT_CLEANUP_QUEUE_CAPACITY: usize = 1;
    const FOCUSED_MEDIA_QUEUE_CAPACITY: usize = 4;
    const MAX_INPUT_EVENTS_PER_TICK: usize = 64;
    const MEDIA_RECONFIGURE_RETRY: Duration = Duration::from_millis(250);
    const MAX_MEDIA_RECONFIGURE_ATTEMPTS: u8 = 4;

    use crate::control_runtime::{
        ControlRuntime, ControlRuntimeConfig, ControlRuntimeState, FocusedMediaDispatchChannels,
        FocusedMediaReconfigure, InputAvailability, InputDispatchChannels, WorkerCapabilityState,
    };

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
        capabilities: Arc<WorkerCapabilityState>,
        encoder_capability_cache: Arc<DurableEncoderCapabilityCache>,
        watchdog: WorkerWatchdog,
        pending_restart: Option<(SessionId, Instant)>,
        generation: u64,
        clock: Instant,
    }

    impl WorkerManager {
        fn new(
            capabilities: Arc<WorkerCapabilityState>,
            encoder_capability_cache: Arc<DurableEncoderCapabilityCache>,
        ) -> Self {
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
                capabilities,
                encoder_capability_cache,
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

            let worker_generation = self.generation.saturating_add(1);
            self.generation = worker_generation;
            let pipe_name = worker_pipe_name(std::process::id(), session.0, worker_generation);
            let user_sid = match session_user_sid(session.0) {
                Ok(sid) => sid,
                Err(error) => {
                    eprintln!(
                        "failed to resolve Worker user SID for session {}: {error}",
                        session.0
                    );
                    let decision = self.watchdog.launch_failed(session);
                    return self.apply_restart_decision(decision);
                }
            };
            let mut pipe = match NamedPipeServer::create_for_user(&pipe_name, &user_sid) {
                Ok(pipe) => pipe,
                Err(error) => {
                    eprintln!(
                        "failed to create Worker IPC pipe for session {}: {error}",
                        session.0
                    );
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

                    self.capabilities
                        .activate(worker_generation, process_id, session.0);
                    if let Err(error) = authenticate_worker(&pipe, process_id, session) {
                        self.capabilities.clear();
                        eprintln!(
                            "Worker IPC handshake failed for pid {process_id}, session {}: {error}",
                            session.0
                        );
                        let _ = process.terminate(1);
                        let decision = self.watchdog.launch_failed(session);
                        return self.apply_restart_decision(decision);
                    }

                    match pipe.try_clone() {
                        Ok(reader) => {
                            let _capability_reader = spawn_worker_capability_reader(
                                reader,
                                Arc::clone(&self.capabilities),
                                Arc::clone(&self.encoder_capability_cache),
                                worker_generation,
                                process_id,
                                session.0,
                            );
                        }
                        Err(error) => {
                            eprintln!(
                                "Worker capability IPC reader unavailable; control remains active: {error}"
                            );
                        }
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

            self.capabilities.clear();
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

        fn send_control(&self, session: SessionId, command: IpcControlCommand) -> bool {
            if !self
                .process
                .as_ref()
                .is_some_and(|process| process.session_id() == session.0)
            {
                eprintln!(
                    "ignoring IPC command for session {}; no matching Worker is running",
                    session.0
                );
                return false;
            }

            let Some(pipe) = self.pipe.as_ref() else {
                eprintln!("Worker IPC pipe is unavailable for session {}", session.0);
                return false;
            };
            if let Err(error) = send_control(pipe, command) {
                eprintln!("failed to send Worker IPC command: {error}");
                return false;
            }
            true
        }

        fn send_input(&self, event: &InputEvent) -> Result<(), String> {
            let process = self
                .process
                .as_ref()
                .ok_or_else(|| "no interactive Worker is running".to_owned())?;
            if !process
                .is_running()
                .map_err(|error| format!("Worker input liveness probe failed: {error}"))?
            {
                return Err("interactive Worker exited before input dispatch".to_owned());
            }
            let pipe = self
                .pipe
                .as_ref()
                .ok_or_else(|| "Worker IPC pipe is unavailable for input dispatch".to_owned())?;
            send_input(pipe, event)
        }

        fn current_process_id(&self) -> Option<u32> {
            self.process.as_ref().map(SessionProcess::process_id)
        }

        fn clear_focused_profile(&self) -> Result<(), String> {
            let process = self
                .process
                .as_ref()
                .ok_or_else(|| "no interactive Worker is running".to_owned())?;
            if !process
                .is_running()
                .map_err(|error| format!("Worker media-reset liveness probe failed: {error}"))?
            {
                return Err("interactive Worker exited before media reset".to_owned());
            }
            let pipe = self
                .pipe
                .as_ref()
                .ok_or_else(|| "Worker IPC pipe is unavailable for media reset".to_owned())?;
            send_control(pipe, IpcControlCommand::ClearFocusedProfile)
        }

        fn send_stream_reconfigure(&self, reconfigure: &StreamReconfigure) -> Result<u32, String> {
            let process = self
                .process
                .as_ref()
                .ok_or_else(|| "no interactive Worker is running".to_owned())?;
            if !process
                .is_running()
                .map_err(|error| format!("Worker media liveness probe failed: {error}"))?
            {
                return Err("interactive Worker exited before media reconfigure".to_owned());
            }
            let pipe = self
                .pipe
                .as_ref()
                .ok_or_else(|| "Worker IPC pipe is unavailable for media reconfigure".to_owned())?;
            send_stream_reconfigure(pipe, reconfigure)?;
            Ok(process.process_id())
        }

        fn release_input(&self) -> Result<(), String> {
            let process = self
                .process
                .as_ref()
                .ok_or_else(|| "no interactive Worker is running".to_owned())?;
            if !process
                .is_running()
                .map_err(|error| format!("Worker input-release liveness probe failed: {error}"))?
            {
                return Err("interactive Worker exited before input release".to_owned());
            }
            let pipe = self
                .pipe
                .as_ref()
                .ok_or_else(|| "Worker IPC pipe is unavailable for input release".to_owned())?;
            send_control(pipe, IpcControlCommand::ReleaseInput)
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
                self.capabilities.clear();
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

    fn spawn_worker_capability_reader(
        pipe: NamedPipeServer,
        capabilities: Arc<WorkerCapabilityState>,
        encoder_capability_cache: Arc<DurableEncoderCapabilityCache>,
        generation: u64,
        expected_process_id: u32,
        expected_session_id: u32,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut decoder = IpcFrameDecoder::default();
            let mut buffer = [0_u8; 4096];

            loop {
                let read = match pipe.read(&mut buffer) {
                    Ok(0) => {
                        let _ = capabilities.clear_report_if_current(
                            generation,
                            expected_process_id,
                            expected_session_id,
                        );
                        return;
                    }
                    Err(error) => {
                        let _ = capabilities.clear_report_if_current(
                            generation,
                            expected_process_id,
                            expected_session_id,
                        );
                        eprintln!(
                            "Worker capability IPC read failed for pid {expected_process_id}: {error}"
                        );
                        return;
                    }
                    Ok(read) => read,
                };
                let frames = match decoder.push_bytes(&buffer[..read]) {
                    Ok(frames) => frames,
                    Err(error) => {
                        let _ = capabilities.clear_report_if_current(
                            generation,
                            expected_process_id,
                            expected_session_id,
                        );
                        eprintln!(
                            "Worker capability IPC frame rejected for pid {expected_process_id}: {error:?}"
                        );
                        return;
                    }
                };

                for frame in frames {
                    match frame.message() {
                        Ok(IpcMessage::WorkerCapabilities(report))
                            if report.process_id == expected_process_id
                                && report.session_id == expected_session_id =>
                        {
                            if capabilities.apply_report(
                                generation,
                                report.process_id,
                                report.session_id,
                                report.dxgi_capture(),
                                report.h264_hardware_encode(),
                            ) {
                                eprintln!(
                                    "ClassMesh Worker capabilities updated: pid={}, session={}, dxgi={}, h264_hw={}",
                                    report.process_id,
                                    report.session_id,
                                    report.dxgi_capture(),
                                    report.h264_hardware_encode()
                                );
                            } else {
                                eprintln!(
                                    "Stale Worker capability report ignored for pid {} session {}",
                                    report.process_id, report.session_id
                                );
                                return;
                            }
                        }
                        Ok(IpcMessage::WorkerCapabilities(report)) => {
                            let _ = capabilities.clear_report_if_current(
                                generation,
                                expected_process_id,
                                expected_session_id,
                            );
                            eprintln!(
                                "Worker capability identity mismatch: expected pid {} session {}, received pid {} session {}",
                                expected_process_id,
                                expected_session_id,
                                report.process_id,
                                report.session_id
                            );
                            return;
                        }
                        Ok(IpcMessage::WorkerEncoderCacheQuery(query))
                            if query.process_id == expected_process_id
                                && query.session_id == expected_session_id =>
                        {
                            if !capabilities.is_current(
                                generation,
                                query.process_id,
                                query.session_id,
                            ) {
                                eprintln!(
                                    "Stale Worker encoder cache query ignored for pid {} session {}",
                                    query.process_id, query.session_id
                                );
                                return;
                            }
                            let key = EncoderCapabilityCacheKey {
                                adapter_identity: query.adapter_identity,
                                driver_version: query.driver_version,
                                encoder_clsid: query.encoder_clsid,
                                width: query.width,
                                height: query.height,
                                target_fps: query.target_fps,
                                bitrate_bps: query.bitrate_bps,
                            };
                            let (hit, qualified) = match encoder_capability_cache.load_exact(&key) {
                                Ok(Some(verified))
                                    if verified.class != EncoderClass::Unsupported =>
                                {
                                    (true, true)
                                }
                                Ok(Some(_)) | Ok(None) => (false, false),
                                Err(error) => {
                                    eprintln!(
                                        "Encoder capability cache query failed closed and will re-probe: {error}"
                                    );
                                    (false, false)
                                }
                            };
                            if !capabilities.apply_h264_qualification(
                                generation,
                                expected_process_id,
                                expected_session_id,
                                qualified,
                            ) {
                                eprintln!(
                                    "Encoder cache query became stale before runtime publication for pid {expected_process_id}"
                                );
                                return;
                            }
                            let response = classmesh_windows_runtime::ipc::IpcFrame::service_encoder_cache_result(
                                classmesh_windows_runtime::ipc::ServiceEncoderCacheResult {
                                    process_id: expected_process_id,
                                    session_id: expected_session_id,
                                    hit,
                                    qualified,
                                },
                            );
                            let response = match response {
                                Ok(response) => response,
                                Err(error) => {
                                    eprintln!(
                                        "Encoder cache result IPC construction failed: {error:?}"
                                    );
                                    return;
                                }
                            };
                            let encoded = match response.encode() {
                                Ok(encoded) => encoded,
                                Err(error) => {
                                    eprintln!(
                                        "Encoder cache result IPC encoding failed: {error:?}"
                                    );
                                    return;
                                }
                            };
                            if let Err(error) = pipe.write_all(&encoded) {
                                let _ = capabilities.clear_report_if_current(
                                    generation,
                                    expected_process_id,
                                    expected_session_id,
                                );
                                eprintln!(
                                    "Encoder cache result IPC write failed for pid {expected_process_id}: {error}"
                                );
                                return;
                            }
                            eprintln!(
                                "ClassMesh Service encoder cache query resolved for pid {expected_process_id}: hit={hit} qualified={qualified}"
                            );
                        }
                        Ok(IpcMessage::WorkerEncoderCacheQuery(query)) => {
                            let _ = capabilities.clear_report_if_current(
                                generation,
                                expected_process_id,
                                expected_session_id,
                            );
                            eprintln!(
                                "Worker encoder cache query identity mismatch: expected pid {} session {}, received pid {} session {}",
                                expected_process_id,
                                expected_session_id,
                                query.process_id,
                                query.session_id
                            );
                            return;
                        }
                        Ok(IpcMessage::WorkerEncoderEvidence(evidence))
                            if evidence.process_id == expected_process_id
                                && evidence.session_id == expected_session_id =>
                        {
                            if !capabilities.is_current(
                                generation,
                                evidence.process_id,
                                evidence.session_id,
                            ) {
                                eprintln!(
                                    "Stale Worker encoder evidence ignored for pid {} session {}",
                                    evidence.process_id, evidence.session_id
                                );
                                return;
                            }
                            match encoder_evidence_parts(evidence) {
                                Ok((key, result)) => {
                                    if let Err(error) = encoder_capability_cache.save(&key, &result)
                                    {
                                        eprintln!(
                                            "Worker encoder evidence rejected by durable cache validation: {error}"
                                        );
                                    } else {
                                        match encoder_capability_cache.load_exact(&key) {
                                            Ok(Some(verified)) => {
                                                let qualified =
                                                    verified.class != EncoderClass::Unsupported;
                                                if capabilities.apply_h264_qualification(
                                                    generation,
                                                    expected_process_id,
                                                    expected_session_id,
                                                    qualified,
                                                ) {
                                                    eprintln!(
                                                        "ClassMesh Service persisted and verified measured H264 encoder evidence for pid {expected_process_id} session {expected_session_id}: qualified={qualified}"
                                                    );
                                                } else {
                                                    eprintln!(
                                                        "Measured H264 evidence became stale before runtime publication for pid {expected_process_id}"
                                                    );
                                                    return;
                                                }
                                            }
                                            Ok(None) => {
                                                eprintln!(
                                                    "Persisted H264 evidence did not reload with its exact cache key; runtime capability remains disabled"
                                                );
                                            }
                                            Err(error) => {
                                                eprintln!(
                                                    "Persisted H264 evidence failed exact reload; runtime capability remains disabled: {error}"
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(error) => {
                                    eprintln!("Worker encoder evidence rejected: {error}");
                                }
                            }
                        }
                        Ok(IpcMessage::WorkerEncoderEvidence(evidence)) => {
                            eprintln!(
                                "Worker encoder evidence identity mismatch: expected pid {} session {}, received pid {} session {}",
                                expected_process_id,
                                expected_session_id,
                                evidence.process_id,
                                evidence.session_id
                            );
                            return;
                        }
                        Ok(unexpected) => {
                            let _ = capabilities.clear_report_if_current(
                                generation,
                                expected_process_id,
                                expected_session_id,
                            );
                            eprintln!(
                                "Unexpected Worker→Service IPC message after handshake: {unexpected:?}"
                            );
                            return;
                        }
                        Err(error) => {
                            let _ = capabilities.clear_report_if_current(
                                generation,
                                expected_process_id,
                                expected_session_id,
                            );
                            eprintln!(
                                "Invalid Worker→Service IPC message after handshake: {error:?}"
                            );
                            return;
                        }
                    }
                }
            }
        })
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
                return Err(format!(
                    "unexpected Worker hello identity/message: {message:?}"
                ));
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

    fn send_input(pipe: &NamedPipeServer, event: &InputEvent) -> Result<(), String> {
        let bytes = IpcFrame::input_event(event)
            .encode()
            .map_err(|error| format!("failed to encode Worker input frame: {error:?}"))?;
        pipe.write_all(&bytes)
            .map_err(|error| format!("Worker input IPC write failed: {error}"))
    }

    fn send_stream_reconfigure(
        pipe: &NamedPipeServer,
        reconfigure: &StreamReconfigure,
    ) -> Result<(), String> {
        let bytes = IpcFrame::stream_reconfigure(reconfigure)
            .encode()
            .map_err(|error| format!("failed to encode Worker media frame: {error:?}"))?;
        pipe.write_all(&bytes)
            .map_err(|error| format!("Worker media IPC write failed: {error}"))
    }

    fn program_data_state_dir() -> Result<PathBuf, String> {
        let program_data = std::env::var_os("ProgramData")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "ProgramData is unavailable; refusing to start control runtime".to_owned()
            })?;
        Ok(PathBuf::from(program_data).join(STATE_DIRECTORY))
    }

    fn encoder_evidence_parts(
        evidence: classmesh_windows_runtime::ipc::WorkerEncoderEvidence,
    ) -> Result<(EncoderCapabilityCacheKey, EncoderBenchmarkResult), String> {
        let class = match evidence.encoder_class {
            0 => EncoderClass::Unsupported,
            1 => EncoderClass::Compatibility,
            2 => EncoderClass::Presentation1080p30,
            3 => EncoderClass::Presentation1080p60,
            value => return Err(format!("unsupported encoder class {value}")),
        };
        let output_frames = usize::try_from(evidence.output_frames)
            .map_err(|_| "encoder output frame count is not representable".to_owned())?;
        let dropped_or_missing = usize::try_from(evidence.dropped_or_missing)
            .map_err(|_| "encoder missing frame count is not representable".to_owned())?;
        Ok((
            EncoderCapabilityCacheKey {
                adapter_identity: evidence.adapter_identity,
                driver_version: evidence.driver_version,
                encoder_clsid: evidence.encoder_clsid,
                width: evidence.width,
                height: evidence.height,
                target_fps: evidence.target_fps,
                bitrate_bps: evidence.bitrate_bps,
            },
            EncoderBenchmarkResult {
                probe: EncoderProbeResult {
                    backend: evidence.backend,
                    codec: Codec::H264,
                    advertised_hardware: evidence.advertised_hardware,
                    gpu_native_input: evidence.gpu_native_input,
                    low_latency_accepted: evidence.low_latency_accepted,
                    sustained_fps: evidence.sustained_fps,
                    p50_encode_ms: evidence.p50_encode_ms,
                    p95_encode_ms: evidence.p95_encode_ms,
                    reset_ok: evidence.reset_ok,
                    dynamic_bitrate_ok: evidence.dynamic_bitrate_ok,
                    keyframe_request_ok: evidence.keyframe_request_ok,
                },
                class,
                output_frames,
                dropped_or_missing,
            },
        ))
    }

    fn encoder_capability_cache() -> Result<DurableEncoderCapabilityCache, String> {
        Ok(DurableEncoderCapabilityCache::new(
            program_data_state_dir()?.join(ENCODER_CAPABILITY_CACHE_FILE),
        ))
    }

    fn unix_time_ms() -> Result<u64, String> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_owned())?;
        u64::try_from(duration.as_millis())
            .map_err(|_| "system clock cannot be represented in milliseconds".to_owned())
    }

    fn load_control_state() -> Result<ControlRuntimeState, String> {
        let state_dir = program_data_state_dir()?;
        let identity_path = state_dir.join(MACHINE_IDENTITY_FILE);
        let authorization_path = state_dir.join(AUTHORIZATION_FILE);

        let identity = DurableMachineIdentity::new(&identity_path)
            .load()
            .map_err(|error| format!("machine identity state rejected: {error}"))?
            .ok_or_else(|| {
                format!(
                    "machine identity state is missing at {}",
                    identity_path.display()
                )
            })?;
        let authorization = DurableAuthorizationState::new(&authorization_path)
            .load()
            .map_err(|error| format!("authorization state rejected: {error}"))?
            .ok_or_else(|| {
                format!(
                    "authorization state is missing at {}",
                    authorization_path.display()
                )
            })?;

        let now_unix_ms = unix_time_ms()?;
        if identity.not_after_unix_ms <= now_unix_ms {
            return Err(
                "machine certificate is expired; refusing control runtime startup".to_owned(),
            );
        }

        let leaf = identity
            .certificate_chain_der
            .first()
            .ok_or_else(|| "machine certificate chain is empty".to_owned())?;
        let fingerprint = CredentialFingerprint(Sha256::digest(leaf).into());
        let expected_principal = PrincipalId(identity.principal_id);
        let authorized_principal = authorization
            .principal_for_credential(fingerprint, now_unix_ms)
            .ok_or_else(|| {
                "machine leaf certificate is not an active authorized credential".to_owned()
            })?;
        if authorized_principal != expected_principal {
            return Err("machine identity principal does not match authorization state".to_owned());
        }

        let key = CngMachineKey::open(identity.cng_key_name.clone())
            .map_err(|error| format!("protected CNG machine key is unavailable: {error}"))?;
        if key
            .export_policy()
            .map_err(|error| format!("failed to verify CNG export policy: {error}"))?
            != 0
        {
            return Err(
                "CNG machine key is exportable; refusing control runtime startup".to_owned(),
            );
        }

        Ok(ControlRuntimeState {
            identity,
            authorization,
            key,
        })
    }

    fn load_control_config() -> Result<ControlRuntimeConfig, String> {
        let program_data = std::env::var_os("ProgramData")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                "ProgramData is unavailable; refusing to start control runtime".to_owned()
            })?;
        let path = PathBuf::from(program_data)
            .join(CONFIG_DIRECTORY)
            .join(CONTROL_RUNTIME_CONFIG_FILE);
        ControlRuntimeConfig::load(&path)
            .map_err(|error| format!("control runtime config rejected: {error}"))
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
        let control_state = match load_control_state() {
            Ok(state) => state,
            Err(error) => {
                eprintln!("ClassMesh control identity state failed closed: {error}");
                set_stopped_with_exit(&status_handle, 1)?;
                return Ok(());
            }
        };
        let control_config = match load_control_config() {
            Ok(config) => config,
            Err(error) => {
                eprintln!("ClassMesh control runtime configuration failed: {error}");
                set_stopped_with_exit(&status_handle, 2)?;
                return Ok(());
            }
        };
        let (input_tx, input_rx) = mpsc::sync_channel::<InputEvent>(INPUT_QUEUE_CAPACITY);
        let (input_cleanup_tx, input_cleanup_rx) =
            mpsc::sync_channel::<()>(INPUT_CLEANUP_QUEUE_CAPACITY);
        let input_availability = Arc::new(AtomicU8::new(InputAvailability::Unavailable as u8));
        let input_channels = InputDispatchChannels {
            event_tx: input_tx,
            cleanup_tx: input_cleanup_tx,
            availability: Arc::clone(&input_availability),
        };
        let (media_reconfigure_tx, media_reconfigure_rx) =
            mpsc::sync_channel::<FocusedMediaReconfigure>(FOCUSED_MEDIA_QUEUE_CAPACITY);
        let released_media_session_floor = Arc::new(AtomicU64::new(0));
        let media_channels = FocusedMediaDispatchChannels {
            reconfigure_tx: media_reconfigure_tx,
            released_session_floor: Arc::clone(&released_media_session_floor),
        };
        let encoder_capability_cache = match encoder_capability_cache() {
            Ok(cache) => Arc::new(cache),
            Err(error) => {
                eprintln!("ClassMesh encoder capability cache path failed: {error}");
                set_stopped_with_exit(&status_handle, 3)?;
                return Ok(());
            }
        };
        eprintln!(
            "ClassMesh Service encoder capability cache ready at {}",
            encoder_capability_cache.path().display()
        );

        let worker_capabilities = Arc::new(WorkerCapabilityState::default());
        let mut control_runtime = match ControlRuntime::start(
            control_state,
            control_config,
            input_channels,
            media_channels,
            Arc::clone(&worker_capabilities),
        ) {
            Ok(runtime) => runtime,
            Err(error) => {
                eprintln!("ClassMesh control runtime failed to start: {error}");
                set_stopped_with_exit(&status_handle, 3)?;
                return Ok(());
            }
        };
        eprintln!(
            "ClassMesh enrolled control listener ready on {}",
            control_runtime.local_address()
        );
        set_running(&status_handle)?;

        let mut supervisor = SessionSupervisor::default();
        let mut workers = WorkerManager::new(
            Arc::clone(&worker_capabilities),
            Arc::clone(&encoder_capability_cache),
        );
        let mut desired_focused_reconfigure: Option<StreamReconfigure> = None;
        let mut desired_focused_control_session_id: Option<u64> = None;
        let mut focused_reconfigure_worker_pid: Option<u32> = None;
        let mut focused_profile_clear_pending = false;
        let mut focused_media_session_floor = 0_u64;
        let mut focused_reconfigure_attempts = 0_u8;
        let mut focused_clear_attempts = 0_u8;
        let mut next_media_reconfigure_attempt = Instant::now();
        let mut next_worker_poll = Instant::now();
        loop {
            match input_cleanup_rx.try_recv() {
                Ok(()) => {
                    if let Err(error) = workers.release_input() {
                        InputAvailability::Unavailable.store(input_availability.as_ref());
                        eprintln!("ClassMesh Service input cleanup failed: {error}");
                    }
                }
                Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => {}
            }

            for _ in 0..MAX_INPUT_EVENTS_PER_TICK {
                match input_rx.try_recv() {
                    Ok(event) => {
                        if let Err(error) = workers.send_input(&event) {
                            InputAvailability::Unavailable.store(input_availability.as_ref());
                            eprintln!("ClassMesh Service input dispatch failed: {error}");
                            break;
                        }
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => break,
                }
            }

            let released_floor = released_media_session_floor.load(Ordering::Acquire);
            if released_floor > focused_media_session_floor {
                focused_media_session_floor = released_floor;
                if released_session_invalidates_desired(
                    released_floor,
                    desired_focused_control_session_id,
                ) {
                    desired_focused_reconfigure = None;
                    desired_focused_control_session_id = None;
                    focused_reconfigure_worker_pid = None;
                    focused_profile_clear_pending = true;
                    focused_clear_attempts = 0;
                    focused_reconfigure_attempts = 0;
                    next_media_reconfigure_attempt = Instant::now();
                }
            }

            while let Ok(dispatch) = media_reconfigure_rx.try_recv() {
                if focused_reconfigure_is_stale(
                    dispatch.control_session_id,
                    focused_media_session_floor,
                    desired_focused_control_session_id,
                ) {
                    continue;
                }
                desired_focused_reconfigure = Some(dispatch.reconfigure);
                desired_focused_control_session_id = Some(dispatch.control_session_id);
                focused_reconfigure_worker_pid = None;
                focused_profile_clear_pending = false;
                focused_reconfigure_attempts = 0;
                focused_clear_attempts = 0;
                next_media_reconfigure_attempt = Instant::now();
            }

            let current_worker_pid = workers.current_process_id();
            if focused_profile_clear_pending {
                if current_worker_pid.is_none() {
                    focused_profile_clear_pending = false;
                } else if Instant::now() >= next_media_reconfigure_attempt {
                    match workers.clear_focused_profile() {
                        Ok(()) => {
                            focused_profile_clear_pending = false;
                            focused_clear_attempts = 0;
                            eprintln!("ClassMesh Service cleared focused Worker profile");
                        }
                        Err(error) => {
                            focused_clear_attempts = focused_clear_attempts.saturating_add(1);
                            if focused_clear_attempts >= MAX_MEDIA_RECONFIGURE_ATTEMPTS {
                                focused_profile_clear_pending = false;
                                eprintln!(
                                    "ClassMesh Service focused media reset abandoned after {} attempts: {error}",
                                    focused_clear_attempts
                                );
                            } else {
                                eprintln!(
                                    "ClassMesh Service will retry focused media reset ({}/{}): {error}",
                                    focused_clear_attempts, MAX_MEDIA_RECONFIGURE_ATTEMPTS
                                );
                                next_media_reconfigure_attempt = Instant::now()
                                    .checked_add(MEDIA_RECONFIGURE_RETRY)
                                    .unwrap_or_else(Instant::now);
                            }
                        }
                    }
                }
            }

            if !focused_profile_clear_pending
                && let Some(reconfigure) = desired_focused_reconfigure.as_ref()
                && current_worker_pid.is_some()
                && focused_reconfigure_worker_pid != current_worker_pid
                && Instant::now() >= next_media_reconfigure_attempt
            {
                match workers.send_stream_reconfigure(reconfigure) {
                    Ok(process_id) => {
                        eprintln!(
                            "ClassMesh Service applied focused profile to Worker {process_id}"
                        );
                        focused_reconfigure_worker_pid = Some(process_id);
                        focused_reconfigure_attempts = 0;
                    }
                    Err(error) => {
                        focused_reconfigure_attempts =
                            focused_reconfigure_attempts.saturating_add(1);
                        if focused_reconfigure_attempts >= MAX_MEDIA_RECONFIGURE_ATTEMPTS {
                            focused_reconfigure_worker_pid = current_worker_pid;
                            eprintln!(
                                "ClassMesh Service focused media reconfigure abandoned after {} attempts: {error}",
                                focused_reconfigure_attempts
                            );
                        } else {
                            eprintln!(
                                "ClassMesh Service will retry focused media reconfigure ({}/{}): {error}",
                                focused_reconfigure_attempts, MAX_MEDIA_RECONFIGURE_ATTEMPTS
                            );
                            focused_reconfigure_worker_pid = None;
                            next_media_reconfigure_attempt = Instant::now()
                                .checked_add(MEDIA_RECONFIGURE_RETRY)
                                .unwrap_or_else(Instant::now);
                        }
                    }
                }
            }

            match event_rx.recv_timeout(Duration::from_millis(5)) {
                Ok(RuntimeEvent::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Ok(RuntimeEvent::Session(event)) => {
                    let action = supervisor.on_event(event);
                    handle_supervisor_action(
                        action,
                        &mut supervisor,
                        &mut workers,
                        input_availability.as_ref(),
                    );
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }

            if !control_runtime.is_running() {
                eprintln!("ClassMesh control runtime exited unexpectedly; stopping service");
                break;
            }

            if Instant::now() >= next_worker_poll {
                let event = workers.poll();
                if matches!(event, WorkerManagerEvent::Running(_)) {
                    focused_reconfigure_worker_pid = None;
                    focused_reconfigure_attempts = 0;
                    focused_clear_attempts = 0;
                    next_media_reconfigure_attempt = Instant::now();
                }
                handle_worker_event(event, &mut supervisor, input_availability.as_ref());
                next_worker_poll = Instant::now()
                    .checked_add(Duration::from_millis(250))
                    .unwrap_or_else(Instant::now);
            }
        }

        InputAvailability::Unavailable.store(input_availability.as_ref());
        workers.stop_any();
        control_runtime.stop();
        set_stopped(&status_handle)
    }

    fn released_session_invalidates_desired(
        released_floor: u64,
        desired_session: Option<u64>,
    ) -> bool {
        desired_session.is_some_and(|desired| desired <= released_floor)
    }

    fn focused_reconfigure_is_stale(
        control_session_id: u64,
        released_floor: u64,
        desired_session: Option<u64>,
    ) -> bool {
        control_session_id <= released_floor
            || desired_session.is_some_and(|desired| control_session_id < desired)
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
        set_stopped_with_exit(handle, 0)
    }

    fn set_stopped_with_exit(
        handle: &ServiceStatusHandle,
        exit_code: u32,
    ) -> windows_service::Result<()> {
        handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(exit_code),
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
        input_availability: &AtomicU8,
    ) {
        match action {
            SupervisorAction::None => {}
            SupervisorAction::LaunchWorker(session) => {
                InputAvailability::Starting.store(input_availability);
                let event = workers.launch(session);
                handle_worker_event(event, supervisor, input_availability);
            }
            SupervisorAction::StopWorker(session) => {
                InputAvailability::Unavailable.store(input_availability);
                workers.stop(session);
                supervisor.mark_worker_stopped(session);
            }
            SupervisorAction::SuspendMedia(session) => {
                InputAvailability::Suspended.store(input_availability);
                let _ = workers.send_control(session, IpcControlCommand::SuspendMedia);
            }
            SupervisorAction::ResumeMedia(session) => {
                let resumed = workers.send_control(session, IpcControlCommand::ResumeMedia);
                let availability = if resumed {
                    InputAvailability::Ready
                } else {
                    InputAvailability::Unavailable
                };
                availability.store(input_availability);
            }
            SupervisorAction::ReplaceWorker {
                old_session,
                new_session,
            } => {
                InputAvailability::Starting.store(input_availability);
                workers.stop(old_session);
                let event = workers.launch(new_session);
                handle_worker_event(event, supervisor, input_availability);
            }
        }
    }

    fn handle_worker_event(
        event: WorkerManagerEvent,
        supervisor: &mut SessionSupervisor,
        input_availability: &AtomicU8,
    ) {
        match event {
            WorkerManagerEvent::Running(session) => {
                supervisor.mark_worker_running(session);
                InputAvailability::Ready.store(input_availability);
            }
            WorkerManagerEvent::RestartScheduled(session) => {
                InputAvailability::Starting.store(input_availability);
                let _ = supervisor.worker_crashed(session);
            }
            WorkerManagerEvent::GiveUp(session) => {
                InputAvailability::Unavailable.store(input_availability);
                supervisor.mark_worker_stopped(session);
            }
            WorkerManagerEvent::None => {}
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn released_session_floor_rejects_stale_profile_updates() {
            assert!(focused_reconfigure_is_stale(7, 7, None));
            assert!(focused_reconfigure_is_stale(6, 7, None));
            assert!(!focused_reconfigure_is_stale(8, 7, None));
        }

        #[test]
        fn newer_desired_session_rejects_older_in_flight_profile() {
            assert!(focused_reconfigure_is_stale(8, 7, Some(9)));
            assert!(!focused_reconfigure_is_stale(9, 7, Some(8)));
        }

        #[test]
        fn release_invalidates_only_same_or_older_desired_session() {
            assert!(released_session_invalidates_desired(9, Some(9)));
            assert!(released_session_invalidates_desired(9, Some(8)));
            assert!(!released_session_invalidates_desired(9, Some(10)));
            assert!(!released_session_invalidates_desired(9, None));
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
