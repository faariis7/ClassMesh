#[cfg(windows)]
const WORKER_IPC_EVENT_QUEUE_CAPACITY: usize = 128;
#[cfg(windows)]
const PRESENTATION_RECEIVE_DRAIN_LIMIT: usize = 8;

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use classmesh_capture_win::CaptureStep;
    use classmesh_win32::{InputInjector, NamedPipeClient};
    use classmesh_windows_runtime::ipc::{IpcFrame, IpcMessage};

    let args: Vec<String> = std::env::args().collect();
    let expected_session = parse_session(&args)?;
    let once = args.iter().any(|arg| arg == "--once");
    let actual_session = classmesh_win32::current_session_id()?;

    if actual_session != expected_session {
        return Err(format!(
            "ClassMesh Worker session mismatch: requested {expected_session}, running in {actual_session}"
        )
        .into());
    }

    eprintln!(
        "ClassMesh Worker started in interactive Windows session {actual_session} (pid {})",
        std::process::id()
    );

    if once {
        return Ok(());
    }

    let pipe_name = parse_pipe_name(&args)?;
    let pipe = NamedPipeClient::connect(&pipe_name, Duration::from_secs(5))?;
    let hello = IpcFrame::worker_hello(std::process::id(), actual_session)
        .encode()
        .map_err(ipc_frame_error)?;
    pipe.write_all(&hello)?;

    let ready = read_one_frame(&pipe)?;
    match ready.message().map_err(ipc_message_error)? {
        IpcMessage::ServiceReady => {
            eprintln!("ClassMesh Worker IPC peer validated by Service");
        }
        other => {
            return Err(format!("unexpected IPC handshake message: {other:?}").into());
        }
    }

    let (event_tx, event_rx) = mpsc::sync_channel(WORKER_IPC_EVENT_QUEUE_CAPACITY);
    let reader_pipe = pipe.try_clone()?;
    let _ipc_thread = spawn_ipc_reader(reader_pipe, event_tx);

    let mut capture_restart = CaptureRestart::default();
    let mut encoder_benchmark = None;
    let mut encoder_cache_query_pending = false;
    let mut encoder_cache_checked = false;
    let mut active_udp_stream: Option<classmesh_worker::udp_stream::FocusedUdpStream> = None;
    let mut capture = match start_capture() {
        Ok((capture, adapter)) => {
            encoder_benchmark = runtime_encoder_benchmark(adapter);
            Some(capture)
        }
        Err(error) => {
            capture_restart.record_failure(Instant::now());
            eprintln!(
                "ClassMesh Worker media unavailable at startup; control remains active: {error}"
            );
            None
        }
    };
    let mut runtime_capabilities = WorkerCapabilitySnapshot {
        dxgi_capture: capture.is_some(),
        h264_hardware_encode: false,
    };
    publish_worker_capabilities(
        &pipe,
        std::process::id(),
        actual_session,
        runtime_capabilities,
    )?;
    let mut capture_due = Instant::now();
    let mut active_focused_profile: Option<FocusedWorkerProfile> = None;
    let mut captured_frames = 0_u64;
    let mut input_injector = InputInjector::default();
    let mut group_media_keys =
        classmesh_worker::group_media_receive::WorkerGroupMediaKeyState::default();
    let mut presentation_multicast: Option<
        classmesh_worker::presentation_multicast_receive::WorkerPresentationMulticastRuntime,
    > = None;
    let mut presentation_unicast: Option<
        classmesh_worker::presentation_unicast_receive::WorkerPresentationUnicastRuntime,
    > = None;
    let mut presentation_decode: Option<
        classmesh_worker::presentation_decode_render::PresentationDecodeRuntime,
    > = None;
    let mut presentation_keyframe_request_pending = false;

    loop {
        let now = Instant::now();
        let mut wait = if capture.is_some() {
            capture_due
                .saturating_duration_since(now)
                .min(Duration::from_millis(50))
        } else if let Some(retry_at) = capture_restart.next_attempt {
            retry_at
                .saturating_duration_since(now)
                .min(Duration::from_millis(250))
        } else {
            Duration::from_millis(250)
        };
        if presentation_multicast.is_some() || presentation_unicast.is_some() {
            wait = wait.min(Duration::from_millis(10));
        }

        match event_rx.recv_timeout(wait) {
            Ok(WorkerEvent::Control(command)) => match command {
                classmesh_windows_runtime::ipc::IpcControlCommand::SuspendMedia => {
                    release_tracked_input(&mut input_injector);
                    capture = None;
                    encoder_benchmark = None;
                    encoder_cache_query_pending = false;
                    encoder_cache_checked = false;
                    if let Some(stream) = active_udp_stream.as_mut() {
                        stream.reset_pipeline();
                    }
                    capture_restart.clear();
                    eprintln!("ClassMesh Worker DXGI capture suspended by Service");
                    continue;
                }
                classmesh_windows_runtime::ipc::IpcControlCommand::ResumeMedia => {
                    // A release attempted during lock/secure-desktop may have been blocked.
                    // Retry once the interactive desktop is active again before accepting input.
                    release_tracked_input(&mut input_injector);
                    capture_restart.clear();
                    encoder_cache_query_pending = false;
                    encoder_cache_checked = false;
                    capture = match start_capture() {
                        Ok((capture, adapter)) => {
                            encoder_benchmark = runtime_encoder_benchmark(adapter);
                            eprintln!("ClassMesh Worker DXGI capture resumed by Service");
                            if !runtime_capabilities.dxgi_capture {
                                runtime_capabilities.dxgi_capture = true;
                                publish_worker_capabilities(
                                    &pipe,
                                    std::process::id(),
                                    actual_session,
                                    runtime_capabilities,
                                )?;
                            }
                            Some(capture)
                        }
                        Err(error) => {
                            capture_restart.record_failure(Instant::now());
                            eprintln!(
                                "ClassMesh Worker media resume failed; control remains active: {error}"
                            );
                            None
                        }
                    };
                    capture_due = Instant::now();
                    continue;
                }
                classmesh_windows_runtime::ipc::IpcControlCommand::Shutdown => {
                    release_tracked_input(&mut input_injector);
                    eprintln!("ClassMesh Worker shutdown requested by Service");
                    return Ok(());
                }
                classmesh_windows_runtime::ipc::IpcControlCommand::ReleaseInput => {
                    release_tracked_input(&mut input_injector);
                    eprintln!("ClassMesh Worker released tracked remote input");
                    continue;
                }
                classmesh_windows_runtime::ipc::IpcControlCommand::ClearFocusedProfile => {
                    active_focused_profile = None;
                    active_udp_stream = None;
                    capture_due = Instant::now();
                    eprintln!("ClassMesh Worker cleared focused media profile");
                    continue;
                }
            },
            Ok(WorkerEvent::UdpStreamStart(start)) => {
                let profile = FocusedWorkerProfile::from_udp_start(start);
                match classmesh_worker::udp_stream::FocusedUdpStream::new(start) {
                    Ok(stream) => {
                        eprintln!(
                            "ClassMesh Worker focused UDP stream ready: stream={}, destination={}, {}x{}@{}fps, {} kbps",
                            stream.stream_id(),
                            stream.destination(),
                            profile.width,
                            profile.height,
                            profile.fps,
                            profile.bitrate_kbps
                        );
                        active_udp_stream = Some(stream);
                        active_focused_profile = Some(profile);
                        capture_due = Instant::now();
                    }
                    Err(error) => {
                        active_udp_stream = None;
                        active_focused_profile = None;
                        eprintln!(
                            "ClassMesh Worker focused UDP stream failed closed; control remains active: {error}"
                        );
                    }
                }
            }
            Ok(WorkerEvent::MediaFeedback(feedback)) => {
                let result =
                    active_udp_stream
                        .as_mut()
                        .ok_or("worker.media.no_active_stream")
                        .and_then(|stream| {
                            stream.apply_feedback(&feedback).map_err(|error| {
                                match error {
                                    classmesh_worker::udp_stream::FocusedUdpStreamError::StreamMismatch => {
                                        "worker.media.feedback_stream_mismatch"
                                    }
                                    _ => "worker.media.feedback_failed",
                                }
                            })
                        });
                match result {
                    Ok(outcome) => {
                        if outcome.retransmitted_packets > 0 || outcome.keyframe_requested {
                            eprintln!(
                                "ClassMesh Worker applied media recovery feedback: retransmitted={}, keyframe_requested={}",
                                outcome.retransmitted_packets, outcome.keyframe_requested
                            );
                        }
                    }
                    Err(code) => {
                        eprintln!("ClassMesh Worker rejected media recovery feedback: {code}");
                    }
                }
            }
            Ok(WorkerEvent::PresentationKeyframeRequest(request)) => {
                eprintln!(
                    "ClassMesh Worker rejected Teacher presentation keyframe directive without an active sender runtime: presentation={}, stream={}, after_frame={}; control remains active",
                    request.presentation_id(),
                    request.stream_id(),
                    request.after_frame_id()
                );
                continue;
            }
            Ok(WorkerEvent::PresentationSenderUnicastAction(action)) => {
                eprintln!(
                    "ClassMesh Worker rejected Teacher presentation unicast sender action without an active sender runtime: slot={}, presentation={}, stream={}, epoch={}, destination={}; control remains active",
                    action.slot_id,
                    action.presentation_id,
                    action.stream_id,
                    action.epoch,
                    action.destination
                );
                continue;
            }
            Ok(WorkerEvent::StreamReconfigure(reconfigure)) => {
                match FocusedWorkerProfile::from_reconfigure(&reconfigure) {
                    Ok(profile) => {
                        let applied = active_udp_stream
                            .as_mut()
                            .ok_or("worker.media.no_active_stream")
                            .and_then(|stream| {
                                stream
                                    .apply_reconfigure(&reconfigure)
                                    .map_err(|_| "worker.media.reconfigure_failed")
                            });
                        match applied {
                            Ok(()) => {
                                active_focused_profile = Some(profile);
                                capture_due = Instant::now();
                                eprintln!(
                                    "ClassMesh Worker focused profile updated: stream={}, {}x{}@{}fps, {} kbps",
                                    profile.stream_id,
                                    profile.width,
                                    profile.height,
                                    profile.fps,
                                    profile.bitrate_kbps
                                );
                            }
                            Err(code) => {
                                eprintln!(
                                    "ClassMesh Worker rejected focused profile update: {code}"
                                );
                            }
                        }
                    }
                    Err(code) => {
                        eprintln!("ClassMesh Worker rejected focused profile update: {code}");
                    }
                }
            }
            Ok(WorkerEvent::PresentationMulticastStart(start)) => {
                use classmesh_windows_runtime::ipc::WorkerPresentationMulticastStartStatus;

                let key_binding_matches = group_media_keys.binding().is_some_and(|binding| {
                    classmesh_worker::presentation_multicast_receive::start_matches_key_binding(
                        start, binding,
                    )
                });
                let status = if !key_binding_matches {
                    eprintln!(
                        "ClassMesh Worker rejected multicast start: active presentation key binding mismatch"
                    );
                    WorkerPresentationMulticastStartStatus::Rejected
                } else {
                    let retry_started = presentation_unicast.is_none()
                        && match (
                            presentation_multicast.as_mut(),
                            presentation_decode.as_mut(),
                        ) {
                            (Some(receiver), Some(decoder)) => {
                                !receiver.failed()
                                    && decoder.pump_window()
                                    && receiver.adopt_retry(start)
                            }
                            _ => false,
                        };
                    if retry_started {
                        WorkerPresentationMulticastStartStatus::Started
                    } else {
                        presentation_multicast = None;
                        presentation_unicast = None;
                        presentation_decode = None;
                        presentation_keyframe_request_pending = false;
                        match classmesh_worker::presentation_multicast_receive::WorkerPresentationMulticastRuntime::start(start) {
                            Ok(receiver) => {
                                match classmesh_worker::presentation_decode_render::PresentationDecodeRuntime::new(
                                    true, None,
                                ) {
                                    Ok(decoder) => {
                                        eprintln!(
                                            "ClassMesh Worker multicast presentation ready: presentation={}, stream={}, group={}:{}, interface={}, teacher_source={}",
                                            start.presentation_id,
                                            start.stream_id,
                                            start.group,
                                            start.port,
                                            start.interface,
                                            start.teacher_source
                                        );
                                        presentation_multicast = Some(receiver);
                                        presentation_decode = Some(decoder);
                                        WorkerPresentationMulticastStartStatus::Started
                                    }
                                    Err(error) => {
                                        eprintln!(
                                            "ClassMesh Worker presentation decoder failed closed after multicast bind/join; start rejected: {error}"
                                        );
                                        WorkerPresentationMulticastStartStatus::Rejected
                                    }
                                }
                            }
                            Err(error) => {
                                eprintln!(
                                    "ClassMesh Worker multicast receiver failed closed; control remains active: {error}"
                                );
                                WorkerPresentationMulticastStartStatus::Rejected
                            }
                        }
                    }
                };
                publish_worker_presentation_multicast_start_result(
                    &pipe,
                    std::process::id(),
                    actual_session,
                    start,
                    status,
                )?;
                continue;
            }
            Ok(WorkerEvent::PresentationUnicastStart(start)) => {
                use classmesh_windows_runtime::ipc::WorkerPresentationUnicastStartStatus;

                let key_binding_matches = group_media_keys.binding().is_some_and(|binding| {
                    classmesh_worker::presentation_unicast_receive::start_matches_key_binding(
                        start, binding,
                    )
                });
                let status = if !key_binding_matches {
                    eprintln!(
                        "ClassMesh Worker rejected unicast start: active presentation key binding mismatch"
                    );
                    WorkerPresentationUnicastStartStatus::Rejected
                } else {
                    let retry_started = presentation_multicast.is_none()
                        && match (presentation_unicast.as_mut(), presentation_decode.as_mut()) {
                            (Some(receiver), Some(decoder)) => {
                                !receiver.failed()
                                    && decoder.pump_window()
                                    && receiver.adopt_retry(start)
                            }
                            _ => false,
                        };
                    if retry_started {
                        WorkerPresentationUnicastStartStatus::Started
                    } else {
                        presentation_multicast = None;
                        presentation_unicast = None;
                        presentation_decode = None;
                        presentation_keyframe_request_pending = false;
                        match classmesh_worker::presentation_unicast_receive::WorkerPresentationUnicastRuntime::start(start) {
                            Ok(receiver) => {
                                match classmesh_worker::presentation_decode_render::PresentationDecodeRuntime::new(
                                    true, None,
                                ) {
                                    Ok(decoder) => {
                                        eprintln!(
                                            "ClassMesh Worker unicast presentation ready: presentation={}, stream={}, port={}, teacher_source={}",
                                            start.presentation_id,
                                            start.stream_id,
                                            start.port,
                                            start.teacher_source
                                        );
                                        presentation_unicast = Some(receiver);
                                        presentation_decode = Some(decoder);
                                        WorkerPresentationUnicastStartStatus::Started
                                    }
                                    Err(error) => {
                                        eprintln!(
                                            "ClassMesh Worker presentation decoder failed closed after unicast bind; start rejected: {error}"
                                        );
                                        WorkerPresentationUnicastStartStatus::Rejected
                                    }
                                }
                            }
                            Err(error) => {
                                eprintln!(
                                    "ClassMesh Worker unicast receiver failed closed; control remains active: {error}"
                                );
                                WorkerPresentationUnicastStartStatus::Rejected
                            }
                        }
                    }
                };
                publish_worker_presentation_unicast_start_result(
                    &pipe,
                    std::process::id(),
                    actual_session,
                    start,
                    status,
                )?;
                continue;
            }
            Ok(WorkerEvent::PresentationKeyClear(clear)) => {
                let cleared = group_media_keys.clear_if_matches(clear);
                if cleared {
                    presentation_multicast = None;
                    presentation_unicast = None;
                    presentation_decode = None;
                    presentation_keyframe_request_pending = false;
                    eprintln!(
                        "ClassMesh Worker stopped presentation receive runtime with exact key clear"
                    );
                }
                eprintln!(
                    "ClassMesh Worker presentation key clear processed: exact_match={cleared}"
                );
                continue;
            }
            Ok(WorkerEvent::PresentationKeyInstall(install)) => {
                let binding = install.binding();
                let receive_binding_mismatch = presentation_multicast
                    .as_ref()
                    .is_some_and(|runtime| !runtime.matches_key_binding(binding))
                    || presentation_unicast
                        .as_ref()
                        .is_some_and(|runtime| !runtime.matches_key_binding(binding));
                let status = if receive_binding_mismatch {
                    drop(install);
                    eprintln!(
                        "ClassMesh Worker rejected presentation key install: active receiver binding mismatch"
                    );
                    classmesh_windows_runtime::ipc::WorkerPresentationKeyInstallStatus::Rejected
                } else {
                    match group_media_keys.install(install) {
                        Ok(installed) => {
                            debug_assert_eq!(installed, binding);
                            classmesh_windows_runtime::ipc::WorkerPresentationKeyInstallStatus::Installed
                        }
                        Err(error) => {
                            eprintln!(
                                "ClassMesh Worker rejected presentation key install: {error}"
                            );
                            classmesh_windows_runtime::ipc::WorkerPresentationKeyInstallStatus::Rejected
                        }
                    }
                };
                publish_worker_presentation_key_install_result(
                    &pipe,
                    std::process::id(),
                    actual_session,
                    binding,
                    status,
                )?;
                continue;
            }
            Ok(WorkerEvent::EncoderCacheResult(result)) => {
                if result.process_id != std::process::id() || result.session_id != actual_session {
                    release_tracked_input(&mut input_injector);
                    return Err(format!(
                        "encoder cache result identity mismatch: pid={} session={}",
                        result.process_id, result.session_id
                    )
                    .into());
                }
                encoder_cache_query_pending = false;
                encoder_cache_checked = true;
                if result.hit {
                    encoder_benchmark = None;
                    eprintln!(
                        "ClassMesh Worker exact encoder cache hit: qualified={}",
                        result.qualified
                    );
                } else {
                    eprintln!(
                        "ClassMesh Worker encoder cache miss; bounded H264 benchmark will run"
                    );
                }
                capture_due = Instant::now();
            }
            Ok(WorkerEvent::Input(event)) => match input_action_from_wire(event) {
                Ok(action) => {
                    if let Err(error) = input_injector.apply(action) {
                        eprintln!(
                            "ClassMesh Worker input rejected: {}",
                            error.diagnostic_code()
                        );
                    }
                }
                Err(error) => {
                    eprintln!("ClassMesh Worker rejected input event: {error}");
                }
            },
            Ok(WorkerEvent::IpcFailure(error)) => {
                release_tracked_input(&mut input_injector);
                return Err(error.into());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                release_tracked_input(&mut input_injector);
                return Err("ClassMesh Worker IPC reader stopped unexpectedly".into());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }

        let mut presentation_pipeline_failed = false;
        let multicast_active = presentation_multicast.is_some();
        let unicast_active = presentation_unicast.is_some();
        if multicast_active ^ unicast_active {
            if let Some(decoder) = presentation_decode.as_mut() {
                let receiver_failed = presentation_multicast
                    .as_ref()
                    .is_some_and(|receiver| receiver.failed())
                    || presentation_unicast
                        .as_ref()
                        .is_some_and(|receiver| receiver.failed());
                for _ in 0..PRESENTATION_RECEIVE_DRAIN_LIMIT {
                    let outcome = if let Some(receiver) = presentation_multicast.as_ref() {
                        receiver.try_receive()
                    } else {
                        presentation_unicast
                            .as_ref()
                            .and_then(|receiver| receiver.try_receive())
                    };
                    let Some(outcome) = outcome else {
                        break;
                    };
                    if let classmesh_network::multicast_receiver::ProtectedMulticastReceiveOutcome::Events(
                        batch,
                    ) = outcome
                    {
                        if let Some(binding) = group_media_keys.binding() {
                            let receiver_matches_binding = presentation_multicast
                                .as_ref()
                                .is_some_and(|receiver| receiver.matches_key_binding(binding))
                                || presentation_unicast
                                    .as_ref()
                                    .is_some_and(|receiver| receiver.matches_key_binding(binding));
                            if !receiver_matches_binding {
                                continue;
                            }
                            for feedback in batch.feedback {
                                publish_worker_presentation_feedback(
                                    &pipe,
                                    std::process::id(),
                                    actual_session,
                                    binding,
                                    feedback,
                                )?;
                            }
                            for frame in batch.frames {
                                let frame_id = frame.frame_id();
                                match group_media_keys.open_access_unit(frame) {
                                    Ok(access_unit) => {
                                        if access_unit.keyframe {
                                            presentation_keyframe_request_pending = false;
                                        }
                                        match decoder.submit(&access_unit) {
                                            Ok(classmesh_worker::presentation_decode_render::PresentationDecodeStep::Decoded(batch)) => {
                                                if batch.present_errors > 0 {
                                                    eprintln!(
                                                        "ClassMesh Worker presentation render reported {} media-local errors",
                                                        batch.present_errors
                                                    );
                                                }
                                                if decoder.waiting_for_keyframe() {
                                                    request_worker_presentation_keyframe_once(
                                                        &pipe,
                                                        std::process::id(),
                                                        actual_session,
                                                        binding,
                                                        access_unit.frame_id,
                                                        &mut presentation_keyframe_request_pending,
                                                    )?;
                                                } else {
                                                    presentation_keyframe_request_pending = false;
                                                }
                                            }
                                            Ok(classmesh_worker::presentation_decode_render::PresentationDecodeStep::WaitingForKeyframe) => {
                                                request_worker_presentation_keyframe_once(
                                                    &pipe,
                                                    std::process::id(),
                                                    actual_session,
                                                    binding,
                                                    access_unit.frame_id,
                                                    &mut presentation_keyframe_request_pending,
                                                )?;
                                            }
                                            Err(error) => {
                                                eprintln!(
                                                    "ClassMesh Worker presentation decode failed on frame={}: {error}; waiting for a new keyframe",
                                                    access_unit.frame_id
                                                );
                                                decoder.recover_after_loss();
                                                request_worker_presentation_keyframe_once(
                                                    &pipe,
                                                    std::process::id(),
                                                    actual_session,
                                                    binding,
                                                    access_unit.frame_id,
                                                    &mut presentation_keyframe_request_pending,
                                                )?;
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        eprintln!(
                                            "ClassMesh Worker dropped unauthenticated presentation ciphertext before decode on frame={frame_id}: {error}"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                presentation_pipeline_failed = receiver_failed || !decoder.pump_window();
            } else {
                presentation_pipeline_failed = true;
                eprintln!(
                    "ClassMesh Worker presentation pipeline invariant failed; active receiver has no decoder"
                );
            }
        } else if multicast_active || unicast_active || presentation_decode.is_some() {
            presentation_pipeline_failed = true;
            eprintln!(
                "ClassMesh Worker presentation pipeline invariant failed; tearing down partial or conflicting runtime"
            );
        }
        if presentation_pipeline_failed {
            eprintln!(
                "ClassMesh Worker presentation receive path stopped after media-local runtime failure; control remains active"
            );
            presentation_multicast = None;
            presentation_unicast = None;
            presentation_decode = None;
            presentation_keyframe_request_pending = false;
        }

        if capture.is_none() && capture_restart.is_due(Instant::now()) {
            match start_capture() {
                Ok((restarted, adapter)) => {
                    encoder_cache_query_pending = false;
                    encoder_cache_checked = false;
                    encoder_benchmark = runtime_encoder_benchmark(adapter);
                    capture = Some(restarted);
                    capture_restart.clear();
                    capture_due = Instant::now();
                    if !runtime_capabilities.dxgi_capture {
                        runtime_capabilities.dxgi_capture = true;
                        publish_worker_capabilities(
                            &pipe,
                            std::process::id(),
                            actual_session,
                            runtime_capabilities,
                        )?;
                    }
                    eprintln!(
                        "ClassMesh Worker DXGI capture recovered; control session remained active"
                    );
                }
                Err(error) => {
                    let will_retry = capture_restart.record_failure(Instant::now());
                    if will_retry {
                        eprintln!(
                            "ClassMesh Worker media restart failed; control remains active and media will retry: {error}"
                        );
                    } else {
                        eprintln!(
                            "ClassMesh Worker media restart budget exhausted; control remains active until a future ResumeMedia: {error}"
                        );
                    }
                }
            }
        }

        let Some(active_capture) = capture.as_mut() else {
            continue;
        };
        if Instant::now() < capture_due {
            continue;
        }

        match active_capture.poll(16) {
            CaptureStep::Frame { meta, frame } => {
                captured_frames = captured_frames.saturating_add(1);
                if captured_frames == 1 || captured_frames % 300 == 0 {
                    eprintln!(
                        "DXGI frame {}: {}x{}, accumulated={}, pointer_visible={}",
                        meta.frame_id,
                        meta.width,
                        meta.height,
                        meta.accumulated_frames,
                        meta.pointer_visible
                    );
                }
                if encoder_benchmark.is_some() && !encoder_cache_checked {
                    if !encoder_cache_query_pending {
                        let query_key = encoder_benchmark
                            .as_mut()
                            .expect("benchmark presence checked")
                            .prepare_cache_key(&frame);
                        match query_key {
                            Ok(key) => {
                                publish_worker_encoder_cache_query(
                                    &pipe,
                                    std::process::id(),
                                    actual_session,
                                    key,
                                )?;
                                encoder_cache_query_pending = true;
                            }
                            Err(error) => {
                                encoder_benchmark = None;
                                encoder_cache_checked = true;
                                eprintln!(
                                    "ClassMesh Worker encoder cache key preparation failed closed; control remains active: {error}"
                                );
                            }
                        }
                    }
                    drop(frame);
                } else if encoder_benchmark.is_some() {
                    let outcome = encoder_benchmark
                        .as_mut()
                        .expect("benchmark presence checked")
                        .process_frame(meta, frame);
                    match outcome {
                        Ok(Some(evidence)) => {
                            publish_worker_encoder_evidence(
                                &pipe,
                                std::process::id(),
                                actual_session,
                                evidence,
                            )?;
                            encoder_benchmark = None;
                            encoder_cache_query_pending = false;
                            eprintln!(
                                "ClassMesh Worker completed bounded H264 benchmark and published measured evidence"
                            );
                        }
                        Ok(None) => {}
                        Err(error) => {
                            encoder_benchmark = None;
                            encoder_cache_query_pending = false;
                            eprintln!(
                                "ClassMesh Worker H264 benchmark failed closed; control remains active: {error}"
                            );
                        }
                    }
                } else if let Some(stream) = active_udp_stream.as_mut() {
                    if let Err(error) = stream.process_frame(meta, frame) {
                        eprintln!(
                            "ClassMesh Worker focused UDP media failed; control remains active: {error}"
                        );
                        active_udp_stream = None;
                        active_focused_profile = None;
                    }
                } else {
                    drop(frame);
                }
                capture_due = if encoder_benchmark.is_some() {
                    Instant::now()
                } else {
                    next_capture_due(active_focused_profile)
                };
            }
            CaptureStep::NoFrame => {
                capture_due = Instant::now();
            }
            CaptureStep::RetryAfter { delay_ms, reason } => {
                encoder_benchmark = None;
                if let Some(stream) = active_udp_stream.as_mut() {
                    stream.reset_pipeline();
                }
                encoder_cache_query_pending = false;
                encoder_cache_checked = false;
                eprintln!("DXGI capture recovery scheduled after {reason:?} in {delay_ms} ms");
                capture_due = Instant::now()
                    .checked_add(Duration::from_millis(delay_ms))
                    .unwrap_or_else(Instant::now);
            }
            CaptureStep::Suspended(reason) => {
                eprintln!("DXGI capture suspended by backend; control remains active: {reason:?}");
                encoder_benchmark = None;
                if let Some(stream) = active_udp_stream.as_mut() {
                    stream.reset_pipeline();
                }
                encoder_cache_query_pending = false;
                encoder_cache_checked = false;
                capture = None;
                capture_restart.clear();
            }
            CaptureStep::Failed(reason) => {
                eprintln!(
                    "DXGI capture failed after backend recovery; control remains active: {reason:?}"
                );
                encoder_benchmark = None;
                if let Some(stream) = active_udp_stream.as_mut() {
                    stream.reset_pipeline();
                }
                encoder_cache_query_pending = false;
                encoder_cache_checked = false;
                capture = None;
                capture_restart.record_failure(Instant::now());
            }
        }
    }
}

#[cfg(windows)]
type WorkerCapture = classmesh_capture_win::RecoveringCapture<
    classmesh_capture_win::DxgiCaptureBackend,
    classmesh_capture_win::DxgiCaptureFactory,
>;

#[cfg(windows)]
const CAPTURE_RESTART_DELAY: std::time::Duration = std::time::Duration::from_millis(500);
#[cfg(windows)]
const MAX_CAPTURE_RESTART_ATTEMPTS: u8 = 4;

#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct CaptureRestart {
    attempts: u8,
    next_attempt: Option<std::time::Instant>,
}

#[cfg(windows)]
impl CaptureRestart {
    fn record_failure(&mut self, now: std::time::Instant) -> bool {
        self.attempts = self.attempts.saturating_add(1);
        if self.attempts >= MAX_CAPTURE_RESTART_ATTEMPTS {
            self.next_attempt = None;
            return false;
        }
        self.next_attempt = now.checked_add(CAPTURE_RESTART_DELAY);
        self.next_attempt.is_some()
    }

    fn is_due(self, now: std::time::Instant) -> bool {
        self.next_attempt.is_some_and(|deadline| now >= deadline)
    }

    fn clear(&mut self) {
        self.attempts = 0;
        self.next_attempt = None;
    }
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct WorkerCapabilitySnapshot {
    dxgi_capture: bool,
    h264_hardware_encode: bool,
}

#[cfg(windows)]
#[derive(Debug)]
enum WorkerEvent {
    Control(classmesh_windows_runtime::ipc::IpcControlCommand),
    Input(classmesh_protocol::control_wire::InputEvent),
    StreamReconfigure(classmesh_protocol::control_wire::StreamReconfigure),
    UdpStreamStart(classmesh_windows_runtime::ipc::ServiceUdpStreamStart),
    MediaFeedback(classmesh_protocol::feedback::FeedbackMessage),
    EncoderCacheResult(classmesh_windows_runtime::ipc::ServiceEncoderCacheResult),
    PresentationKeyInstall(
        classmesh_windows_runtime::ipc_sensitive::SensitivePresentationKeyInstall,
    ),
    PresentationKeyClear(classmesh_windows_runtime::ipc::ServicePresentationKeyClear),
    PresentationMulticastStart(classmesh_windows_runtime::ipc::ServicePresentationMulticastStart),
    PresentationUnicastStart(classmesh_windows_runtime::ipc::ServicePresentationUnicastStart),
    PresentationKeyframeRequest(classmesh_core::keyframe::PresentationKeyframeRequest),
    PresentationSenderUnicastAction(
        classmesh_windows_runtime::ipc::ServicePresentationSenderUnicastAction,
    ),
    IpcFailure(String),
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FocusedWorkerProfile {
    stream_id: u64,
    width: u32,
    height: u32,
    fps: u32,
    bitrate_kbps: u32,
}

#[cfg(windows)]
impl FocusedWorkerProfile {
    fn from_udp_start(start: classmesh_windows_runtime::ipc::ServiceUdpStreamStart) -> Self {
        Self {
            stream_id: u64::from(start.stream_id),
            width: u32::from(start.width),
            height: u32::from(start.height),
            fps: u32::from(start.fps),
            bitrate_kbps: start.bitrate_kbps,
        }
    }

    fn from_reconfigure(
        reconfigure: &classmesh_protocol::control_wire::StreamReconfigure,
    ) -> Result<Self, &'static str> {
        use classmesh_protocol::control_wire::{MediaTransport, VideoCodec};

        if reconfigure.stream_id == 0 {
            return Err("worker.media.invalid_stream");
        }
        if reconfigure.transport != MediaTransport::Unspecified as i32
            || !reconfigure.transport_parameters.is_empty()
        {
            return Err("worker.media.transport_change_not_supported");
        }
        let profile = reconfigure
            .profile
            .as_ref()
            .ok_or("worker.media.missing_profile")?;
        if profile.codec != VideoCodec::H264 as i32 {
            return Err("worker.media.unsupported_codec");
        }
        use classmesh_core::adaptation::{StreamProfile, StreamProfileError};

        let width = u16::try_from(profile.width).map_err(|_| "worker.media.invalid_geometry")?;
        let height = u16::try_from(profile.height).map_err(|_| "worker.media.invalid_geometry")?;
        let fps = u8::try_from(profile.fps).map_err(|_| "worker.media.invalid_fps")?;
        let validated = StreamProfile::new(width, height, fps, profile.bitrate_kbps)
            .validate()
            .map_err(|error| match error {
                StreamProfileError::InvalidGeometry => "worker.media.invalid_geometry",
                StreamProfileError::InvalidFps => "worker.media.invalid_fps",
                StreamProfileError::InvalidBitrate => "worker.media.invalid_bitrate",
            })?;

        Ok(Self {
            stream_id: reconfigure.stream_id,
            width: u32::from(validated.width),
            height: u32::from(validated.height),
            fps: u32::from(validated.fps),
            bitrate_kbps: validated.bitrate_kbps,
        })
    }

    fn capture_interval(self) -> std::time::Duration {
        std::time::Duration::from_micros(1_000_000_u64 / u64::from(self.fps))
    }
}

#[cfg(windows)]
fn next_capture_due(profile: Option<FocusedWorkerProfile>) -> std::time::Instant {
    let now = std::time::Instant::now();
    let Some(profile) = profile else {
        return now;
    };
    now.checked_add(profile.capture_interval()).unwrap_or(now)
}

#[cfg(windows)]
fn release_tracked_input(injector: &mut classmesh_win32::InputInjector) {
    if let Err(error) = injector.release_all() {
        eprintln!(
            "ClassMesh Worker input cleanup deferred: {}",
            error.diagnostic_code()
        );
    }
}

#[cfg(windows)]
fn input_action_from_wire(
    event: classmesh_protocol::control_wire::InputEvent,
) -> Result<classmesh_win32::InputAction, String> {
    use classmesh_protocol::control_wire::input_event::Event;
    use classmesh_win32::{InputAction, MouseButton};

    let Some(event) = event.event else {
        return Err("input event payload is missing".to_owned());
    };

    match event {
        Event::MouseMove(mouse) => Ok(InputAction::MouseMove {
            x: mouse.x,
            y: mouse.y,
            absolute: mouse.absolute,
        }),
        Event::MouseButton(button) => {
            let down = button.down;
            let button = match button.button {
                1 => MouseButton::Left,
                2 => MouseButton::Right,
                3 => MouseButton::Middle,
                4 => MouseButton::X1,
                5 => MouseButton::X2,
                value => return Err(format!("unsupported mouse button {value}")),
            };
            Ok(InputAction::MouseButton { button, down })
        }
        Event::MouseWheel(wheel) => Ok(InputAction::MouseWheel {
            delta: wheel.delta,
            horizontal: wheel.horizontal,
        }),
        Event::Key(key) => Ok(InputAction::Key {
            virtual_key: key.virtual_key,
            scan_code: key.scan_code,
            down: key.down,
            extended: key.extended,
        }),
        Event::ReleaseAll(_) => Ok(InputAction::ReleaseAll),
    }
}

#[cfg(windows)]
fn start_capture() -> Result<
    (
        WorkerCapture,
        classmesh_capture_win::AdapterCapabilityIdentity,
    ),
    Box<dyn std::error::Error>,
> {
    use classmesh_capture_win::{
        RecoveringCapture, enumerate_displays, query_adapter_capability_identity,
    };
    use classmesh_core::recovery::RecoveryPolicy;

    let displays = enumerate_displays().map_err(capture_error)?;
    let display = displays
        .iter()
        .find(|display| display.primary)
        .or_else(|| displays.first())
        .ok_or("no attached desktop display is available for DXGI capture")?;

    eprintln!(
        "ClassMesh Worker selecting display {} ({}x{}, adapter={:08x}:{:08x}, output={})",
        display.name,
        display.width,
        display.height,
        display.id.adapter_luid_high,
        display.id.adapter_luid_low,
        display.id.output_index
    );

    let adapter = query_adapter_capability_identity(display.id).map_err(capture_error)?;
    let mut capture = RecoveringCapture::new(
        display.id,
        classmesh_capture_win::DxgiCaptureFactory,
        RecoveryPolicy::default(),
    );
    capture.start().map_err(capture_error)?;
    Ok((capture, adapter))
}

#[cfg(windows)]
fn runtime_encoder_benchmark(
    adapter: classmesh_capture_win::AdapterCapabilityIdentity,
) -> Option<classmesh_worker::encoder_benchmark::RuntimeEncoderBenchmark> {
    match classmesh_worker::encoder_benchmark::RuntimeEncoderBenchmark::compatibility_720p30(
        adapter,
    ) {
        Ok(benchmark) => Some(benchmark),
        Err(error) => {
            eprintln!(
                "ClassMesh Worker could not initialize bounded H264 benchmark; control remains active: {error}"
            );
            None
        }
    }
}

#[cfg(windows)]
fn publish_worker_encoder_cache_query(
    pipe: &classmesh_win32::NamedPipeClient,
    process_id: u32,
    session_id: u32,
    key: classmesh_codec_win::EncoderCapabilityCacheKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let query = classmesh_windows_runtime::ipc::WorkerEncoderCacheQuery {
        process_id,
        session_id,
        adapter_identity: key.adapter_identity,
        driver_version: key.driver_version,
        encoder_clsid: key.encoder_clsid,
        width: key.width,
        height: key.height,
        target_fps: key.target_fps,
        bitrate_bps: key.bitrate_bps,
    };
    let frame = classmesh_windows_runtime::ipc::IpcFrame::worker_encoder_cache_query(&query)
        .map_err(ipc_message_error)?;
    pipe.write_all(&frame.encode().map_err(ipc_frame_error)?)?;
    Ok(())
}

#[cfg(windows)]
fn publish_worker_encoder_evidence(
    pipe: &classmesh_win32::NamedPipeClient,
    process_id: u32,
    session_id: u32,
    evidence: classmesh_worker::encoder_benchmark::MeasuredEncoderEvidence,
) -> Result<(), Box<dyn std::error::Error>> {
    use classmesh_video::EncoderClass;

    let encoder_class = match evidence.result.class {
        EncoderClass::Unsupported => 0,
        EncoderClass::Compatibility => 1,
        EncoderClass::Presentation1080p30 => 2,
        EncoderClass::Presentation1080p60 => 3,
    };
    let report = classmesh_windows_runtime::ipc::WorkerEncoderEvidence {
        process_id,
        session_id,
        adapter_identity: evidence.key.adapter_identity,
        driver_version: evidence.key.driver_version,
        encoder_clsid: evidence.key.encoder_clsid,
        width: evidence.key.width,
        height: evidence.key.height,
        target_fps: evidence.key.target_fps,
        bitrate_bps: evidence.key.bitrate_bps,
        backend: evidence.result.probe.backend,
        advertised_hardware: evidence.result.probe.advertised_hardware,
        gpu_native_input: evidence.result.probe.gpu_native_input,
        low_latency_accepted: evidence.result.probe.low_latency_accepted,
        reset_ok: evidence.result.probe.reset_ok,
        dynamic_bitrate_ok: evidence.result.probe.dynamic_bitrate_ok,
        keyframe_request_ok: evidence.result.probe.keyframe_request_ok,
        encoder_class,
        sustained_fps: evidence.result.probe.sustained_fps,
        p50_encode_ms: evidence.result.probe.p50_encode_ms,
        p95_encode_ms: evidence.result.probe.p95_encode_ms,
        output_frames: u32::try_from(evidence.result.output_frames)?,
        dropped_or_missing: u32::try_from(evidence.result.dropped_or_missing)?,
    };
    let frame = classmesh_windows_runtime::ipc::IpcFrame::worker_encoder_evidence(&report)
        .map_err(ipc_message_error)?;
    pipe.write_all(&frame.encode().map_err(ipc_frame_error)?)?;
    Ok(())
}

#[cfg(windows)]
fn publish_worker_presentation_key_install_result(
    pipe: &classmesh_win32::NamedPipeClient,
    process_id: u32,
    session_id: u32,
    binding: classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding,
    status: classmesh_windows_runtime::ipc::WorkerPresentationKeyInstallStatus,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = classmesh_windows_runtime::ipc::WorkerPresentationKeyInstallResult {
        process_id,
        session_id,
        control_session_id: binding.control_session_id,
        request_id: binding.request_id,
        presentation_id: binding.presentation_id,
        stream_id: binding.stream_id,
        epoch: binding.epoch,
        status,
    };
    let frame =
        classmesh_windows_runtime::ipc::IpcFrame::worker_presentation_key_install_result(result)
            .map_err(ipc_message_error)?;
    pipe.write_all(&frame.encode().map_err(ipc_frame_error)?)?;
    Ok(())
}

#[cfg(windows)]
fn publish_worker_presentation_multicast_start_result(
    pipe: &classmesh_win32::NamedPipeClient,
    process_id: u32,
    session_id: u32,
    start: classmesh_windows_runtime::ipc::ServicePresentationMulticastStart,
    status: classmesh_windows_runtime::ipc::WorkerPresentationMulticastStartStatus,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = classmesh_windows_runtime::ipc::WorkerPresentationMulticastStartResult {
        process_id,
        session_id,
        control_session_id: start.control_session_id,
        request_id: start.request_id,
        presentation_id: start.presentation_id,
        stream_id: start.stream_id,
        status,
    };
    let frame =
        classmesh_windows_runtime::ipc::IpcFrame::worker_presentation_multicast_start_result(
            result,
        )
        .map_err(ipc_message_error)?;
    pipe.write_all(&frame.encode().map_err(ipc_frame_error)?)?;
    Ok(())
}

#[cfg(windows)]
fn publish_worker_presentation_unicast_start_result(
    pipe: &classmesh_win32::NamedPipeClient,
    process_id: u32,
    session_id: u32,
    start: classmesh_windows_runtime::ipc::ServicePresentationUnicastStart,
    status: classmesh_windows_runtime::ipc::WorkerPresentationUnicastStartStatus,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = classmesh_windows_runtime::ipc::WorkerPresentationUnicastStartResult {
        process_id,
        session_id,
        control_session_id: start.control_session_id,
        request_id: start.request_id,
        presentation_id: start.presentation_id,
        stream_id: start.stream_id,
        status,
    };
    let frame =
        classmesh_windows_runtime::ipc::IpcFrame::worker_presentation_unicast_start_result(result)
            .map_err(ipc_message_error)?;
    pipe.write_all(&frame.encode().map_err(ipc_frame_error)?)?;
    Ok(())
}

#[cfg(windows)]
fn request_worker_presentation_keyframe_once(
    pipe: &classmesh_win32::NamedPipeClient,
    process_id: u32,
    session_id: u32,
    binding: classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding,
    after_frame_id: u64,
    pending: &mut bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if *pending {
        return Ok(());
    }
    publish_worker_presentation_feedback(
        pipe,
        process_id,
        session_id,
        binding,
        classmesh_protocol::feedback::FeedbackMessage::RequestKeyframe {
            stream_id: binding.stream_id,
            after_frame_id,
        },
    )?;
    *pending = true;
    Ok(())
}

#[cfg(windows)]
fn publish_worker_presentation_feedback(
    pipe: &classmesh_win32::NamedPipeClient,
    process_id: u32,
    session_id: u32,
    binding: classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding,
    feedback: classmesh_protocol::feedback::FeedbackMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    let report = classmesh_windows_runtime::ipc::WorkerPresentationFeedback {
        process_id,
        session_id,
        control_session_id: binding.control_session_id,
        request_id: binding.request_id,
        presentation_id: binding.presentation_id,
        epoch: binding.epoch,
        feedback,
    };
    let frame = classmesh_windows_runtime::ipc::IpcFrame::worker_presentation_feedback(&report)
        .map_err(ipc_message_error)?;
    pipe.write_all(&frame.encode().map_err(ipc_frame_error)?)?;
    Ok(())
}

#[cfg(windows)]
fn publish_worker_capabilities(
    pipe: &classmesh_win32::NamedPipeClient,
    process_id: u32,
    session_id: u32,
    snapshot: WorkerCapabilitySnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    let frame = classmesh_windows_runtime::ipc::IpcFrame::worker_capabilities(
        classmesh_windows_runtime::ipc::WorkerRuntimeCapabilities::new(
            process_id,
            session_id,
            snapshot.dxgi_capture,
            snapshot.h264_hardware_encode,
        ),
    );
    let encoded = frame.encode().map_err(ipc_frame_error)?;
    pipe.write_all(&encoded)?;
    Ok(())
}

#[cfg(windows)]
fn worker_event_from_decoded_frame(
    frame: classmesh_windows_runtime::ipc_sensitive::DecodedIpcFrame,
) -> Result<WorkerEvent, String> {
    use classmesh_windows_runtime::ipc::IpcMessage;
    use classmesh_windows_runtime::ipc_sensitive::DecodedIpcFrame;

    match frame {
        DecodedIpcFrame::PresentationKeyInstall(install) => {
            Ok(WorkerEvent::PresentationKeyInstall(install))
        }
        DecodedIpcFrame::Regular(frame) => match frame.message() {
            Ok(IpcMessage::Control(command)) => Ok(WorkerEvent::Control(command)),
            Ok(IpcMessage::InputEvent(event)) => Ok(WorkerEvent::Input(event)),
            Ok(IpcMessage::StreamReconfigure(reconfigure)) => {
                Ok(WorkerEvent::StreamReconfigure(reconfigure))
            }
            Ok(IpcMessage::ServiceUdpStreamStart(start)) => Ok(WorkerEvent::UdpStreamStart(start)),
            Ok(IpcMessage::ServiceMediaFeedback(feedback)) => {
                Ok(WorkerEvent::MediaFeedback(feedback))
            }
            Ok(IpcMessage::ServicePresentationKeyClear(clear)) => {
                Ok(WorkerEvent::PresentationKeyClear(clear))
            }
            Ok(IpcMessage::ServicePresentationMulticastStart(start)) => {
                Ok(WorkerEvent::PresentationMulticastStart(start))
            }
            Ok(IpcMessage::ServicePresentationUnicastStart(start)) => {
                Ok(WorkerEvent::PresentationUnicastStart(start))
            }
            Ok(IpcMessage::ServicePresentationKeyframeRequest(request)) => {
                Ok(WorkerEvent::PresentationKeyframeRequest(request))
            }
            Ok(IpcMessage::ServicePresentationSenderUnicastAction(action)) => {
                Ok(WorkerEvent::PresentationSenderUnicastAction(action))
            }
            Ok(IpcMessage::ServiceEncoderCacheResult(result)) => {
                Ok(WorkerEvent::EncoderCacheResult(result))
            }
            Ok(unexpected) => Err(format!(
                "unexpected IPC message after handshake: {unexpected:?}"
            )),
            Err(error) => Err(format!("invalid IPC message after handshake: {error:?}")),
        },
    }
}

#[cfg(windows)]
fn spawn_ipc_reader(
    pipe: classmesh_win32::NamedPipeClient,
    event_tx: std::sync::mpsc::SyncSender<WorkerEvent>,
) -> std::thread::JoinHandle<()> {
    use classmesh_windows_runtime::ipc_sensitive::SensitiveIpcFrameDecoder;

    std::thread::spawn(move || {
        let mut decoder = SensitiveIpcFrameDecoder::default();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = match pipe.read(&mut buffer) {
                Ok(0) => {
                    let _ = event_tx.send(WorkerEvent::IpcFailure(
                        "ClassMesh Service IPC pipe closed".to_owned(),
                    ));
                    return;
                }
                Ok(read) => read,
                Err(error) => {
                    let _ = event_tx.send(WorkerEvent::IpcFailure(format!(
                        "ClassMesh Service IPC read failed: {error}"
                    )));
                    return;
                }
            };

            let frames = match decoder.push_bytes_zeroizing(&mut buffer[..read]) {
                Ok(frames) => frames,
                Err(error) => {
                    let _ = event_tx.send(WorkerEvent::IpcFailure(format!(
                        "ClassMesh Service IPC frame error: {error:?}"
                    )));
                    return;
                }
            };

            for frame in frames {
                let event = match worker_event_from_decoded_frame(frame) {
                    Ok(event) => event,
                    Err(error) => {
                        let _ = event_tx.send(WorkerEvent::IpcFailure(error));
                        return;
                    }
                };
                if event_tx.send(event).is_err() {
                    return;
                }
            }
        }
    })
}

#[cfg(windows)]
fn read_one_frame(
    pipe: &classmesh_win32::NamedPipeClient,
) -> Result<classmesh_windows_runtime::ipc::IpcFrame, Box<dyn std::error::Error>> {
    use classmesh_windows_runtime::ipc::IpcFrameDecoder;

    let mut decoder = IpcFrameDecoder::default();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = pipe.read(&mut buffer)?;
        if read == 0 {
            return Err("ClassMesh Service IPC pipe closed during handshake".into());
        }
        let mut frames = decoder
            .push_bytes(&buffer[..read])
            .map_err(ipc_frame_error)?;
        if !frames.is_empty() {
            return Ok(frames.remove(0));
        }
    }
}

#[cfg(windows)]
fn capture_error(error: classmesh_capture_win::CaptureFailure) -> std::io::Error {
    std::io::Error::other(format!("DXGI capture error: {error:?}"))
}

#[cfg(windows)]
fn ipc_frame_error(error: classmesh_windows_runtime::ipc::IpcFrameError) -> std::io::Error {
    std::io::Error::other(format!("IPC frame error: {error:?}"))
}

#[cfg(windows)]
fn ipc_message_error(error: classmesh_windows_runtime::ipc::IpcMessageError) -> std::io::Error {
    std::io::Error::other(format!("IPC message error: {error:?}"))
}

#[cfg(windows)]
fn parse_session(args: &[String]) -> Result<u32, Box<dyn std::error::Error>> {
    let index = args
        .iter()
        .position(|arg| arg == "--session")
        .ok_or("missing required --session argument")?;
    let raw = args
        .get(index + 1)
        .ok_or("--session requires a numeric value")?;
    Ok(raw.parse::<u32>()?)
}

#[cfg(windows)]
fn parse_pipe_name(args: &[String]) -> Result<String, Box<dyn std::error::Error>> {
    let index = args
        .iter()
        .position(|arg| arg == "--pipe")
        .ok_or("missing required --pipe argument")?;
    let value = args.get(index + 1).ok_or("--pipe requires a pipe name")?;
    Ok(value.clone())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-worker is supported only on Windows");
}

#[cfg(all(test, windows))]
mod focused_profile_tests {
    use super::*;

    #[test]
    fn sensitive_key_install_routes_to_dedicated_worker_event() {
        use classmesh_protocol::control_wire::PresentationKeyGrant;
        use classmesh_protocol::group_media_control::PRESENTATION_GROUP_KEY_BYTES;
        use classmesh_windows_runtime::ipc_sensitive::{
            DecodedIpcFrame, SensitivePresentationKeyInstall,
        };

        let mut grant = PresentationKeyGrant {
            presentation_id: 55,
            stream_id: 7,
            epoch: 3,
            key_material: vec![0x5a; PRESENTATION_GROUP_KEY_BYTES],
        };
        let install = SensitivePresentationKeyInstall::take_from_control_grant(77, 44, &mut grant)
            .expect("valid install");
        let event =
            worker_event_from_decoded_frame(DecodedIpcFrame::PresentationKeyInstall(install))
                .expect("sensitive install routes");

        let WorkerEvent::PresentationKeyInstall(install) = event else {
            panic!("expected dedicated presentation-key event");
        };
        assert_eq!(install.binding().control_session_id, 77);
        assert_eq!(install.binding().request_id, 44);
        assert_eq!(install.binding().presentation_id, 55);
        assert_eq!(install.binding().stream_id, 7);
        assert_eq!(install.binding().epoch, 3);
        assert!(grant.key_material.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn exact_presentation_key_clear_routes_as_typed_worker_event() {
        use classmesh_windows_runtime::ipc::{IpcFrame, ServicePresentationKeyClear};
        use classmesh_windows_runtime::ipc_sensitive::DecodedIpcFrame;

        let clear = ServicePresentationKeyClear {
            control_session_id: 77,
            request_id: 44,
            presentation_id: 55,
            stream_id: 7,
            epoch: 3,
        };
        let frame = IpcFrame::service_presentation_key_clear(clear).expect("valid clear");
        let event =
            worker_event_from_decoded_frame(DecodedIpcFrame::Regular(frame)).expect("clear routes");

        let WorkerEvent::PresentationKeyClear(received) = event else {
            panic!("expected presentation-key clear event");
        };
        assert_eq!(received, clear);
    }

    #[test]
    fn presentation_multicast_start_routes_as_typed_worker_event() {
        use std::net::Ipv4Addr;

        use classmesh_windows_runtime::ipc::{IpcFrame, ServicePresentationMulticastStart};
        use classmesh_windows_runtime::ipc_sensitive::DecodedIpcFrame;

        let start = ServicePresentationMulticastStart {
            control_session_id: 77,
            request_id: 44,
            presentation_id: 55,
            stream_id: 7,
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_kbps: 6_000,
            group: Ipv4Addr::new(239, 10, 20, 30),
            port: 49_000,
            interface: Ipv4Addr::new(192, 0, 2, 10),
            teacher_source: Ipv4Addr::new(192, 0, 2, 44),
        };
        let frame =
            IpcFrame::service_presentation_multicast_start(start).expect("valid multicast start");
        let event = worker_event_from_decoded_frame(DecodedIpcFrame::Regular(frame))
            .expect("multicast start routes");

        let WorkerEvent::PresentationMulticastStart(received) = event else {
            panic!("expected presentation multicast start event");
        };
        assert_eq!(received, start);
    }

    #[test]
    fn presentation_unicast_start_routes_as_typed_worker_event() {
        use std::net::{IpAddr, Ipv4Addr};

        use classmesh_windows_runtime::ipc::{IpcFrame, ServicePresentationUnicastStart};
        use classmesh_windows_runtime::ipc_sensitive::DecodedIpcFrame;

        let start = ServicePresentationUnicastStart {
            control_session_id: 77,
            request_id: 44,
            presentation_id: 55,
            stream_id: 7,
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_kbps: 6_000,
            port: 49_000,
            teacher_source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)),
        };
        let frame =
            IpcFrame::service_presentation_unicast_start(start).expect("valid unicast start");
        let event = worker_event_from_decoded_frame(DecodedIpcFrame::Regular(frame))
            .expect("unicast start routes");

        let WorkerEvent::PresentationUnicastStart(received) = event else {
            panic!("expected presentation unicast start event");
        };
        assert_eq!(received, start);
    }

    #[test]
    fn presentation_keyframe_request_routes_as_typed_worker_event() {
        use classmesh_core::keyframe::PresentationKeyframeRequest;
        use classmesh_windows_runtime::ipc::IpcFrame;
        use classmesh_windows_runtime::ipc_sensitive::DecodedIpcFrame;

        let request =
            PresentationKeyframeRequest::new(55, 7, 42).expect("valid keyframe directive");
        let frame = IpcFrame::service_presentation_keyframe_request(request)
            .expect("valid keyframe directive frame");
        let event = worker_event_from_decoded_frame(DecodedIpcFrame::Regular(frame))
            .expect("keyframe directive routes");

        let WorkerEvent::PresentationKeyframeRequest(received) = event else {
            panic!("expected presentation keyframe request event");
        };
        assert_eq!(received, request);
    }

    #[test]
    fn presentation_sender_unicast_action_routes_as_typed_worker_event() {
        use classmesh_windows_runtime::ipc::{
            IpcFrame, ServicePresentationSenderUnicastAction,
            ServicePresentationSenderUnicastActionKind,
        };
        use classmesh_windows_runtime::ipc_sensitive::DecodedIpcFrame;

        let action = ServicePresentationSenderUnicastAction {
            kind: ServicePresentationSenderUnicastActionKind::Attach,
            slot_id: 11,
            presentation_id: 55,
            stream_id: 7,
            epoch: 3,
            destination: "192.0.2.44:49001".parse().expect("valid destination"),
        };
        let frame = IpcFrame::service_presentation_sender_unicast_action(action)
            .expect("valid sender action frame");
        let event = worker_event_from_decoded_frame(DecodedIpcFrame::Regular(frame))
            .expect("sender action routes");

        let WorkerEvent::PresentationSenderUnicastAction(received) = event else {
            panic!("expected presentation sender unicast action event");
        };
        assert_eq!(received, action);
    }

    #[test]
    fn service_cannot_send_worker_unicast_result_back_to_worker() {
        use classmesh_windows_runtime::ipc::{
            IpcFrame, WorkerPresentationUnicastStartResult, WorkerPresentationUnicastStartStatus,
        };
        use classmesh_windows_runtime::ipc_sensitive::DecodedIpcFrame;

        let result = WorkerPresentationUnicastStartResult {
            process_id: 42,
            session_id: 7,
            control_session_id: 77,
            request_id: 44,
            presentation_id: 55,
            stream_id: 7,
            status: WorkerPresentationUnicastStartStatus::Started,
        };
        let frame = IpcFrame::worker_presentation_unicast_start_result(result)
            .expect("valid unicast result");
        let error = worker_event_from_decoded_frame(DecodedIpcFrame::Regular(frame))
            .expect_err("Worker-to-Service result must be rejected on Service-to-Worker path");
        assert!(error.contains("unexpected IPC message after handshake"));
    }

    #[test]
    fn service_cannot_send_worker_multicast_result_back_to_worker() {
        use classmesh_windows_runtime::ipc::{
            IpcFrame, WorkerPresentationMulticastStartResult,
            WorkerPresentationMulticastStartStatus,
        };
        use classmesh_windows_runtime::ipc_sensitive::DecodedIpcFrame;

        let result = WorkerPresentationMulticastStartResult {
            process_id: 42,
            session_id: 7,
            control_session_id: 77,
            request_id: 44,
            presentation_id: 55,
            stream_id: 7,
            status: WorkerPresentationMulticastStartStatus::Started,
        };
        let frame = IpcFrame::worker_presentation_multicast_start_result(result)
            .expect("valid multicast result");
        let error = worker_event_from_decoded_frame(DecodedIpcFrame::Regular(frame))
            .expect_err("Worker-to-Service result must be rejected on Service-to-Worker path");
        assert!(error.contains("unexpected IPC message after handshake"));
    }

    #[test]
    fn service_cannot_send_worker_install_result_back_to_worker() {
        use classmesh_windows_runtime::ipc::{
            IpcFrame, WorkerPresentationKeyInstallResult, WorkerPresentationKeyInstallStatus,
        };
        use classmesh_windows_runtime::ipc_sensitive::DecodedIpcFrame;

        let result = WorkerPresentationKeyInstallResult {
            process_id: 42,
            session_id: 7,
            control_session_id: 77,
            request_id: 44,
            presentation_id: 55,
            stream_id: 7,
            epoch: 3,
            status: WorkerPresentationKeyInstallStatus::Installed,
        };
        let frame =
            IpcFrame::worker_presentation_key_install_result(result).expect("valid result frame");
        let error = worker_event_from_decoded_frame(DecodedIpcFrame::Regular(frame))
            .expect_err("Worker-to-Service result must be rejected on Service-to-Worker path");
        assert!(error.contains("unexpected IPC message after handshake"));
    }

    #[test]
    fn capability_snapshot_does_not_claim_h264_before_encode_validation() {
        let mut snapshot = WorkerCapabilitySnapshot::default();
        assert!(!snapshot.dxgi_capture);
        assert!(!snapshot.h264_hardware_encode);

        snapshot.dxgi_capture = true;
        assert!(snapshot.dxgi_capture);
        assert!(!snapshot.h264_hardware_encode);
    }

    #[test]
    fn capture_restart_budget_is_bounded_without_stopping_worker_control() {
        let started = std::time::Instant::now();
        let mut retry = CaptureRestart::default();

        assert!(retry.record_failure(started));
        assert_eq!(retry.attempts, 1);
        let first_due = retry.next_attempt.expect("retry deadline");
        assert!(!retry.is_due(started));
        assert!(retry.is_due(first_due));

        assert!(retry.record_failure(first_due));
        let second_due = retry.next_attempt.expect("second retry deadline");
        assert!(retry.record_failure(second_due));
        let third_due = retry.next_attempt.expect("third retry deadline");
        assert!(!retry.record_failure(third_due));
        assert_eq!(retry.attempts, MAX_CAPTURE_RESTART_ATTEMPTS);
        assert!(retry.next_attempt.is_none());

        retry.clear();
        assert_eq!(retry, CaptureRestart::default());
    }

    use classmesh_protocol::control_wire::{
        MediaTransport, StreamReconfigure, VideoCodec, VideoProfile,
    };

    fn reconfigure() -> StreamReconfigure {
        StreamReconfigure {
            stream_id: 9,
            profile: Some(VideoProfile {
                width: 960,
                height: 540,
                fps: 30,
                bitrate_kbps: 1_500,
                codec: VideoCodec::H264 as i32,
            }),
            transport: MediaTransport::Unspecified as i32,
            transport_parameters: Vec::new(),
        }
    }

    #[test]
    fn focused_profile_accepts_transport_neutral_h264_profile() {
        let profile =
            FocusedWorkerProfile::from_reconfigure(&reconfigure()).expect("valid profile");
        assert_eq!(profile.stream_id, 9);
        assert_eq!((profile.width, profile.height, profile.fps), (960, 540, 30));
        assert_eq!(profile.bitrate_kbps, 1_500);
        assert_eq!(
            profile.capture_interval(),
            std::time::Duration::from_micros(33_333)
        );
    }

    #[test]
    fn focused_profile_rejects_transport_change_and_invalid_geometry() {
        let mut transport_change = reconfigure();
        transport_change.transport = MediaTransport::QuicDatagram as i32;
        assert_eq!(
            FocusedWorkerProfile::from_reconfigure(&transport_change),
            Err("worker.media.transport_change_not_supported")
        );

        let mut odd_geometry = reconfigure();
        odd_geometry.profile.as_mut().expect("profile").width = 959;
        assert_eq!(
            FocusedWorkerProfile::from_reconfigure(&odd_geometry),
            Err("worker.media.invalid_geometry")
        );
    }
}
