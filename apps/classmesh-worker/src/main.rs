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

    let (event_tx, event_rx) = mpsc::channel();
    let _ipc_thread = spawn_ipc_reader(pipe, event_tx);

    let mut capture = Some(start_capture()?);
    let mut capture_due = Instant::now();
    let mut captured_frames = 0_u64;
    let mut input_injector = InputInjector::default();

    loop {
        let wait = if capture.is_some() {
            capture_due
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(50))
        } else {
            Duration::from_millis(250)
        };

        match event_rx.recv_timeout(wait) {
            Ok(WorkerEvent::Control(command)) => match command {
                classmesh_windows_runtime::ipc::IpcControlCommand::SuspendMedia => {
                    release_tracked_input(&mut input_injector);
                    capture = None;
                    eprintln!("ClassMesh Worker DXGI capture suspended by Service");
                    continue;
                }
                classmesh_windows_runtime::ipc::IpcControlCommand::ResumeMedia => {
                    capture = match start_capture() {
                        Ok(capture) => Some(capture),
                        Err(error) => {
                            release_tracked_input(&mut input_injector);
                            return Err(error);
                        }
                    };
                    capture_due = Instant::now();
                    eprintln!("ClassMesh Worker DXGI capture resumed by Service");
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
            },
            Ok(WorkerEvent::Input(event)) => match input_action_from_wire(event) {
                Ok(action) => {
                    if let Err(error) = input_injector.apply(action) {
                        eprintln!("ClassMesh Worker input execution failed: {error}");
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
                // The next milestone hands this GPU-native texture directly to the encoder. For now
                // dropping the frame releases the Desktop Duplication frame without CPU readback.
                drop(frame);
                capture_due = Instant::now();
            }
            CaptureStep::NoFrame => {
                capture_due = Instant::now();
            }
            CaptureStep::RetryAfter { delay_ms, reason } => {
                eprintln!("DXGI capture recovery scheduled after {reason:?} in {delay_ms} ms");
                capture_due = Instant::now()
                    .checked_add(Duration::from_millis(delay_ms))
                    .unwrap_or_else(Instant::now);
            }
            CaptureStep::Suspended(reason) => {
                eprintln!("DXGI capture suspended by backend: {reason:?}");
                capture = None;
            }
            CaptureStep::Failed(reason) => {
                release_tracked_input(&mut input_injector);
                return Err(capture_error(reason).into());
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
#[derive(Debug)]
enum WorkerEvent {
    Control(classmesh_windows_runtime::ipc::IpcControlCommand),
    Input(classmesh_protocol::control_wire::InputEvent),
    IpcFailure(String),
}

#[cfg(windows)]
fn release_tracked_input(injector: &mut classmesh_win32::InputInjector) {
    if let Err(error) = injector.release_all() {
        eprintln!("ClassMesh Worker failed to release tracked input during teardown: {error}");
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
fn start_capture() -> Result<WorkerCapture, Box<dyn std::error::Error>> {
    use classmesh_capture_win::{RecoveringCapture, enumerate_displays};
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

    let mut capture = RecoveringCapture::new(
        display.id,
        classmesh_capture_win::DxgiCaptureFactory,
        RecoveryPolicy::default(),
    );
    capture.start().map_err(capture_error)?;
    Ok(capture)
}

#[cfg(windows)]
fn spawn_ipc_reader(
    pipe: classmesh_win32::NamedPipeClient,
    event_tx: std::sync::mpsc::Sender<WorkerEvent>,
) -> std::thread::JoinHandle<()> {
    use classmesh_windows_runtime::ipc::{IpcFrameDecoder, IpcMessage};

    std::thread::spawn(move || {
        let mut decoder = IpcFrameDecoder::default();
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

            let frames = match decoder.push_bytes(&buffer[..read]) {
                Ok(frames) => frames,
                Err(error) => {
                    let _ = event_tx.send(WorkerEvent::IpcFailure(format!(
                        "ClassMesh Service IPC frame error: {error:?}"
                    )));
                    return;
                }
            };

            for frame in frames {
                match frame.message() {
                    Ok(IpcMessage::Control(command)) => {
                        if event_tx.send(WorkerEvent::Control(command)).is_err() {
                            return;
                        }
                    }
                    Ok(IpcMessage::InputEvent(event)) => {
                        if event_tx.send(WorkerEvent::Input(event)).is_err() {
                            return;
                        }
                    }
                    Ok(unexpected) => {
                        let _ = event_tx.send(WorkerEvent::IpcFailure(format!(
                            "unexpected IPC message after handshake: {unexpected:?}"
                        )));
                        return;
                    }
                    Err(error) => {
                        let _ = event_tx.send(WorkerEvent::IpcFailure(format!(
                            "invalid IPC message after handshake: {error:?}"
                        )));
                        return;
                    }
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
