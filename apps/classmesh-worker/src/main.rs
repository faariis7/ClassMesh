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
    let mut active_focused_profile: Option<FocusedWorkerProfile> = None;
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
                    // A release attempted during lock/secure-desktop may have been blocked.
                    // Retry once the interactive desktop is active again before accepting input.
                    release_tracked_input(&mut input_injector);
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
            Ok(WorkerEvent::StreamReconfigure(reconfigure)) => {
                match FocusedWorkerProfile::from_reconfigure(&reconfigure) {
                    Ok(profile) => {
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
                        eprintln!("ClassMesh Worker rejected focused profile update: {code}");
                    }
                }
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
                capture_due = next_capture_due(active_focused_profile);
            }
            CaptureStep::NoFrame => {
                capture_due = next_capture_due(active_focused_profile);
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
    StreamReconfigure(classmesh_protocol::control_wire::StreamReconfigure),
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
        if profile.width == 0
            || profile.height == 0
            || profile.width > 1920
            || profile.height > 1080
            || profile.width % 2 != 0
            || profile.height % 2 != 0
        {
            return Err("worker.media.invalid_geometry");
        }
        if !(1..=60).contains(&profile.fps) {
            return Err("worker.media.invalid_fps");
        }
        if profile.bitrate_kbps == 0 || profile.bitrate_kbps > 50_000 {
            return Err("worker.media.invalid_bitrate");
        }

        Ok(Self {
            stream_id: reconfigure.stream_id,
            width: profile.width,
            height: profile.height,
            fps: profile.fps,
            bitrate_kbps: profile.bitrate_kbps,
        })
    }

    fn capture_interval(self) -> std::time::Duration {
        std::time::Duration::from_micros(1_000_000_u64 / u64::from(self.fps))
    }
}

#[cfg(windows)]
fn next_capture_due(profile: Option<FocusedWorkerProfile>) -> std::time::Instant {
    let interval = profile.map_or_else(
        || std::time::Duration::from_micros(1_000_000_u64 / 30),
        FocusedWorkerProfile::capture_interval,
    );
    std::time::Instant::now()
        .checked_add(interval)
        .unwrap_or_else(std::time::Instant::now)
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
                    Ok(IpcMessage::StreamReconfigure(reconfigure)) => {
                        if event_tx
                            .send(WorkerEvent::StreamReconfigure(reconfigure))
                            .is_err()
                        {
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


#[cfg(all(test, windows))]
mod focused_profile_tests {
    use super::*;
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
