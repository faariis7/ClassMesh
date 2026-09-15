#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Duration;

    use classmesh_win32::NamedPipeClient;
    use classmesh_windows_runtime::ipc::{
        IpcControlCommand, IpcFrame, IpcFrameDecoder, IpcMessage,
    };

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

    let mut decoder = IpcFrameDecoder::default();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = pipe.read(&mut buffer)?;
        if read == 0 {
            return Err("ClassMesh Service IPC pipe closed".into());
        }

        let frames = decoder
            .push_bytes(&buffer[..read])
            .map_err(ipc_frame_error)?;
        for frame in frames {
            match frame.message().map_err(ipc_message_error)? {
                IpcMessage::Control(IpcControlCommand::SuspendMedia) => {
                    eprintln!("ClassMesh Worker media suspended by Service");
                }
                IpcMessage::Control(IpcControlCommand::ResumeMedia) => {
                    eprintln!("ClassMesh Worker media resumed by Service");
                }
                IpcMessage::Control(IpcControlCommand::Shutdown) => {
                    eprintln!("ClassMesh Worker shutdown requested by Service");
                    return Ok(());
                }
                unexpected => {
                    return Err(
                        format!("unexpected IPC message after handshake: {unexpected:?}").into(),
                    );
                }
            }
        }
    }
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
