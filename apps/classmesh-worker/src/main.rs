#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Duration;

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

    // The Worker remains intentionally small at this milestone. The next step connects the
    // authenticated service/worker Named Pipe and lets IPC drive capture/media lifecycle.
    loop {
        std::thread::sleep(Duration::from_secs(30));
    }
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

#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-worker is supported only on Windows");
}
