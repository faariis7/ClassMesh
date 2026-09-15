#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::{BufWriter, Write};
    use std::time::{Duration, Instant};

    use classmesh_capture_win::CaptureStep;
    use classmesh_worker::presentation::PresentationPipeline;

    let args: Vec<String> = std::env::args().collect();
    let seconds = parse_seconds(&args)?;
    let output_path = parse_output_path(&args)?;
    let mut output = match output_path.as_deref() {
        Some(path) => {
            eprintln!("ClassMesh media probe writing raw H.264 access units to {path}");
            Some(BufWriter::new(File::create(path)?))
        }
        None => None,
    };

    let mut capture = start_capture()?;
    let mut pipeline: Option<PresentationPipeline> = None;
    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_secs(seconds))
        .unwrap_or(started);
    let mut next_report = started;
    let mut total_encoded_frames = 0_u64;
    let mut total_encoded_bytes = 0_u64;

    eprintln!("ClassMesh media probe running for {seconds} seconds");

    while Instant::now() < deadline {
        match capture.poll(16) {
            CaptureStep::Frame { meta, frame } => {
                if pipeline.is_none() {
                    let created = PresentationPipeline::from_first_frame(&frame)?;
                    let profile = created.profile();
                    eprintln!(
                        "presentation encoder: {} | {}x{} -> {}x{} @ {} fps, {} kbps",
                        created.encoder_name(),
                        profile.source_width,
                        profile.source_height,
                        profile.target_width,
                        profile.target_height,
                        profile.fps,
                        profile.bitrate_bps / 1_000
                    );
                    pipeline = Some(created);
                }

                let encoded = pipeline
                    .as_mut()
                    .expect("pipeline was initialized above")
                    .process_frame(meta, frame)?;
                write_frames(
                    &encoded,
                    output.as_mut(),
                    &mut total_encoded_frames,
                    &mut total_encoded_bytes,
                )?;
            }
            CaptureStep::NoFrame => {}
            CaptureStep::RetryAfter { delay_ms, reason } => {
                eprintln!(
                    "DXGI recovery after {reason:?}; rebuilding media pipeline (delay={delay_ms} ms)"
                );
                pipeline = None;
                if delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(delay_ms.min(250)));
                }
            }
            CaptureStep::Suspended(reason) => {
                return Err(format!("DXGI capture suspended during media probe: {reason:?}").into());
            }
            CaptureStep::Failed(reason) => {
                return Err(format!("DXGI capture failed during media probe: {reason:?}").into());
            }
        }

        if Instant::now() >= next_report {
            if let Some(active) = pipeline.as_ref() {
                let stats = active.stats();
                eprintln!(
                    "media stats: captured={} submitted={} encoded={} keyframes={} rate_drop={} pool_drop={} in_flight={} bytes={}",
                    stats.captured_frames,
                    stats.submitted_frames,
                    stats.encoded_frames,
                    stats.keyframes,
                    stats.rate_dropped_frames,
                    stats.pool_dropped_frames,
                    stats.in_flight_surfaces,
                    stats.encoded_bytes
                );
            }
            next_report = Instant::now()
                .checked_add(Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }
    }

    if let Some(active) = pipeline.as_mut() {
        let tail = active.finish()?;
        write_frames(
            &tail,
            output.as_mut(),
            &mut total_encoded_frames,
            &mut total_encoded_bytes,
        )?;
        let stats = active.stats();
        eprintln!(
            "final pipeline stats: captured={} submitted={} encoded={} keyframes={} rate_drop={} pool_drop={} in_flight={} bytes={}",
            stats.captured_frames,
            stats.submitted_frames,
            stats.encoded_frames,
            stats.keyframes,
            stats.rate_dropped_frames,
            stats.pool_dropped_frames,
            stats.in_flight_surfaces,
            stats.encoded_bytes
        );
    }

    if let Some(writer) = output.as_mut() {
        writer.flush()?;
    }

    eprintln!(
        "ClassMesh media probe complete: encoded_frames={total_encoded_frames}, encoded_bytes={total_encoded_bytes}, elapsed={:.2}s",
        started.elapsed().as_secs_f32()
    );
    Ok(())
}

#[cfg(windows)]
type ProbeCapture = classmesh_capture_win::RecoveringCapture<
    classmesh_capture_win::DxgiCaptureBackend,
    classmesh_capture_win::DxgiCaptureFactory,
>;

#[cfg(windows)]
fn start_capture() -> Result<ProbeCapture, Box<dyn std::error::Error>> {
    use classmesh_capture_win::{RecoveringCapture, enumerate_displays};
    use classmesh_core::recovery::RecoveryPolicy;

    let displays = enumerate_displays().map_err(capture_error)?;
    let display = displays
        .iter()
        .find(|display| display.primary)
        .or_else(|| displays.first())
        .ok_or("no attached desktop display is available for DXGI capture")?;

    eprintln!(
        "media probe display: {} ({}x{}, adapter={:08x}:{:08x}, output={})",
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
fn write_frames<W: std::io::Write>(
    frames: &[classmesh_video::distributor::SharedEncodedFrame],
    mut output: Option<&mut W>,
    total_frames: &mut u64,
    total_bytes: &mut u64,
) -> std::io::Result<()> {
    for frame in frames {
        *total_frames = total_frames.saturating_add(1);
        *total_bytes = total_bytes
            .saturating_add(u64::try_from(frame.data.len()).unwrap_or(u64::MAX));
        if let Some(writer) = output.as_deref_mut() {
            writer.write_all(&frame.data)?;
        }
    }
    Ok(())
}

#[cfg(windows)]
fn parse_seconds(args: &[String]) -> Result<u64, Box<dyn std::error::Error>> {
    let Some(index) = args.iter().position(|arg| arg == "--seconds") else {
        return Ok(10);
    };
    let raw = args
        .get(index + 1)
        .ok_or("--seconds requires a positive integer")?;
    let seconds = raw.parse::<u64>()?;
    if seconds == 0 || seconds > 3_600 {
        return Err("--seconds must be between 1 and 3600".into());
    }
    Ok(seconds)
}

#[cfg(windows)]
fn parse_output_path(args: &[String]) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(index) = args.iter().position(|arg| arg == "--output") else {
        return Ok(None);
    };
    let path = args
        .get(index + 1)
        .ok_or("--output requires a file path")?;
    Ok(Some(path.clone()))
}

#[cfg(windows)]
fn capture_error(error: classmesh_capture_win::CaptureFailure) -> std::io::Error {
    std::io::Error::other(format!("DXGI capture error: {error:?}"))
}

#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-media-probe is supported only on Windows");
}
