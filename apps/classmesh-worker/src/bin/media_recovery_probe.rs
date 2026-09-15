#[cfg(windows)]
use std::time::{Duration, Instant};

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use classmesh_codec_win::mf::MfPlatform;
    use classmesh_worker::receiver_render::PresentationWindow;

    let args: Vec<String> = std::env::args().collect();
    let cycles = parse_u64_arg(&args, "--cycles", 5, 1, 1_000)?;
    let pause_ms = parse_u64_arg(&args, "--pause-ms", 250, 0, 60_000)?;

    let _platform = MfPlatform::startup()?;
    let (device, mut decoder) = create_decoder_device()?;
    let mut presentation = PresentationWindow::new(&device, 1280, 720)?;

    eprintln!(
        "ClassMesh media recovery probe started: decoder={} cycles={} pause_ms={}",
        decoder.decoder_name(),
        cycles,
        pause_ms
    );
    eprintln!(
        "The probe keeps one HWND alive while repeatedly releasing and rebuilding the D3D11/MF decoder/presenter stack."
    );

    let mut longest_recovery = Duration::ZERO;
    let mut total_recovery = Duration::ZERO;

    for cycle in 1..=cycles {
        if !presentation.pump_messages() {
            eprintln!("presentation window closed before recovery cycle {cycle}");
            return Ok(());
        }

        if pause_ms > 0 {
            std::thread::sleep(Duration::from_millis(pause_ms));
        }

        let started = Instant::now();
        let (new_device, new_decoder) = create_decoder_device()?;
        presentation.recover_device(&new_device)?;
        decoder = new_decoder;
        let elapsed = started.elapsed();
        total_recovery = total_recovery.saturating_add(elapsed);
        longest_recovery = longest_recovery.max(elapsed);

        eprintln!(
            "recovery cycle {cycle}/{cycles}: decoder={} elapsed_ms={:.2} presenter_recoveries=ok",
            decoder.decoder_name(),
            elapsed.as_secs_f64() * 1_000.0
        );

        if !presentation.pump_messages() {
            eprintln!("presentation window closed after recovery cycle {cycle}");
            return Ok(());
        }
    }

    decoder.end_streaming()?;
    eprintln!(
        "ClassMesh media recovery probe complete: cycles={} total_recovery_ms={:.2} longest_recovery_ms={:.2}",
        cycles,
        total_recovery.as_secs_f64() * 1_000.0,
        longest_recovery.as_secs_f64() * 1_000.0
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-media-recovery-probe is supported only on Windows");
}

#[cfg(windows)]
fn create_decoder_device() -> Result<
    (
        windows::Win32::Graphics::Direct3D11::ID3D11Device,
        classmesh_codec_win::mf_decoder::MfH264Decoder,
    ),
    Box<dyn std::error::Error>,
> {
    use classmesh_codec_win::d3d11::create_default_video_device;
    use classmesh_codec_win::mf_decoder::{MfH264Decoder, enumerate_h264_decoders};

    let device = create_default_video_device()?;
    let candidates = enumerate_h264_decoders()?;
    if candidates.is_empty() {
        return Err("Media Foundation returned no H.264 decoder candidates".into());
    }

    let mut failures = Vec::new();
    for candidate in &candidates {
        match MfH264Decoder::new(candidate, &device) {
            Ok(decoder) => return Ok((device, decoder)),
            Err(error) => failures.push(format!("{}: {error}", candidate.name())),
        }
    }

    Err(format!(
        "no D3D11-aware H.264 decoder could be activated: {}",
        failures.join(" | ")
    )
    .into())
}

#[cfg(windows)]
fn parse_u64_arg(
    args: &[String],
    name: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    let Some(index) = args.iter().position(|arg| arg == name) else {
        return Ok(default);
    };
    let raw = args
        .get(index + 1)
        .ok_or_else(|| format!("{name} requires a value"))?;
    let value = raw.parse::<u64>()?;
    if value < min || value > max {
        return Err(format!("{name} must be between {min} and {max}").into());
    }
    Ok(value)
}
