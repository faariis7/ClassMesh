use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use classmesh_network::AssembledFrame;
use classmesh_network::receiver::{ReceiverEvent, ReceiverPolicy};
use classmesh_network::transport::UdpFrameReceiver;
use classmesh_network::udp::DatagramError;

#[derive(Debug, Default)]
struct ReceiverCounters {
    frames: u64,
    bytes: u64,
    keyframes: u64,
    nack_requests: u64,
    keyframe_requests: u64,
    stale_drops: u64,
    decoded_gpu_frames: u64,
    presented_frames: u64,
    present_errors: u64,
    decode_errors: u64,
    decode_waiting_frames: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let listen = parse_socket_arg(&args, "--listen", "0.0.0.0:57000")?;
    let seconds = parse_u64_arg(&args, "--seconds", 30, 1, 86_400)?;
    let output_path = parse_optional_arg(&args, "--output")?;
    let render_enabled = has_flag(&args, "--render");
    let decode_enabled = has_flag(&args, "--decode") || render_enabled;

    let mut output = match output_path.as_deref() {
        Some(path) => {
            eprintln!("ClassMesh media receiver writing reassembled H.264 to {path}");
            Some(BufWriter::new(File::create(path)?))
        }
        None => None,
    };
    let mut decoder = if decode_enabled {
        Some(DecodeProbe::new(render_enabled)?)
    } else {
        None
    };

    let mut receiver = UdpFrameReceiver::bind(listen, ReceiverPolicy::default())?;
    receiver.set_read_timeout(Some(Duration::from_millis(100)))?;
    let bound = receiver.local_addr()?;
    eprintln!("ClassMesh media receiver listening on {bound} for {seconds} seconds");
    if decoder.is_some() {
        eprintln!("hardware H.264 decode probe is enabled; waiting for the first keyframe");
    }
    if render_enabled {
        eprintln!("D3D11 flip-model presentation window is enabled");
    }

    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_secs(seconds))
        .unwrap_or(started);
    let mut next_report = started;
    let mut counters = ReceiverCounters::default();

    while Instant::now() < deadline {
        let now_us = elapsed_us(started);
        match receiver.receive_once(now_us) {
            Ok(batch) => {
                handle_events(
                    &batch.events,
                    output.as_mut(),
                    decoder.as_mut(),
                    &mut counters,
                )?;
            }
            Err(DatagramError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(format!("UDP media receive failed: {error}").into()),
        }

        let tick_events = receiver.tick(elapsed_us(started));
        handle_events(
            &tick_events,
            output.as_mut(),
            decoder.as_mut(),
            &mut counters,
        )?;

        if let Some(active) = decoder.as_mut()
            && !active.pump_window()
        {
            eprintln!("student presentation window closed; stopping media receiver");
            break;
        }

        if Instant::now() >= next_report {
            let stats = receiver.stats();
            let gpu_recoveries = decoder.as_ref().map_or(0, DecodeProbe::gpu_recoveries);
            eprintln!(
                "receiver stats: datagrams={} frames={} bytes={} keyframes={} sequence_gaps={} reordered={} nack_requests={} keyframe_requests={} stale_drops={} decoded_gpu_frames={} presented_frames={} present_errors={} decode_errors={} decode_waiting_frames={} gpu_recoveries={}",
                stats.datagrams_received,
                counters.frames,
                counters.bytes,
                counters.keyframes,
                stats.sequence_gaps_observed,
                stats.reordered_or_duplicate,
                counters.nack_requests,
                counters.keyframe_requests,
                counters.stale_drops,
                counters.decoded_gpu_frames,
                counters.presented_frames,
                counters.present_errors,
                counters.decode_errors,
                counters.decode_waiting_frames,
                gpu_recoveries
            );
            next_report = Instant::now()
                .checked_add(Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }
    }

    if let Some(writer) = output.as_mut() {
        writer.flush()?;
    }
    if let Some(active) = decoder.as_mut() {
        match active.finish() {
            Ok(batch) => apply_decode_batch(&mut counters, batch),
            Err(error) => {
                counters.decode_errors = counters.decode_errors.saturating_add(1);
                eprintln!("hardware decoder shutdown reported: {error}");
            }
        }
    }

    let stats = receiver.stats();
    let gpu_recoveries = decoder.as_ref().map_or(0, DecodeProbe::gpu_recoveries);
    eprintln!(
        "ClassMesh media receiver complete: datagrams={} frames={} bytes={} keyframes={} sequence_gaps={} reordered={} nack_requests={} keyframe_requests={} stale_drops={} decoded_gpu_frames={} presented_frames={} present_errors={} decode_errors={} decode_waiting_frames={} gpu_recoveries={} elapsed={:.2}s",
        stats.datagrams_received,
        counters.frames,
        counters.bytes,
        counters.keyframes,
        stats.sequence_gaps_observed,
        stats.reordered_or_duplicate,
        counters.nack_requests,
        counters.keyframe_requests,
        counters.stale_drops,
        counters.decoded_gpu_frames,
        counters.presented_frames,
        counters.present_errors,
        counters.decode_errors,
        counters.decode_waiting_frames,
        gpu_recoveries,
        started.elapsed().as_secs_f32()
    );
    Ok(())
}

fn handle_events<W: Write>(
    events: &[ReceiverEvent],
    mut output: Option<&mut W>,
    mut decoder: Option<&mut DecodeProbe>,
    counters: &mut ReceiverCounters,
) -> Result<(), Box<dyn std::error::Error>> {
    for event in events {
        match event {
            ReceiverEvent::FrameReady(frame) => {
                counters.frames = counters.frames.saturating_add(1);
                counters.bytes = counters
                    .bytes
                    .saturating_add(u64::try_from(frame.data.len()).unwrap_or(u64::MAX));
                if frame.keyframe {
                    counters.keyframes = counters.keyframes.saturating_add(1);
                }
                if let Some(writer) = output.as_deref_mut() {
                    writer.write_all(&frame.data)?;
                }
                if let Some(active) = decoder.as_deref_mut() {
                    match active.submit(frame) {
                        Ok(DecodeStep::Decoded(batch)) => apply_decode_batch(counters, batch),
                        Ok(DecodeStep::WaitingForKeyframe) => {
                            counters.decode_waiting_frames =
                                counters.decode_waiting_frames.saturating_add(1);
                        }
                        Err(error) => {
                            counters.decode_errors = counters.decode_errors.saturating_add(1);
                            eprintln!(
                                "hardware decode failed on frame={}: {error}; waiting for a new keyframe",
                                frame.frame_id
                            );
                            active.recover_after_loss();
                        }
                    }
                }
            }
            ReceiverEvent::NeedNack {
                frame_id,
                missing_packet_indices,
                ..
            } => {
                counters.nack_requests = counters.nack_requests.saturating_add(1);
                eprintln!(
                    "receiver requests NACK: frame={frame_id}, missing={missing_packet_indices:?}"
                );
            }
            ReceiverEvent::NeedKeyframe { after_frame_id, .. } => {
                counters.keyframe_requests = counters.keyframe_requests.saturating_add(1);
                eprintln!("receiver requests keyframe after frame={after_frame_id}");
                if let Some(active) = decoder.as_deref_mut() {
                    active.recover_after_loss();
                }
            }
            ReceiverEvent::DroppedStaleFrame { frame_id, .. } => {
                counters.stale_drops = counters.stale_drops.saturating_add(1);
                eprintln!("receiver dropped stale frame={frame_id}");
            }
        }
    }
    Ok(())
}

fn apply_decode_batch(counters: &mut ReceiverCounters, batch: DecodeBatch) {
    counters.decoded_gpu_frames = counters
        .decoded_gpu_frames
        .saturating_add(u64::try_from(batch.decoded).unwrap_or(u64::MAX));
    counters.presented_frames = counters
        .presented_frames
        .saturating_add(u64::try_from(batch.presented).unwrap_or(u64::MAX));
    counters.present_errors = counters
        .present_errors
        .saturating_add(u64::try_from(batch.present_errors).unwrap_or(u64::MAX));
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DecodeBatch {
    decoded: usize,
    presented: usize,
    present_errors: usize,
}

#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeStep {
    Decoded(DecodeBatch),
    WaitingForKeyframe,
}

#[cfg(windows)]
struct DecodeProbe {
    decoder: classmesh_codec_win::mf_decoder::MfH264Decoder,
    presentation: Option<classmesh_worker::receiver_render::PresentationWindow>,
    device: windows::Win32::Graphics::Direct3D11::ID3D11Device,
    _platform: classmesh_codec_win::mf::MfPlatform,
    render_enabled: bool,
    waiting_for_keyframe: bool,
    gpu_recoveries: u64,
}

#[cfg(windows)]
impl DecodeProbe {
    fn new(render_enabled: bool) -> Result<Self, Box<dyn std::error::Error>> {
        use classmesh_codec_win::mf::MfPlatform;
        use classmesh_worker::receiver_render::PresentationWindow;

        let platform = MfPlatform::startup()?;
        let (device, decoder) = Self::create_decoder_device()?;
        let presentation = if render_enabled {
            Some(PresentationWindow::new(&device, 1280, 720)?)
        } else {
            None
        };

        Ok(Self {
            decoder,
            presentation,
            device,
            _platform: platform,
            render_enabled,
            waiting_for_keyframe: true,
            gpu_recoveries: 0,
        })
    }

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
                Ok(decoder) => {
                    eprintln!(
                        "hardware decode candidate selected: {} ({})",
                        candidate.name(),
                        candidate.clsid()
                    );
                    return Ok((device, decoder));
                }
                Err(error) => failures.push(format!("{}: {error}", candidate.name())),
            }
        }

        Err(format!(
            "no D3D11-aware H.264 decoder could be activated: {}",
            failures.join(" | ")
        )
        .into())
    }

    fn rebuild_gpu_pipeline(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        use classmesh_worker::receiver_render::PresentationWindow;

        eprintln!("rebuilding student D3D11 decoder/presenter pipeline after device loss");
        let (new_device, new_decoder) = Self::create_decoder_device()?;

        if self.render_enabled {
            if let Some(presentation) = self.presentation.as_mut() {
                presentation.recover_device(&new_device)?;
            } else {
                self.presentation = Some(PresentationWindow::new(&new_device, 1280, 720)?);
            }
        }

        self.decoder = new_decoder;
        self.device = new_device;
        self.waiting_for_keyframe = true;
        self.gpu_recoveries = self.gpu_recoveries.saturating_add(1);
        eprintln!(
            "student GPU media pipeline rebuilt; waiting for keyframe (recovery #{})",
            self.gpu_recoveries
        );
        Ok(())
    }

    fn submit(&mut self, frame: &AssembledFrame) -> Result<DecodeStep, Box<dyn std::error::Error>> {
        use classmesh_render_win::{DxgiFailureClass, classify_dxgi_error};

        if self.waiting_for_keyframe && !frame.keyframe {
            return Ok(DecodeStep::WaitingForKeyframe);
        }

        let mut batch = self.drain_decoded()?;
        if self.waiting_for_keyframe {
            if !frame.keyframe {
                return Ok(DecodeStep::Decoded(batch));
            }
            self.waiting_for_keyframe = false;
        }

        match self
            .decoder
            .submit_access_unit(&frame.data, frame.timestamp_us)
        {
            Ok(()) => {}
            Err(error) if classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost => {
                self.rebuild_gpu_pipeline()?;
                if !frame.keyframe {
                    return Ok(DecodeStep::Decoded(batch));
                }
                self.waiting_for_keyframe = false;
                self.decoder
                    .submit_access_unit(&frame.data, frame.timestamp_us)?;
            }
            Err(error) => return Err(error.into()),
        }

        batch.add(self.drain_decoded()?);
        Ok(DecodeStep::Decoded(batch))
    }

    fn drain_decoded(&mut self) -> Result<DecodeBatch, Box<dyn std::error::Error>> {
        use classmesh_render_win::{DxgiFailureClass, classify_dxgi_error};

        let frames = match self.decoder.poll_decoded() {
            Ok(frames) => frames,
            Err(error) if classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost => {
                self.rebuild_gpu_pipeline()?;
                return Ok(DecodeBatch::default());
            }
            Err(error) => return Err(error.into()),
        };
        let mut batch = DecodeBatch {
            decoded: frames.len(),
            ..DecodeBatch::default()
        };
        let mut device_lost = false;
        for frame in &frames {
            if let Some(presentation) = self.presentation.as_mut() {
                match presentation.present(frame) {
                    Ok(()) => batch.presented = batch.presented.saturating_add(1),
                    Err(error) => {
                        batch.present_errors = batch.present_errors.saturating_add(1);
                        if classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost {
                            device_lost = true;
                            eprintln!(
                                "D3D11 presentation reported device loss; rebuilding shared GPU media pipeline"
                            );
                            break;
                        }
                        eprintln!(
                            "D3D11 presentation failed while decode remains healthy: {error}"
                        );
                    }
                }
            }
        }

        if device_lost {
            drop(frames);
            self.rebuild_gpu_pipeline()?;
        }
        Ok(batch)
    }

    fn recover_after_loss(&mut self) {
        use classmesh_render_win::{DxgiFailureClass, classify_dxgi_error};

        if let Err(error) = self.decoder.flush() {
            if classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost {
                if let Err(recovery_error) = self.rebuild_gpu_pipeline() {
                    eprintln!("GPU pipeline rebuild failed during loss recovery: {recovery_error}");
                }
            } else {
                eprintln!("hardware decoder flush failed during loss recovery: {error}");
            }
        }
        self.waiting_for_keyframe = true;
    }

    fn pump_window(&mut self) -> bool {
        let (open, device_lost) = match self.presentation.as_mut() {
            Some(presentation) => {
                let open = presentation.pump_messages();
                let device_lost = presentation.take_device_lost();
                (open, device_lost)
            }
            None => (true, false),
        };

        if open
            && device_lost
            && let Err(error) = self.rebuild_gpu_pipeline()
        {
            eprintln!("GPU pipeline rebuild failed after window resize device loss: {error}");
        }
        open
    }

    fn finish(&mut self) -> Result<DecodeBatch, Box<dyn std::error::Error>> {
        let decoded = self.drain_decoded()?;
        self.decoder.end_streaming()?;
        Ok(decoded)
    }

    const fn gpu_recoveries(&self) -> u64 {
        self.gpu_recoveries
    }
}

#[cfg(windows)]
impl DecodeBatch {
    fn add(&mut self, other: Self) {
        self.decoded = self.decoded.saturating_add(other.decoded);
        self.presented = self.presented.saturating_add(other.presented);
        self.present_errors = self.present_errors.saturating_add(other.present_errors);
    }
}

#[cfg(not(windows))]
struct DecodeProbe;

#[cfg(not(windows))]
impl DecodeProbe {
    fn new(_render_enabled: bool) -> Result<Self, Box<dyn std::error::Error>> {
        Err("--decode/--render are supported only by the Windows media receiver".into())
    }

    fn submit(
        &mut self,
        _frame: &AssembledFrame,
    ) -> Result<DecodeStep, Box<dyn std::error::Error>> {
        Err("hardware decode is unavailable on this platform".into())
    }

    fn recover_after_loss(&mut self) {}

    fn pump_window(&mut self) -> bool {
        true
    }

    fn finish(&mut self) -> Result<DecodeBatch, Box<dyn std::error::Error>> {
        Ok(DecodeBatch::default())
    }

    const fn gpu_recoveries(&self) -> u64 {
        0
    }
}

fn parse_socket_arg(
    args: &[String],
    name: &str,
    default: &str,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let value = parse_optional_arg(args, name)?.unwrap_or_else(|| default.to_owned());
    Ok(value.parse()?)
}

fn parse_u64_arg(
    args: &[String],
    name: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    let Some(raw) = parse_optional_arg(args, name)? else {
        return Ok(default);
    };
    let value = raw.parse::<u64>()?;
    if value < min || value > max {
        return Err(format!("{name} must be between {min} and {max}").into());
    }
    Ok(value)
}

fn parse_optional_arg(
    args: &[String],
    name: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(index) = args.iter().position(|arg| arg == name) else {
        return Ok(None);
    };
    let value = args
        .get(index + 1)
        .ok_or_else(|| format!("{name} requires a value"))?;
    Ok(Some(value.clone()))
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|arg| arg == name)
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}
