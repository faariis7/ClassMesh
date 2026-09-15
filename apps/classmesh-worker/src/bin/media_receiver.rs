use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use classmesh_network::AssembledFrame;
use classmesh_network::feedback::{MediaFeedback, UdpFeedbackSender};
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
    feedback_sent: u64,
    feedback_errors: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct RecoveryTelemetry {
    recoveries: u64,
    forced_recoveries: u64,
    last: Duration,
    longest: Duration,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let listen = parse_socket_arg(&args, "--listen", "0.0.0.0:57000")?;
    let seconds = parse_u64_arg(&args, "--seconds", 30, 1, 86_400)?;
    let output_path = parse_optional_arg(&args, "--output")?;
    let feedback_to = parse_optional_socket_arg(&args, "--feedback-to")?;
    let render_enabled = has_flag(&args, "--render");
    let decode_enabled = has_flag(&args, "--decode") || render_enabled;
    let recover_after_frames =
        parse_optional_u64_arg(&args, "--recover-after-frames", 1, u64::MAX)?;
    if recover_after_frames.is_some() && !decode_enabled {
        return Err("--recover-after-frames requires --decode or --render".into());
    }

    let mut output = match output_path.as_deref() {
        Some(path) => {
            eprintln!("ClassMesh media receiver writing reassembled H.264 to {path}");
            Some(BufWriter::new(File::create(path)?))
        }
        None => None,
    };
    let mut decoder = if decode_enabled {
        Some(DecodeProbe::new(render_enabled, recover_after_frames)?)
    } else {
        None
    };
    let feedback_sender = match feedback_to {
        Some(destination) => {
            let local: SocketAddr = "0.0.0.0:0".parse()?;
            let sender = UdpFeedbackSender::bind(local, destination)?;
            eprintln!(
                "Phase-4 diagnostic feedback from {} to {destination}",
                sender.local_addr()?
            );
            Some(sender)
        }
        None => None,
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
    if let Some(frame_count) = recover_after_frames {
        eprintln!(
            "scheduled live-stream GPU media recovery after {frame_count} decoder-eligible frames"
        );
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
                    feedback_sender.as_ref(),
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
            feedback_sender.as_ref(),
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
            let recovery = decoder
                .as_ref()
                .map_or_else(RecoveryTelemetry::default, DecodeProbe::recovery_telemetry);
            eprintln!(
                "receiver stats: datagrams={} frames={} bytes={} keyframes={} sequence_gaps={} reordered={} nack_requests={} keyframe_requests={} feedback_sent={} feedback_errors={} stale_drops={} decoded_gpu_frames={} presented_frames={} present_errors={} decode_errors={} decode_waiting_frames={} gpu_recoveries={} forced_gpu_recoveries={} last_gpu_recovery_ms={:.2} longest_gpu_recovery_ms={:.2}",
                stats.datagrams_received,
                counters.frames,
                counters.bytes,
                counters.keyframes,
                stats.sequence_gaps_observed,
                stats.reordered_or_duplicate,
                counters.nack_requests,
                counters.keyframe_requests,
                counters.feedback_sent,
                counters.feedback_errors,
                counters.stale_drops,
                counters.decoded_gpu_frames,
                counters.presented_frames,
                counters.present_errors,
                counters.decode_errors,
                counters.decode_waiting_frames,
                recovery.recoveries,
                recovery.forced_recoveries,
                recovery.last.as_secs_f64() * 1_000.0,
                recovery.longest.as_secs_f64() * 1_000.0
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
    let recovery = decoder
        .as_ref()
        .map_or_else(RecoveryTelemetry::default, DecodeProbe::recovery_telemetry);
    eprintln!(
        "ClassMesh media receiver complete: datagrams={} frames={} bytes={} keyframes={} sequence_gaps={} reordered={} nack_requests={} keyframe_requests={} feedback_sent={} feedback_errors={} stale_drops={} decoded_gpu_frames={} presented_frames={} present_errors={} decode_errors={} decode_waiting_frames={} gpu_recoveries={} forced_gpu_recoveries={} last_gpu_recovery_ms={:.2} longest_gpu_recovery_ms={:.2} elapsed={:.2}s",
        stats.datagrams_received,
        counters.frames,
        counters.bytes,
        counters.keyframes,
        stats.sequence_gaps_observed,
        stats.reordered_or_duplicate,
        counters.nack_requests,
        counters.keyframe_requests,
        counters.feedback_sent,
        counters.feedback_errors,
        counters.stale_drops,
        counters.decoded_gpu_frames,
        counters.presented_frames,
        counters.present_errors,
        counters.decode_errors,
        counters.decode_waiting_frames,
        recovery.recoveries,
        recovery.forced_recoveries,
        recovery.last.as_secs_f64() * 1_000.0,
        recovery.longest.as_secs_f64() * 1_000.0,
        started.elapsed().as_secs_f32()
    );
    Ok(())
}

fn handle_events<W: Write>(
    events: &[ReceiverEvent],
    mut output: Option<&mut W>,
    mut decoder: Option<&mut DecodeProbe>,
    feedback_sender: Option<&UdpFeedbackSender>,
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
                stream_id,
                frame_id,
                missing_packet_indices,
            } => {
                counters.nack_requests = counters.nack_requests.saturating_add(1);
                eprintln!(
                    "receiver requests NACK: frame={frame_id}, missing={missing_packet_indices:?}"
                );
                send_feedback(
                    feedback_sender,
                    &MediaFeedback::Nack {
                        stream_id: *stream_id,
                        frame_id: *frame_id,
                        missing_packet_indices: missing_packet_indices.clone(),
                    },
                    counters,
                );
            }
            ReceiverEvent::NeedKeyframe {
                stream_id,
                after_frame_id,
            } => {
                counters.keyframe_requests = counters.keyframe_requests.saturating_add(1);
                eprintln!("receiver requests keyframe after frame={after_frame_id}");
                send_feedback(
                    feedback_sender,
                    &MediaFeedback::RequestKeyframe {
                        stream_id: *stream_id,
                        after_frame_id: *after_frame_id,
                    },
                    counters,
                );
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

fn send_feedback(
    sender: Option<&UdpFeedbackSender>,
    feedback: &MediaFeedback,
    counters: &mut ReceiverCounters,
) {
    let Some(sender) = sender else {
        return;
    };
    match sender.send(feedback) {
        Ok(_) => counters.feedback_sent = counters.feedback_sent.saturating_add(1),
        Err(error) => {
            counters.feedback_errors = counters.feedback_errors.saturating_add(1);
            eprintln!("media feedback send failed without stopping video: {error}");
        }
    }
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
    forced_recoveries: u64,
    recover_after_frames: Option<u64>,
    decoder_eligible_frames: u64,
    last_recovery: Duration,
    longest_recovery: Duration,
}

#[cfg(windows)]
impl DecodeProbe {
    fn new(
        render_enabled: bool,
        recover_after_frames: Option<u64>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
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
            forced_recoveries: 0,
            recover_after_frames,
            decoder_eligible_frames: 0,
            last_recovery: Duration::ZERO,
            longest_recovery: Duration::ZERO,
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

    fn rebuild_gpu_pipeline(&mut self, reason: &str) -> Result<(), Box<dyn std::error::Error>> {
        use classmesh_worker::receiver_render::PresentationWindow;

        let started = Instant::now();
        eprintln!("rebuilding student D3D11 decoder/presenter pipeline: reason={reason}");
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
        let elapsed = started.elapsed();
        self.last_recovery = elapsed;
        self.longest_recovery = self.longest_recovery.max(elapsed);
        eprintln!(
            "student GPU media pipeline rebuilt; waiting for keyframe (recovery #{}, elapsed_ms={:.2})",
            self.gpu_recoveries,
            elapsed.as_secs_f64() * 1_000.0
        );
        Ok(())
    }

    fn submit(&mut self, frame: &AssembledFrame) -> Result<DecodeStep, Box<dyn std::error::Error>> {
        use classmesh_render_win::{DxgiFailureClass, classify_dxgi_error};

        if self.waiting_for_keyframe && !frame.keyframe {
            return Ok(DecodeStep::WaitingForKeyframe);
        }

        self.decoder_eligible_frames = self.decoder_eligible_frames.saturating_add(1);
        if self
            .recover_after_frames
            .is_some_and(|threshold| self.decoder_eligible_frames >= threshold)
        {
            self.recover_after_frames = None;
            eprintln!(
                "triggering scheduled live-stream GPU media recovery at decoder frame {} (keyframe={})",
                self.decoder_eligible_frames, frame.keyframe
            );
            self.rebuild_gpu_pipeline("scheduled live-stream recovery test")?;
            self.forced_recoveries = self.forced_recoveries.saturating_add(1);
            if !frame.keyframe {
                return Ok(DecodeStep::WaitingForKeyframe);
            }
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
                self.rebuild_gpu_pipeline("decoder input device loss")?;
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
                self.rebuild_gpu_pipeline("decoder output device loss")?;
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
            self.rebuild_gpu_pipeline("presentation device loss")?;
        }
        Ok(batch)
    }

    fn recover_after_loss(&mut self) {
        use classmesh_render_win::{DxgiFailureClass, classify_dxgi_error};

        if let Err(error) = self.decoder.flush() {
            if classify_dxgi_error(&error) == DxgiFailureClass::DeviceLost {
                if let Err(recovery_error) = self.rebuild_gpu_pipeline("decoder flush device loss")
                {
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
            && let Err(error) = self.rebuild_gpu_pipeline("presentation window device loss")
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

    const fn recovery_telemetry(&self) -> RecoveryTelemetry {
        RecoveryTelemetry {
            recoveries: self.gpu_recoveries,
            forced_recoveries: self.forced_recoveries,
            last: self.last_recovery,
            longest: self.longest_recovery,
        }
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
    fn new(
        _render_enabled: bool,
        _recover_after_frames: Option<u64>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
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

    const fn recovery_telemetry(&self) -> RecoveryTelemetry {
        RecoveryTelemetry {
            recoveries: 0,
            forced_recoveries: 0,
            last: Duration::ZERO,
            longest: Duration::ZERO,
        }
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

fn parse_optional_socket_arg(
    args: &[String],
    name: &str,
) -> Result<Option<SocketAddr>, Box<dyn std::error::Error>> {
    parse_optional_arg(args, name)?
        .map(|value| value.parse::<SocketAddr>().map_err(Into::into))
        .transpose()
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

fn parse_optional_u64_arg(
    args: &[String],
    name: &str,
    min: u64,
    max: u64,
) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    let Some(raw) = parse_optional_arg(args, name)? else {
        return Ok(None);
    };
    let value = raw.parse::<u64>()?;
    if value < min || value > max {
        return Err(format!("{name} must be between {min} and {max}").into());
    }
    Ok(Some(value))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_u64_parser_accepts_absent_and_valid_values() {
        let absent = vec!["receiver".to_owned()];
        assert_eq!(
            parse_optional_u64_arg(&absent, "--recover-after-frames", 1, 100).unwrap(),
            None
        );

        let present = vec![
            "receiver".to_owned(),
            "--recover-after-frames".to_owned(),
            "90".to_owned(),
        ];
        assert_eq!(
            parse_optional_u64_arg(&present, "--recover-after-frames", 1, 100).unwrap(),
            Some(90)
        );
    }

    #[test]
    fn optional_u64_parser_rejects_out_of_range_value() {
        let args = vec![
            "receiver".to_owned(),
            "--recover-after-frames".to_owned(),
            "0".to_owned(),
        ];
        assert!(parse_optional_u64_arg(&args, "--recover-after-frames", 1, 100).is_err());
    }

    #[test]
    fn optional_socket_parser_accepts_feedback_destination() {
        let args = vec![
            "receiver".to_owned(),
            "--feedback-to".to_owned(),
            "127.0.0.1:57001".to_owned(),
        ];
        assert_eq!(
            parse_optional_socket_arg(&args, "--feedback-to").unwrap(),
            Some("127.0.0.1:57001".parse().unwrap())
        );
    }
}
