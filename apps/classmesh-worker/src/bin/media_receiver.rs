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
    decode_errors: u64,
    decode_waiting_frames: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let listen = parse_socket_arg(&args, "--listen", "0.0.0.0:57000")?;
    let seconds = parse_u64_arg(&args, "--seconds", 30, 1, 86_400)?;
    let output_path = parse_optional_arg(&args, "--output")?;
    let decode_enabled = has_flag(&args, "--decode");

    let mut output = match output_path.as_deref() {
        Some(path) => {
            eprintln!("ClassMesh media receiver writing reassembled H.264 to {path}");
            Some(BufWriter::new(File::create(path)?))
        }
        None => None,
    };
    let mut decoder = if decode_enabled {
        Some(DecodeProbe::new()?)
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

        if Instant::now() >= next_report {
            let stats = receiver.stats();
            eprintln!(
                "receiver stats: datagrams={} frames={} bytes={} keyframes={} sequence_gaps={} reordered={} nack_requests={} keyframe_requests={} stale_drops={} decoded_gpu_frames={} decode_errors={} decode_waiting_frames={}",
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
                counters.decode_errors,
                counters.decode_waiting_frames
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
            Ok(decoded) => {
                counters.decoded_gpu_frames = counters
                    .decoded_gpu_frames
                    .saturating_add(u64::try_from(decoded).unwrap_or(u64::MAX));
            }
            Err(error) => {
                counters.decode_errors = counters.decode_errors.saturating_add(1);
                eprintln!("hardware decoder shutdown reported: {error}");
            }
        }
    }

    let stats = receiver.stats();
    eprintln!(
        "ClassMesh media receiver complete: datagrams={} frames={} bytes={} keyframes={} sequence_gaps={} reordered={} nack_requests={} keyframe_requests={} stale_drops={} decoded_gpu_frames={} decode_errors={} decode_waiting_frames={} elapsed={:.2}s",
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
        counters.decode_errors,
        counters.decode_waiting_frames,
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
                        Ok(DecodeStep::Decoded(count)) => {
                            counters.decoded_gpu_frames = counters
                                .decoded_gpu_frames
                                .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
                        }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeStep {
    Decoded(usize),
    WaitingForKeyframe,
}

#[cfg(windows)]
struct DecodeProbe {
    decoder: classmesh_codec_win::mf_decoder::MfH264Decoder,
    _device: windows::Win32::Graphics::Direct3D11::ID3D11Device,
    _platform: classmesh_codec_win::mf::MfPlatform,
    waiting_for_keyframe: bool,
}

#[cfg(windows)]
impl DecodeProbe {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        use classmesh_codec_win::d3d11::create_default_video_device;
        use classmesh_codec_win::mf::MfPlatform;
        use classmesh_codec_win::mf_decoder::{MfH264Decoder, enumerate_h264_decoders};

        let platform = MfPlatform::startup()?;
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
                    return Ok(Self {
                        decoder,
                        _device: device,
                        _platform: platform,
                        waiting_for_keyframe: true,
                    });
                }
                Err(error) => {
                    failures.push(format!("{}: {error}", candidate.name()));
                }
            }
        }

        Err(format!(
            "no D3D11-aware H.264 decoder could be activated: {}",
            failures.join(" | ")
        )
        .into())
    }

    fn submit(&mut self, frame: &AssembledFrame) -> Result<DecodeStep, Box<dyn std::error::Error>> {
        if self.waiting_for_keyframe && !frame.keyframe {
            return Ok(DecodeStep::WaitingForKeyframe);
        }
        if frame.keyframe {
            self.waiting_for_keyframe = false;
        }

        let mut decoded = self.decoder.poll_decoded()?.len();
        self.decoder
            .submit_access_unit(&frame.data, frame.timestamp_us)?;
        decoded = decoded.saturating_add(self.decoder.poll_decoded()?.len());
        Ok(DecodeStep::Decoded(decoded))
    }

    fn recover_after_loss(&mut self) {
        if let Err(error) = self.decoder.flush() {
            eprintln!("hardware decoder flush failed during loss recovery: {error}");
        }
        self.waiting_for_keyframe = true;
    }

    fn finish(&mut self) -> Result<usize, Box<dyn std::error::Error>> {
        let decoded = self.decoder.poll_decoded()?.len();
        self.decoder.end_streaming()?;
        Ok(decoded)
    }
}

#[cfg(not(windows))]
struct DecodeProbe;

#[cfg(not(windows))]
impl DecodeProbe {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Err("--decode is supported only by the Windows media receiver".into())
    }

    fn submit(
        &mut self,
        _frame: &AssembledFrame,
    ) -> Result<DecodeStep, Box<dyn std::error::Error>> {
        Err("hardware decode is unavailable on this platform".into())
    }

    fn recover_after_loss(&mut self) {}

    fn finish(&mut self) -> Result<usize, Box<dyn std::error::Error>> {
        Ok(0)
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
