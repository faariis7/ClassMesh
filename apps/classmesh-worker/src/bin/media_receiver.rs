use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use classmesh_network::receiver::{ReceiverEvent, ReceiverPolicy};
use classmesh_network::transport::UdpFrameReceiver;
use classmesh_network::udp::DatagramError;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let listen = parse_socket_arg(&args, "--listen", "0.0.0.0:57000")?;
    let seconds = parse_u64_arg(&args, "--seconds", 30, 1, 86_400)?;
    let output_path = parse_optional_arg(&args, "--output")?;

    let mut output = match output_path.as_deref() {
        Some(path) => {
            eprintln!("ClassMesh media receiver writing reassembled H.264 to {path}");
            Some(BufWriter::new(File::create(path)?))
        }
        None => None,
    };

    let mut receiver = UdpFrameReceiver::bind(listen, ReceiverPolicy::default())?;
    receiver.set_read_timeout(Some(Duration::from_millis(100)))?;
    let bound = receiver.local_addr()?;
    eprintln!("ClassMesh media receiver listening on {bound} for {seconds} seconds");

    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_secs(seconds))
        .unwrap_or(started);
    let mut next_report = started;
    let mut frames = 0_u64;
    let mut bytes = 0_u64;
    let mut keyframes = 0_u64;
    let mut nack_requests = 0_u64;
    let mut keyframe_requests = 0_u64;
    let mut stale_drops = 0_u64;

    while Instant::now() < deadline {
        let now_us = elapsed_us(started);
        match receiver.receive_once(now_us) {
            Ok(batch) => {
                handle_events(
                    &batch.events,
                    output.as_mut(),
                    &mut frames,
                    &mut bytes,
                    &mut keyframes,
                    &mut nack_requests,
                    &mut keyframe_requests,
                    &mut stale_drops,
                )?;
            }
            Err(DatagramError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(format!("UDP media receive failed: {error:?}").into()),
        }

        let tick_events = receiver.tick(elapsed_us(started));
        handle_events(
            &tick_events,
            output.as_mut(),
            &mut frames,
            &mut bytes,
            &mut keyframes,
            &mut nack_requests,
            &mut keyframe_requests,
            &mut stale_drops,
        )?;

        if Instant::now() >= next_report {
            let stats = receiver.stats();
            eprintln!(
                "receiver stats: datagrams={} frames={} bytes={} keyframes={} sequence_gaps={} reordered={} nack_requests={} keyframe_requests={} stale_drops={}",
                stats.datagrams_received,
                frames,
                bytes,
                keyframes,
                stats.sequence_gaps_observed,
                stats.reordered_or_duplicate,
                nack_requests,
                keyframe_requests,
                stale_drops
            );
            next_report = Instant::now()
                .checked_add(Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }
    }

    if let Some(writer) = output.as_mut() {
        writer.flush()?;
    }
    let stats = receiver.stats();
    eprintln!(
        "ClassMesh media receiver complete: datagrams={} frames={} bytes={} keyframes={} sequence_gaps={} reordered={} nack_requests={} keyframe_requests={} stale_drops={} elapsed={:.2}s",
        stats.datagrams_received,
        frames,
        bytes,
        keyframes,
        stats.sequence_gaps_observed,
        stats.reordered_or_duplicate,
        nack_requests,
        keyframe_requests,
        stale_drops,
        started.elapsed().as_secs_f32()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_events<W: Write>(
    events: &[ReceiverEvent],
    mut output: Option<&mut W>,
    frames: &mut u64,
    bytes: &mut u64,
    keyframes: &mut u64,
    nack_requests: &mut u64,
    keyframe_requests: &mut u64,
    stale_drops: &mut u64,
) -> std::io::Result<()> {
    for event in events {
        match event {
            ReceiverEvent::FrameReady(frame) => {
                *frames = frames.saturating_add(1);
                *bytes = bytes.saturating_add(u64::try_from(frame.data.len()).unwrap_or(u64::MAX));
                if frame.keyframe {
                    *keyframes = keyframes.saturating_add(1);
                }
                if let Some(writer) = output.as_deref_mut() {
                    writer.write_all(&frame.data)?;
                }
            }
            ReceiverEvent::NeedNack {
                frame_id,
                missing_packet_indices,
                ..
            } => {
                *nack_requests = nack_requests.saturating_add(1);
                eprintln!(
                    "receiver requests NACK: frame={frame_id}, missing={missing_packet_indices:?}"
                );
            }
            ReceiverEvent::NeedKeyframe { after_frame_id, .. } => {
                *keyframe_requests = keyframe_requests.saturating_add(1);
                eprintln!("receiver requests keyframe after frame={after_frame_id}");
            }
            ReceiverEvent::DroppedStaleFrame { frame_id, .. } => {
                *stale_drops = stale_drops.saturating_add(1);
                eprintln!("receiver dropped stale frame={frame_id}");
            }
        }
    }
    Ok(())
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

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}
