use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use classmesh_network::feedback::{MediaFeedback, UdpFeedbackSender};
use classmesh_network::receiver::{ReceiverEvent, ReceiverPolicy};
use classmesh_network::transport::UdpFrameReceiver;
use classmesh_network::udp::DatagramError;
use classmesh_worker::presentation_decode_render::{
    PresentationDecodeBatch as DecodeBatch, PresentationDecodeRuntime as DecodeProbe,
    PresentationDecodeStep as DecodeStep, PresentationRecoveryTelemetry as RecoveryTelemetry,
};

#[path = "media_receiver/reporting.rs"]
mod reporting;
#[path = "media_receiver/timing.rs"]
mod timing;

use reporting::{StatusReporter, StatusSnapshot};
use timing::FragmentTimings;

#[derive(Debug, Clone, Copy, Default)]
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

fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let listen = parse_socket_arg(&args, "--listen", "0.0.0.0:57000")?;
    let seconds = parse_u64_arg(&args, "--seconds", 30, 1, 86_400)?;
    let output_path = parse_optional_arg(&args, "--output")?;
    let feedback_to = parse_optional_socket_arg(&args, "--feedback-to")?;
    let render_enabled = has_flag(&args, "--render");
    let decode_enabled = has_flag(&args, "--decode") || render_enabled;
    let mut fragment_timings = if has_flag(&args, "--fragment-timing") {
        if !listen.ip().is_loopback() {
            return Err("--fragment-timing requires a loopback --listen address".into());
        }
        Some(FragmentTimings::default())
    } else {
        None
    };
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
    let mut status = StatusReporter::start(
        std::io::stderr(),
        receiver.stats(),
        started,
        fragment_timings.is_some(),
    )?;
    let mut counters = ReceiverCounters::default();
    let mut window_closed = false;

    let receiving = (|| -> Result<(), Box<dyn std::error::Error>> {
        while Instant::now() < deadline {
            // Keep the blocking socket wait outside the reassembly deadline.
            let read_started_us = fragment_timings.as_ref().map(|_| elapsed_us(started));
            let mut received_us = 0;
            match receiver.receive_once_with_clock(|| {
                received_us = elapsed_us(started);
                received_us
            }) {
                Ok(batch) => {
                    if let (Some(timings), Some(read_started_us)) =
                        (fragment_timings.as_mut(), read_started_us)
                    {
                        let assembled_us = elapsed_us(started);
                        timings.observe_packet(batch.header, read_started_us, received_us);
                        timings.observe_events(&batch.events, assembled_us);
                    }
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
            if let Some(timings) = fragment_timings.as_mut() {
                timings.observe_events(&tick_events, elapsed_us(started));
            }
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
                window_closed = true;
                break;
            }

            status.publish_if_due(Instant::now(), || StatusSnapshot {
                sampled_us: elapsed_us(started),
                stats: receiver.stats(),
                counters,
                recovery: decoder
                    .as_ref()
                    .map_or_else(RecoveryTelemetry::default, DecodeProbe::recovery_telemetry),
            });
        }
        if let Some(writer) = output.as_mut() {
            writer.flush()?;
        }
        Ok(())
    })();

    let stopped_receiving = Instant::now();
    let Some(status_reports_dropped) = status.finish(Duration::from_secs(2))? else {
        return Ok(ExitCode::FAILURE);
    };
    receiving?;
    if window_closed {
        eprintln!("student presentation window closed; stopping media receiver");
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
        "ClassMesh media receiver complete: datagrams={} frames={} bytes={} keyframes={} sequence_gaps={} sequence_missing_packets={} reordered={} nack_requests={} keyframe_requests={} feedback_sent={} feedback_errors={} stale_drops={} decoded_gpu_frames={} presented_frames={} present_errors={} decode_errors={} decode_waiting_frames={} gpu_recoveries={} forced_gpu_recoveries={} last_gpu_recovery_ms={:.2} longest_gpu_recovery_ms={:.2} status_reports_dropped={status_reports_dropped} elapsed={:.2}s",
        stats.datagrams_received,
        counters.frames,
        counters.bytes,
        counters.keyframes,
        stats.sequence_gaps_observed,
        stats.missing_datagrams_observed,
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
        stopped_receiving.duration_since(started).as_secs_f32()
    );
    if let Some(timings) = fragment_timings {
        timings.report();
    }
    Ok(ExitCode::SUCCESS)
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
                        Err(_) => {
                            counters.decode_errors = counters.decode_errors.saturating_add(1);
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
            ReceiverEvent::DroppedStaleFrame { .. } => {
                counters.stale_drops = counters.stale_drops.saturating_add(1);
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
        Err(_) => counters.feedback_errors = counters.feedback_errors.saturating_add(1),
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
    fn periodic_reports_continue_during_sustained_incomplete_frames() {
        use classmesh_network::udp::UdpMediaSocket;
        use classmesh_network::{PacketizeMeta, packetize_frame};
        use classmesh_protocol::media::MAX_PACKET_PAYLOAD;

        let loopback = "127.0.0.1:0".parse().unwrap();
        let socket = UdpMediaSocket::bind(loopback).unwrap();
        let mut receiver = UdpFrameReceiver::bind(loopback, ReceiverPolicy::default()).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let destination = receiver.local_addr().unwrap();
        let start = Instant::now();
        let mut status =
            StatusReporter::start(std::io::sink(), receiver.stats(), start, false).unwrap();
        let mut reports = 0;
        let mut stale = 0;
        for id in 1..=80 {
            let age = Duration::from_millis(id * 40);
            let fragments = packetize_frame(
                &vec![0x55; MAX_PACKET_PAYLOAD + 1],
                PacketizeMeta {
                    protocol_major: 0,
                    protocol_minor: 4,
                    stream_id: 1,
                    frame_id: id,
                    first_sequence: id as u32,
                    timestamp_us: 0,
                    keyframe: true,
                },
            )
            .unwrap();
            socket.send_packet_to(&fragments[0], destination).unwrap();
            let batch = receiver.receive_once(age.as_micros() as u64).unwrap();
            for event in batch.events {
                assert!(!matches!(event, ReceiverEvent::FrameReady(_)));
                stale += usize::from(matches!(event, ReceiverEvent::DroppedStaleFrame { .. }));
            }
            assert!(receiver.has_pending_frames());
            status.publish_if_due(start + age, || {
                reports += 1;
                StatusSnapshot {
                    sampled_us: age.as_micros() as u64,
                    stats: receiver.stats(),
                    counters: ReceiverCounters::default(),
                    recovery: RecoveryTelemetry::default(),
                }
            });
        }
        assert_eq!(stale, 78);
        assert_eq!(reports, 4, "incomplete frames must not starve reports");
        assert!(status.finish(Duration::from_secs(2)).unwrap().is_some());
    }

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
