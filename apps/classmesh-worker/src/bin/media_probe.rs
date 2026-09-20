#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::{BufWriter, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};

    use classmesh_capture_win::CaptureStep;
    use classmesh_core::keyframe::KeyframeRequestCoordinator;
    use classmesh_network::feedback::UdpFeedbackReceiver;
    use classmesh_network::transport::{UdpFrameSender, UdpSenderConfig};
    use classmesh_worker::presentation::PresentationPipeline;

    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--benchmark-h264") {
        return run_h264_benchmark(&args);
    }
    let seconds = parse_seconds(&args)?;
    let output_path = parse_output_path(&args)?;
    let udp_destination = parse_udp_destination(&args)?;
    let feedback_listen = parse_feedback_listen(&args)?;
    if feedback_listen.is_some() && udp_destination.is_none() {
        return Err("--feedback-listen requires --udp-to".into());
    }

    let mut output = match output_path.as_deref() {
        Some(path) => {
            eprintln!("ClassMesh media probe writing raw H.264 access units to {path}");
            Some(BufWriter::new(File::create(path)?))
        }
        None => None,
    };
    let mut udp_sender = match udp_destination {
        Some(destination) => {
            let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
            let sender = UdpFrameSender::bind(local, UdpSenderConfig::presentation(1, destination))
                .map_err(network_error)?;
            eprintln!(
                "ClassMesh media probe streaming encoded frames from {} to {destination}",
                sender.local_addr().map_err(network_error)?
            );
            Some(sender)
        }
        None => None,
    };
    let feedback_receiver = match feedback_listen {
        Some(listen) => {
            let receiver = UdpFeedbackReceiver::bind(listen).map_err(feedback_error)?;
            receiver.set_nonblocking(true).map_err(feedback_error)?;
            eprintln!(
                "Phase-4 diagnostic media feedback listening on {}",
                receiver.local_addr().map_err(feedback_error)?
            );
            Some(receiver)
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
    let mut feedback_stats = FeedbackStats::default();
    let mut keyframe_coordinator = KeyframeRequestCoordinator::default();
    let mut pending_keyframe_request = false;

    eprintln!("ClassMesh media probe running for {seconds} seconds");

    while Instant::now() < deadline {
        if let (Some(receiver), Some(sender)) = (feedback_receiver.as_ref(), udp_sender.as_mut()) {
            pending_keyframe_request |= drain_feedback(
                receiver,
                sender,
                elapsed_us(started),
                &mut keyframe_coordinator,
                &mut feedback_stats,
            )?;
        }

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

                let active = pipeline.as_mut().expect("pipeline was initialized above");
                if pending_keyframe_request {
                    match active.request_keyframe() {
                        Ok(()) => {
                            feedback_stats.keyframe_forces =
                                feedback_stats.keyframe_forces.saturating_add(1);
                            pending_keyframe_request = false;
                            eprintln!("teacher encoder accepted coalesced keyframe request");
                        }
                        Err(error) => {
                            feedback_stats.keyframe_force_errors =
                                feedback_stats.keyframe_force_errors.saturating_add(1);
                            eprintln!("teacher encoder rejected keyframe request: {error}");
                            pending_keyframe_request = false;
                        }
                    }
                }

                let encoded = active.process_frame(meta, frame)?;
                handle_encoded_frames(
                    &encoded,
                    output.as_mut(),
                    udp_sender.as_mut(),
                    elapsed_us(started),
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
                pending_keyframe_request = true;
                if delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(delay_ms.min(250)));
                }
            }
            CaptureStep::Suspended(reason) => {
                return Err(
                    format!("DXGI capture suspended during media probe: {reason:?}").into(),
                );
            }
            CaptureStep::Failed(reason) => {
                return Err(format!("DXGI capture failed during media probe: {reason:?}").into());
            }
        }

        if Instant::now() >= next_report {
            if let Some(active) = pipeline.as_ref() {
                let stats = active.stats();
                if let Some(sender) = udp_sender.as_ref() {
                    let network = sender.stats();
                    eprintln!(
                        "media stats: captured={} submitted={} encoded={} keyframes={} keyframe_requests={} rate_drop={} pool_drop={} in_flight={} bytes={} udp_frames={} udp_packets={} udp_payload_bytes={} retransmits={} feedback_rx={} feedback_errors={} keyframe_forces={} keyframe_force_errors={} keyframe_grants={} keyframe_suppressed={}",
                        stats.captured_frames,
                        stats.submitted_frames,
                        stats.encoded_frames,
                        stats.keyframes,
                        stats.keyframe_requests,
                        stats.rate_dropped_frames,
                        stats.pool_dropped_frames,
                        stats.in_flight_surfaces,
                        stats.encoded_bytes,
                        network.frames_sent,
                        network.packets_sent,
                        network.payload_bytes_sent,
                        network.retransmit_packets_sent,
                        feedback_stats.received,
                        feedback_stats.errors,
                        feedback_stats.keyframe_forces,
                        feedback_stats.keyframe_force_errors,
                        keyframe_coordinator.granted_requests(),
                        keyframe_coordinator.suppressed_requests()
                    );
                } else {
                    eprintln!(
                        "media stats: captured={} submitted={} encoded={} keyframes={} keyframe_requests={} rate_drop={} pool_drop={} in_flight={} bytes={}",
                        stats.captured_frames,
                        stats.submitted_frames,
                        stats.encoded_frames,
                        stats.keyframes,
                        stats.keyframe_requests,
                        stats.rate_dropped_frames,
                        stats.pool_dropped_frames,
                        stats.in_flight_surfaces,
                        stats.encoded_bytes
                    );
                }
            }
            next_report = Instant::now()
                .checked_add(Duration::from_secs(1))
                .unwrap_or_else(Instant::now);
        }
    }

    if let Some(active) = pipeline.as_mut() {
        let tail = active.finish()?;
        handle_encoded_frames(
            &tail,
            output.as_mut(),
            udp_sender.as_mut(),
            elapsed_us(started),
            &mut total_encoded_frames,
            &mut total_encoded_bytes,
        )?;
        let stats = active.stats();
        eprintln!(
            "final pipeline stats: captured={} submitted={} encoded={} keyframes={} keyframe_requests={} rate_drop={} pool_drop={} in_flight={} bytes={}",
            stats.captured_frames,
            stats.submitted_frames,
            stats.encoded_frames,
            stats.keyframes,
            stats.keyframe_requests,
            stats.rate_dropped_frames,
            stats.pool_dropped_frames,
            stats.in_flight_surfaces,
            stats.encoded_bytes
        );
    }

    if let Some(writer) = output.as_mut() {
        writer.flush()?;
    }

    if let Some(sender) = udp_sender.as_ref() {
        let stats = sender.stats();
        eprintln!(
            "final UDP stats: frames={} packets={} payload_bytes={} retransmits={} cache_misses={}",
            stats.frames_sent,
            stats.packets_sent,
            stats.payload_bytes_sent,
            stats.retransmit_packets_sent,
            stats.retransmit_cache_misses
        );
    }

    eprintln!(
        "ClassMesh media probe complete: encoded_frames={total_encoded_frames}, encoded_bytes={total_encoded_bytes}, feedback_rx={}, feedback_errors={}, keyframe_forces={}, keyframe_force_errors={}, keyframe_grants={}, keyframe_suppressed={}, elapsed={:.2}s",
        feedback_stats.received,
        feedback_stats.errors,
        feedback_stats.keyframe_forces,
        feedback_stats.keyframe_force_errors,
        keyframe_coordinator.granted_requests(),
        keyframe_coordinator.suppressed_requests(),
        started.elapsed().as_secs_f32()
    );
    Ok(())
}

#[cfg(windows)]
fn run_h264_benchmark(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};

    use classmesh_capture_win::CaptureStep;
    use classmesh_codec_win::{
        BenchmarkCapabilities, BoundedEncoderBenchmark, EncoderBenchmarkConfig, summarize_benchmark,
    };
    use classmesh_video::{Codec, EncoderClass};
    use classmesh_worker::presentation::{PresentationPipeline, PresentationTarget};

    const MISSING_OUTPUT_LATENCY: Duration = Duration::from_secs(5);
    const RESET_VERIFY_WINDOW: Duration = Duration::from_secs(2);

    let seconds = parse_seconds(args)?;
    let config = EncoderBenchmarkConfig::compatibility_720p30();
    let target = PresentationTarget::try_from(config)?;
    let mut benchmark = BoundedEncoderBenchmark::from_config(config)
        .map_err(|error| format!("invalid bounded H.264 benchmark config: {error:?}"))?;
    let mut capture = start_capture()?;
    let mut pipeline: Option<PresentationPipeline> = None;
    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_secs(seconds))
        .unwrap_or(started);
    let mut candidate = None;
    let mut profile = None;
    let mut low_latency_accepted = false;
    let mut keyframe_request_accepted = false;
    let mut keyframe_observed = false;
    let mut benchmark_started_at: Option<Instant> = None;

    eprintln!(
        "ClassMesh bounded H.264 benchmark: {}x{} @ {} fps, {} samples, {} kbps",
        config.width,
        config.height,
        config.target_fps,
        config.sample_frames,
        config.bitrate_kbps
    );

    while Instant::now() < deadline && !benchmark.is_submission_complete() {
        match capture.poll(16) {
            CaptureStep::Frame { meta, frame } => {
                if pipeline.is_none() {
                    let mut created =
                        PresentationPipeline::from_first_frame_with_target(&frame, target)?;
                    candidate = Some(created.encoder_candidate().clone());
                    profile = Some(created.profile());
                    low_latency_accepted = created.low_latency_accepted();
                    keyframe_request_accepted = created.request_keyframe().is_ok();
                    pipeline = Some(created);
                }

                let active = pipeline.as_mut().expect("benchmark pipeline initialized");
                let submitted_before = active.stats().submitted_frames;
                let process_started_at = Instant::now();
                let outputs = active.process_frame_with_metrics(meta, frame)?;
                let submitted_after = active.stats().submitted_frames;
                for _ in submitted_before..submitted_after {
                    if benchmark.record_submission() && benchmark_started_at.is_none() {
                        benchmark_started_at = Some(process_started_at);
                    }
                }
                for output in outputs {
                    keyframe_observed |= output.frame.meta.keyframe;
                    if benchmark.outputs() < benchmark.submitted() {
                        benchmark
                            .record_output(output.encode_latency)
                            .map_err(|error| format!("H.264 benchmark sample error: {error:?}"))?;
                    }
                }
            }
            CaptureStep::NoFrame => {}
            CaptureStep::RetryAfter { delay_ms, reason } => {
                eprintln!(
                    "H.264 benchmark DXGI retry after {reason:?} in {delay_ms} ms"
                );
                if delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(delay_ms.min(250)));
                }
            }
            CaptureStep::Suspended(reason) => {
                return Err(format!("DXGI suspended during H.264 benchmark: {reason:?}").into());
            }
            CaptureStep::Failed(reason) => {
                return Err(format!("DXGI failed during H.264 benchmark: {reason:?}").into());
            }
        }
    }

    let Some(mut active) = pipeline.take() else {
        return Err("H.264 benchmark captured no usable frames".into());
    };
    let tail = active.finish_with_metrics()?;
    for output in tail {
        keyframe_observed |= output.frame.meta.keyframe;
        if benchmark.outputs() < benchmark.submitted() {
            benchmark
                .record_output(output.encode_latency)
                .map_err(|error| format!("H.264 benchmark tail sample error: {error:?}"))?;
        }
    }
    benchmark
        .finalize_missing(MISSING_OUTPUT_LATENCY)
        .map_err(|error| format!("H.264 benchmark finalize error: {error:?}"))?;
    let benchmark_started_at =
        benchmark_started_at.ok_or("H.264 benchmark submitted no frames")?;
    let benchmark_elapsed = benchmark_started_at.elapsed().as_secs_f32();

    let reset_deadline = Instant::now()
        .checked_add(RESET_VERIFY_WINDOW)
        .unwrap_or_else(Instant::now);
    let mut reset_ok = false;
    while Instant::now() < reset_deadline {
        match capture.poll(16) {
            CaptureStep::Frame { meta, frame } => {
                match PresentationPipeline::from_first_frame_with_target(&frame, target) {
                    Ok(mut recreated) => {
                        if recreated.process_frame_with_metrics(meta, frame).is_ok()
                            && recreated.stats().submitted_frames > 0
                        {
                            reset_ok = true;
                        }
                    }
                    Err(error) => {
                        eprintln!("H.264 benchmark reset recreation failed: {error}");
                    }
                }
                break;
            }
            CaptureStep::NoFrame => {}
            CaptureStep::RetryAfter { delay_ms, .. } => {
                if delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(delay_ms.min(100)));
                }
            }
            CaptureStep::Suspended(_) | CaptureStep::Failed(_) => break,
        }
    }

    let candidate = candidate.ok_or("H.264 benchmark has no encoder candidate")?;
    let profile = profile.ok_or("H.264 benchmark has no resolved profile")?;
    let capabilities = BenchmarkCapabilities {
        gpu_native_input: true,
        low_latency_accepted,
        reset_ok,
        dynamic_bitrate_ok: false,
        keyframe_request_ok: keyframe_request_accepted && keyframe_observed,
    };
    let result = summarize_benchmark(
        &candidate,
        Codec::H264,
        benchmark.samples(),
        benchmark_elapsed,
        capabilities,
    )
    .map_err(|error| format!("H.264 benchmark summary failed: {error:?}"))?;

    // This slice validates the 720p compatibility profile only. Never promote a 720p result to a
    // 1080p class even if latency/FPS thresholds would otherwise satisfy the generic classifier.
    let qualified_class = result.class.min(EncoderClass::Compatibility);
    eprintln!(
        "H.264 benchmark evidence: encoder={:?}, profile={}x{}@{}fps, submitted={}, outputs={}, missing={}, sustained_fps={:.2}, p50_ms={:.2}, p95_ms={:.2}, low_latency={}, keyframe_ok={}, reset_ok={}, qualified_class={qualified_class:?}",
        candidate.name,
        profile.target_width,
        profile.target_height,
        profile.fps,
        benchmark.submitted(),
        result.output_frames,
        result.dropped_or_missing,
        result.probe.sustained_fps,
        result.probe.p50_encode_ms,
        result.probe.p95_encode_ms,
        result.probe.low_latency_accepted,
        result.probe.keyframe_request_ok,
        result.probe.reset_ok,
    );

    if qualified_class == EncoderClass::Unsupported {
        return Err("bounded H.264 benchmark did not qualify the compatibility profile".into());
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Debug, Default)]
struct FeedbackStats {
    received: u64,
    errors: u64,
    keyframe_forces: u64,
    keyframe_force_errors: u64,
}

#[cfg(windows)]
fn drain_feedback(
    receiver: &classmesh_network::feedback::UdpFeedbackReceiver,
    sender: &mut classmesh_network::transport::UdpFrameSender,
    now_us: u64,
    coordinator: &mut classmesh_core::keyframe::KeyframeRequestCoordinator,
    stats: &mut FeedbackStats,
) -> Result<bool, Box<dyn std::error::Error>> {
    use classmesh_network::feedback::{
        FeedbackTransportError, MediaFeedback, apply_sender_feedback,
    };

    const MAX_FEEDBACK_PER_TICK: usize = 32;
    let mut force_keyframe = false;
    for _ in 0..MAX_FEEDBACK_PER_TICK {
        let (feedback, peer) = match receiver.receive_one() {
            Ok(received) => received,
            Err(FeedbackTransportError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(error) => {
                stats.errors = stats.errors.saturating_add(1);
                eprintln!("ignoring malformed/unreadable media feedback: {error}");
                continue;
            }
        };

        stats.received = stats.received.saturating_add(1);
        if feedback.stream_id() != 1 {
            stats.errors = stats.errors.saturating_add(1);
            eprintln!(
                "ignoring feedback for unexpected stream {} from {peer}",
                feedback.stream_id()
            );
            continue;
        }

        let outcome = apply_sender_feedback(sender, now_us, &feedback).map_err(network_error)?;
        if outcome.retransmitted_packets > 0 {
            eprintln!(
                "retransmitted {} live media packets after feedback from {peer}",
                outcome.retransmitted_packets
            );
        }
        if outcome.keyframe_requested {
            let after_frame = match feedback {
                MediaFeedback::RequestKeyframe { after_frame_id, .. } => after_frame_id,
                MediaFeedback::Nack { .. } => 0,
            };
            if coordinator.request(now_us) {
                force_keyframe = true;
                eprintln!(
                    "accepted receiver keyframe request from {peer} after frame {after_frame}"
                );
            } else {
                eprintln!(
                    "coalesced receiver keyframe request from {peer} after frame {after_frame}"
                );
            }
        }
    }
    Ok(force_keyframe)
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
fn handle_encoded_frames<W: std::io::Write>(
    frames: &[classmesh_video::distributor::SharedEncodedFrame],
    mut output: Option<&mut W>,
    mut udp_sender: Option<&mut classmesh_network::transport::UdpFrameSender>,
    now_us: u64,
    total_frames: &mut u64,
    total_bytes: &mut u64,
) -> Result<(), Box<dyn std::error::Error>> {
    for frame in frames {
        *total_frames = total_frames.saturating_add(1);
        *total_bytes =
            total_bytes.saturating_add(u64::try_from(frame.data.len()).unwrap_or(u64::MAX));
        if let Some(writer) = output.as_deref_mut() {
            writer.write_all(&frame.data)?;
        }
        if let Some(sender) = udp_sender.as_deref_mut() {
            sender.send_frame(now_us, frame).map_err(network_error)?;
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
    let path = args.get(index + 1).ok_or("--output requires a file path")?;
    Ok(Some(path.clone()))
}

#[cfg(windows)]
fn parse_udp_destination(
    args: &[String],
) -> Result<Option<std::net::SocketAddr>, Box<dyn std::error::Error>> {
    parse_socket_option(args, "--udp-to")
}

#[cfg(windows)]
fn parse_feedback_listen(
    args: &[String],
) -> Result<Option<std::net::SocketAddr>, Box<dyn std::error::Error>> {
    parse_socket_option(args, "--feedback-listen")
}

#[cfg(windows)]
fn parse_socket_option(
    args: &[String],
    name: &str,
) -> Result<Option<std::net::SocketAddr>, Box<dyn std::error::Error>> {
    let Some(index) = args.iter().position(|arg| arg == name) else {
        return Ok(None);
    };
    let address = args
        .get(index + 1)
        .ok_or_else(|| format!("{name} requires an IP:port address"))?;
    Ok(Some(address.parse()?))
}

#[cfg(windows)]
fn elapsed_us(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

#[cfg(windows)]
fn capture_error(error: classmesh_capture_win::CaptureFailure) -> std::io::Error {
    std::io::Error::other(format!("DXGI capture error: {error:?}"))
}

#[cfg(windows)]
fn network_error(error: classmesh_network::transport::UdpSendError) -> std::io::Error {
    std::io::Error::other(format!("UDP media send error: {error:?}"))
}

#[cfg(windows)]
fn feedback_error(error: classmesh_network::feedback::FeedbackTransportError) -> std::io::Error {
    std::io::Error::other(format!("media feedback error: {error}"))
}

#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-media-probe is supported only on Windows");
}
