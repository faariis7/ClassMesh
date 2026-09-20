#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    const BENCHMARK_KEYFRAME_AFTER_SUBMISSIONS: usize = 30;
    const BENCHMARK_RESET_MAX_SUBMISSIONS: usize = 30;

    use std::fs::File;
    use std::io::{BufWriter, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};

    use classmesh_capture_win::CaptureStep;
    use classmesh_codec_win::{
        BenchmarkCapabilities, BoundedEncoderBenchmark, EncoderBenchmarkConfig,
        EncoderCapabilityCacheKey, summarize_benchmark,
    };
    use classmesh_core::keyframe::KeyframeRequestCoordinator;
    use classmesh_network::feedback::UdpFeedbackReceiver;
    use classmesh_network::transport::{UdpFrameSender, UdpSenderConfig};
    use classmesh_video::Codec;
    use classmesh_worker::presentation::{PresentationPipeline, PresentationTarget};

    let args: Vec<String> = std::env::args().collect();
    let seconds = parse_seconds(&args)?;
    let encoder_benchmark_enabled = args.iter().any(|arg| arg == "--encoder-benchmark");
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

    let (mut capture, adapter_identity) = start_capture()?;
    let mut pipeline: Option<PresentationPipeline> = None;
    let benchmark_config =
        encoder_benchmark_enabled.then(EncoderBenchmarkConfig::compatibility_720p30);
    let mut encoder_benchmark = benchmark_config
        .map(BoundedEncoderBenchmark::from_config)
        .transpose()
        .map_err(benchmark_accumulator_error)?;
    let mut benchmark_started: Option<Instant> = None;
    let mut benchmark_non_keyframe_observed = false;
    let mut benchmark_keyframe_request_attempted = false;
    let mut benchmark_keyframe_request_pending = false;
    let mut benchmark_keyframe_request_frame: Option<u64> = None;
    let mut benchmark_keyframe_observed = false;
    let mut pending_reset_benchmark: Option<PendingResetBenchmark> = None;
    let mut benchmark_completed = !encoder_benchmark_enabled;
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
                    let created = match benchmark_config.filter(|_| !benchmark_completed) {
                        Some(config) => PresentationPipeline::from_first_frame_with_target(
                            &frame,
                            PresentationTarget::try_from(config)?,
                        )?,
                        None => PresentationPipeline::from_first_frame(&frame)?,
                    };
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
                    if !benchmark_completed && benchmark_started.is_none() {
                        benchmark_started = Some(Instant::now());
                    }
                    if let Some(pending) = pending_reset_benchmark.as_ref() {
                        let same_candidate = created.encoder_candidate() == &pending.candidate;
                        let recreated_profile = created.profile();
                        let same_target = same_benchmark_target(recreated_profile, pending.profile);
                        if !same_candidate || !same_target {
                            let pending = pending_reset_benchmark
                                .take()
                                .expect("pending reset benchmark exists");
                            report_encoder_benchmark(pending, false);
                            benchmark_completed = true;
                            eprintln!(
                                "encoder benchmark reset/recreate mismatch: same_candidate={} same_target={}",
                                same_candidate, same_target
                            );
                            pipeline = Some(created);
                            continue;
                        }
                    }
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

                let benchmark_frame_id = meta.frame_id;
                if encoder_benchmark.as_ref().is_some_and(|benchmark| {
                    benchmark.submitted() >= BENCHMARK_KEYFRAME_AFTER_SUBMISSIONS
                }) && benchmark_non_keyframe_observed
                    && !benchmark_keyframe_request_attempted
                {
                    benchmark_keyframe_request_attempted = true;
                    benchmark_keyframe_request_pending = active.request_keyframe().is_ok();
                }

                let submitted_before = active.stats().submitted_frames;
                let encoded = active.process_frame_with_metrics(meta, frame)?;
                let submitted_after = active.stats().submitted_frames;
                if benchmark_keyframe_request_pending && submitted_after > submitted_before {
                    benchmark_keyframe_request_frame = Some(benchmark_frame_id);
                    benchmark_keyframe_request_pending = false;
                }

                if let Some(benchmark) = encoder_benchmark.as_mut() {
                    for _ in submitted_before..submitted_after {
                        if !benchmark.record_submission() {
                            break;
                        }
                    }
                }
                if let Some(pending) = pending_reset_benchmark.as_mut() {
                    let accepted = submitted_after.saturating_sub(submitted_before);
                    pending.reset_submissions = pending
                        .reset_submissions
                        .saturating_add(usize::try_from(accepted).unwrap_or(usize::MAX));
                }

                let mut frames = Vec::with_capacity(encoded.len());
                for encoded_output in encoded {
                    if let Some(benchmark) = encoder_benchmark.as_mut() {
                        benchmark
                            .record_output(encoded_output.encode_latency)
                            .map_err(benchmark_accumulator_error)?;
                    }
                    if let Some(pending) = pending_reset_benchmark.as_mut() {
                        pending.reset_output_observed = true;
                    }
                    benchmark_non_keyframe_observed |= !encoded_output.frame.meta.keyframe;
                    benchmark_keyframe_observed |=
                        benchmark_keyframe_request_frame.is_some_and(|frame_id| {
                            frame_id == encoded_output.frame.meta.frame_id
                                && encoded_output.frame.meta.keyframe
                        });
                    frames.push(encoded_output.frame);
                }
                handle_encoded_frames(
                    &frames,
                    output.as_mut(),
                    udp_sender.as_mut(),
                    elapsed_us(started),
                    &mut total_encoded_frames,
                    &mut total_encoded_bytes,
                )?;

                let reset_probe_done = pending_reset_benchmark.as_ref().is_some_and(|pending| {
                    pending.reset_output_observed
                        || pending.reset_submissions >= BENCHMARK_RESET_MAX_SUBMISSIONS
                });
                if reset_probe_done {
                    let tail = active.finish_with_metrics()?;
                    let mut tail_frames = Vec::with_capacity(tail.len());
                    for encoded_output in tail {
                        if let Some(pending) = pending_reset_benchmark.as_mut() {
                            pending.reset_output_observed = true;
                        }
                        tail_frames.push(encoded_output.frame);
                    }
                    handle_encoded_frames(
                        &tail_frames,
                        output.as_mut(),
                        udp_sender.as_mut(),
                        elapsed_us(started),
                        &mut total_encoded_frames,
                        &mut total_encoded_bytes,
                    )?;
                    let pending = pending_reset_benchmark
                        .take()
                        .expect("completed reset probe must exist");
                    let reset_ok = pending.reset_output_observed;
                    report_encoder_benchmark(pending, reset_ok);
                    benchmark_completed = true;
                    pipeline = None;
                    continue;
                }

                if encoder_benchmark
                    .as_ref()
                    .is_some_and(BoundedEncoderBenchmark::is_submission_complete)
                {
                    let candidate = active.encoder_candidate().clone();
                    let benchmark_profile = active.profile();
                    let low_latency_accepted = active.low_latency_accepted();
                    let tail = active.finish_with_metrics()?;
                    let mut tail_frames = Vec::with_capacity(tail.len());
                    for encoded_output in tail {
                        if let Some(benchmark) = encoder_benchmark.as_mut() {
                            benchmark
                                .record_output(encoded_output.encode_latency)
                                .map_err(benchmark_accumulator_error)?;
                        }
                        benchmark_non_keyframe_observed |= !encoded_output.frame.meta.keyframe;
                        benchmark_keyframe_observed |= benchmark_keyframe_request_frame
                            .is_some_and(|frame_id| {
                                frame_id == encoded_output.frame.meta.frame_id
                                    && encoded_output.frame.meta.keyframe
                            });
                        tail_frames.push(encoded_output.frame);
                    }
                    handle_encoded_frames(
                        &tail_frames,
                        output.as_mut(),
                        udp_sender.as_mut(),
                        elapsed_us(started),
                        &mut total_encoded_frames,
                        &mut total_encoded_bytes,
                    )?;

                    let benchmark = encoder_benchmark
                        .as_mut()
                        .expect("submission-complete benchmark must exist");
                    benchmark
                        .finalize_missing(
                            classmesh_codec_win::mf_async::MfAsyncWaitConfig::default()
                                .drain_timeout,
                        )
                        .map_err(benchmark_accumulator_error)?;
                    let elapsed_seconds = benchmark_started
                        .expect("benchmark start is set with its pipeline")
                        .elapsed()
                        .as_secs_f32();
                    let mut result = summarize_benchmark(
                        &candidate,
                        Codec::H264,
                        benchmark.samples(),
                        elapsed_seconds,
                        BenchmarkCapabilities {
                            gpu_native_input: true,
                            low_latency_accepted,
                            reset_ok: false,
                            dynamic_bitrate_ok: false,
                            keyframe_request_ok: benchmark_keyframe_request_frame.is_some()
                                && benchmark_keyframe_observed,
                        },
                    )
                    .map_err(benchmark_summary_error)?;
                    result.class = class_for_actual_target(result.class, benchmark_profile);
                    let submitted = benchmark.submitted();
                    let cache_key = benchmark_cache_key(
                        &adapter_identity,
                        &candidate,
                        benchmark_profile,
                    )?;
                    pending_reset_benchmark = Some(PendingResetBenchmark {
                        result,
                        candidate,
                        profile: benchmark_profile,
                        cache_key,
                        submitted,
                        reset_submissions: 0,
                        reset_output_observed: false,
                    });
                    encoder_benchmark = None;
                    pipeline = None;
                    eprintln!(
                        "encoder benchmark baseline complete; recreating the same GPU encode pipeline for bounded reset evidence"
                    );
                    continue;
                }
            }
            CaptureStep::NoFrame => {}
            CaptureStep::RetryAfter { delay_ms, reason } => {
                eprintln!(
                    "DXGI recovery after {reason:?}; rebuilding media pipeline (delay={delay_ms} ms)"
                );
                pipeline = None;
                pending_keyframe_request = true;
                if let Some(pending) = pending_reset_benchmark.take() {
                    report_encoder_benchmark(pending, false);
                    benchmark_completed = true;
                    eprintln!(
                        "encoder benchmark reset/recreate evidence failed during DXGI recovery"
                    );
                } else if !benchmark_completed {
                    encoder_benchmark = benchmark_config
                        .map(BoundedEncoderBenchmark::from_config)
                        .transpose()
                        .map_err(benchmark_accumulator_error)?;
                    benchmark_started = None;
                    benchmark_non_keyframe_observed = false;
                    benchmark_keyframe_request_attempted = false;
                    benchmark_keyframe_request_pending = false;
                    benchmark_keyframe_request_frame = None;
                    benchmark_keyframe_observed = false;
                    eprintln!("encoder benchmark restarted after DXGI recovery");
                }
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
        if pending_reset_benchmark.is_some() {
            let tail = active.finish_with_metrics()?;
            let mut tail_frames = Vec::with_capacity(tail.len());
            for encoded_output in tail {
                if let Some(pending) = pending_reset_benchmark.as_mut() {
                    pending.reset_output_observed = true;
                }
                tail_frames.push(encoded_output.frame);
            }
            handle_encoded_frames(
                &tail_frames,
                output.as_mut(),
                udp_sender.as_mut(),
                elapsed_us(started),
                &mut total_encoded_frames,
                &mut total_encoded_bytes,
            )?;
            let pending = pending_reset_benchmark
                .take()
                .expect("pending reset benchmark exists");
            let reset_ok = pending.reset_output_observed;
            report_encoder_benchmark(pending, reset_ok);
            benchmark_completed = true;
        } else {
            let tail = active.finish()?;
            handle_encoded_frames(
                &tail,
                output.as_mut(),
                udp_sender.as_mut(),
                elapsed_us(started),
                &mut total_encoded_frames,
                &mut total_encoded_bytes,
            )?;
        }
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
    if encoder_benchmark_enabled && !benchmark_completed {
        return Err("encoder benchmark did not complete its configured sample target".into());
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Debug)]
struct PendingResetBenchmark {
    result: classmesh_codec_win::EncoderBenchmarkResult,
    candidate: classmesh_codec_win::EncoderCandidate,
    profile: classmesh_worker::presentation::PresentationProfile,
    cache_key: classmesh_codec_win::EncoderCapabilityCacheKey,
    submitted: usize,
    reset_submissions: usize,
    reset_output_observed: bool,
}

#[cfg(windows)]
fn same_benchmark_target(
    left: classmesh_worker::presentation::PresentationProfile,
    right: classmesh_worker::presentation::PresentationProfile,
) -> bool {
    left.target_width == right.target_width
        && left.target_height == right.target_height
        && left.fps == right.fps
        && left.bitrate_bps == right.bitrate_bps
}

#[cfg(windows)]
fn report_encoder_benchmark(mut pending: PendingResetBenchmark, reset_ok: bool) {
    pending.result.probe.reset_ok = reset_ok;
    pending.result.class =
        class_for_actual_target(pending.result.probe.classify(), pending.profile);
    eprintln!(
        "encoder benchmark: backend={} class={:?} target={}x{}@{} submitted={} outputs={} missing={} fps={:.2} p50_ms={:.2} p95_ms={:.2} low_latency={} keyframe_request={} reset={} reset_submissions={} dynamic_bitrate=false cache_adapter={} cache_driver={} cache_encoder={} cache_bitrate_bps={}",
        pending.result.probe.backend,
        pending.result.class,
        pending.profile.target_width,
        pending.profile.target_height,
        pending.profile.fps,
        pending.submitted,
        pending.result.output_frames,
        pending.result.dropped_or_missing,
        pending.result.probe.sustained_fps,
        pending.result.probe.p50_encode_ms,
        pending.result.probe.p95_encode_ms,
        pending.result.probe.low_latency_accepted,
        pending.result.probe.keyframe_request_ok,
        pending.result.probe.reset_ok,
        pending.reset_submissions,
        pending.cache_key.adapter_identity,
        pending.cache_key.driver_version,
        pending.cache_key.encoder_clsid,
        pending.cache_key.bitrate_bps,
    );
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
fn start_capture() -> Result<
    (
        ProbeCapture,
        classmesh_capture_win::AdapterCapabilityIdentity,
    ),
    Box<dyn std::error::Error>,
> {
    use classmesh_capture_win::{
        RecoveringCapture, enumerate_displays, query_adapter_capability_identity,
    };
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

    let adapter_identity =
        query_adapter_capability_identity(display.id).map_err(capture_error)?;
    eprintln!(
        "media probe adapter identity: {} driver={}",
        adapter_identity.adapter_identity(),
        adapter_identity.driver_version
    );

    let mut capture = RecoveringCapture::new(
        display.id,
        classmesh_capture_win::DxgiCaptureFactory,
        RecoveryPolicy::default(),
    );
    capture.start().map_err(capture_error)?;
    Ok((capture, adapter_identity))
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
fn benchmark_cache_key(
    adapter: &classmesh_capture_win::AdapterCapabilityIdentity,
    candidate: &classmesh_codec_win::EncoderCandidate,
    profile: classmesh_worker::presentation::PresentationProfile,
) -> Result<EncoderCapabilityCacheKey, Box<dyn std::error::Error>> {
    Ok(EncoderCapabilityCacheKey {
        adapter_identity: adapter.adapter_identity(),
        driver_version: adapter.driver_version.clone(),
        encoder_clsid: candidate.clsid.clone(),
        width: u16::try_from(profile.target_width)?,
        height: u16::try_from(profile.target_height)?,
        target_fps: u16::try_from(profile.fps)?,
        bitrate_bps: profile.bitrate_bps,
    })
}

#[cfg(windows)]
fn class_for_actual_target(
    class: classmesh_video::EncoderClass,
    profile: classmesh_worker::presentation::PresentationProfile,
) -> classmesh_video::EncoderClass {
    if profile.target_width < 1920 || profile.target_height < 1080 || profile.fps < 30 {
        return class.min(classmesh_video::EncoderClass::Compatibility);
    }
    if profile.fps < 60 {
        return class.min(classmesh_video::EncoderClass::Presentation1080p30);
    }
    class
}

#[cfg(windows)]
fn benchmark_accumulator_error(
    error: classmesh_codec_win::BenchmarkAccumulatorError,
) -> std::io::Error {
    std::io::Error::other(format!("encoder benchmark accumulation failed: {error:?}"))
}

#[cfg(windows)]
fn benchmark_summary_error(error: classmesh_codec_win::BenchmarkError) -> std::io::Error {
    std::io::Error::other(format!("encoder benchmark summary failed: {error:?}"))
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

#[cfg(all(test, windows))]
mod benchmark_policy_tests {
    use super::*;

    fn profile(
        width: u32,
        height: u32,
        fps: u32,
    ) -> classmesh_worker::presentation::PresentationProfile {
        classmesh_worker::presentation::PresentationProfile {
            source_width: width,
            source_height: height,
            target_width: width,
            target_height: height,
            fps,
            bitrate_bps: 2_500_000,
        }
    }

    #[test]
    fn benchmark_cache_key_binds_adapter_driver_encoder_and_profile() {
        let adapter = classmesh_capture_win::AdapterCapabilityIdentity {
            adapter_luid_low: 0x1122_3344,
            adapter_luid_high: 0x5566_7788,
            driver_version: "31.0.15.5123".into(),
        };
        let candidate = classmesh_codec_win::EncoderCandidate {
            name: "test".into(),
            clsid: "{encoder-clsid}".into(),
            vendor: classmesh_codec_win::EncoderVendor::Nvidia,
            advertised_hardware: true,
            advertised_async: true,
        };
        let key = benchmark_cache_key(&adapter, &candidate, profile(1280, 720, 30))
            .expect("synthetic cache key should build");
        assert_eq!(key.adapter_identity, "55667788:11223344");
        assert_eq!(key.driver_version, "31.0.15.5123");
        assert_eq!(key.encoder_clsid, "{encoder-clsid}");
        assert_eq!((key.width, key.height, key.target_fps), (1280, 720, 30));
        assert_eq!(key.bitrate_bps, 2_500_000);
    }

    #[test]
    fn lower_geometry_cannot_be_labeled_as_1080p() {
        assert_eq!(
            class_for_actual_target(
                classmesh_video::EncoderClass::Presentation1080p30,
                profile(1280, 720, 30),
            ),
            classmesh_video::EncoderClass::Compatibility
        );
    }

    #[test]
    fn recreated_lower_geometry_stays_capped_after_reset() {
        let profile = profile(1280, 720, 30);
        assert_eq!(
            class_for_actual_target(classmesh_video::EncoderClass::Presentation1080p60, profile,),
            classmesh_video::EncoderClass::Compatibility
        );
    }

    #[test]
    fn thirty_fps_target_cannot_be_labeled_as_1080p60() {
        assert_eq!(
            class_for_actual_target(
                classmesh_video::EncoderClass::Presentation1080p60,
                profile(1920, 1080, 30),
            ),
            classmesh_video::EncoderClass::Presentation1080p30
        );
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("classmesh-media-probe is supported only on Windows");
}
