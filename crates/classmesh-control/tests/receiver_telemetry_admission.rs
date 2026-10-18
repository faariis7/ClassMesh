use std::time::{Duration, Instant};

use classmesh_control::receiver_telemetry::{
    ReceiverPlaybackCounters, ReceiverTelemetryBinding, ReceiverTelemetryDecision,
    ReceiverTelemetryError, ReceiverTelemetryGate, ReceiverTelemetrySnapshot,
};

fn binding(epoch: u32) -> ReceiverTelemetryBinding {
    ReceiverTelemetryBinding {
        process_id: 101,
        session_id: 22,
        worker_generation: 3,
        control_session_id: 4,
        request_id: 5,
        presentation_id: 6,
        stream_id: 7,
        epoch,
        receiver_generation: 8,
    }
}

fn sample(binding: ReceiverTelemetryBinding, sequence: u64, frames: u64) -> ReceiverTelemetrySnapshot {
    ReceiverTelemetrySnapshot {
        binding,
        sequence,
        counters: ReceiverPlaybackCounters {
            authenticated_frames: frames,
            rejected_frames: 1,
            decoded_frames: frames.saturating_sub(1),
            presented_frames: frames.saturating_sub(2),
            present_errors: 0,
            decode_errors: 0,
            keyframe_waits: 0,
            queue_drops: 0,
        },
    }
}

#[test]
fn only_a_service_activated_exact_binding_is_admitted() {
    let mut gate = ReceiverTelemetryGate::default();
    let now = Instant::now();
    assert_eq!(gate.observe(sample(binding(1), 1, 10), now), Err(ReceiverTelemetryError::NoActiveBinding));
    gate.activate(binding(1)).unwrap();
    let mut wrong = binding(1);
    wrong.control_session_id += 1;
    assert_eq!(gate.observe(sample(wrong, 1, 10), now), Err(ReceiverTelemetryError::BindingMismatch));
    wrong = binding(1);
    wrong.receiver_generation += 1;
    assert_eq!(gate.observe(sample(wrong, 1, 10), now), Err(ReceiverTelemetryError::BindingMismatch));
    assert_eq!(gate.observe(sample(binding(1), 1, 10), now), Ok(ReceiverTelemetryDecision::Baseline));
}

#[test]
fn contiguous_reports_produce_separate_verified_decode_and_present_deltas() {
    let mut gate = ReceiverTelemetryGate::default();
    gate.activate(binding(1)).unwrap();
    let now = Instant::now();
    gate.observe(sample(binding(1), 1, 10), now).unwrap();
    let mut report = sample(binding(1), 2, 16);
    report.counters.presented_frames = 11;
    report.counters.decode_errors = 2;
    let result = gate.observe(report, now + Duration::from_secs(5)).unwrap();
    let ReceiverTelemetryDecision::Interval(interval) = result else { panic!("expected contiguous interval"); };
    assert_eq!(interval.elapsed, Duration::from_secs(5));
    assert_eq!(interval.authenticated_frames, 6);
    assert_eq!(interval.decoded_frames, 6);
    assert_eq!(interval.presented_frames, 3);
    assert_eq!(interval.decode_errors, 2);
    assert_eq!(interval.rejected_frames, 0);
    // There is intentionally no synthetic packet-loss rate or RTT in this interval.
}

#[test]
fn rejected_replay_and_clock_regression_do_not_advance_sequence() {
    let mut gate = ReceiverTelemetryGate::default();
    gate.activate(binding(1)).unwrap();
    let now = Instant::now();
    gate.observe(sample(binding(1), 1, 10), now).unwrap();
    assert_eq!(gate.observe(sample(binding(1), 1, 12), now + Duration::from_secs(5)), Err(ReceiverTelemetryError::Replay));
    assert_eq!(gate.observe(sample(binding(1), 2, 12), now - Duration::from_secs(1)), Err(ReceiverTelemetryError::ClockRegression));
    assert!(matches!(gate.observe(sample(binding(1), 2, 12), now + Duration::from_secs(5)), Ok(ReceiverTelemetryDecision::Interval(_))));
}

#[test]
fn counters_cannot_regress_and_invalid_metrics_do_not_mutate_state() {
    let mut gate = ReceiverTelemetryGate::default();
    gate.activate(binding(1)).unwrap();
    let now = Instant::now();
    gate.observe(sample(binding(1), 1, 10), now).unwrap();
    let mut bad = sample(binding(1), 2, 11);
    bad.counters.rejected_frames = 0;
    assert_eq!(gate.observe(bad, now + Duration::from_secs(5)), Err(ReceiverTelemetryError::CounterRegression));
    assert!(matches!(gate.observe(sample(binding(1), 2, 12), now + Duration::from_secs(5)), Ok(ReceiverTelemetryDecision::Interval(_))));
}

#[test]
fn gaps_and_expired_reports_are_baselines_not_false_healthy_intervals() {
    let mut gate = ReceiverTelemetryGate::default();
    gate.activate(binding(1)).unwrap();
    let now = Instant::now();
    gate.observe(sample(binding(1), 1, 10), now).unwrap();
    assert_eq!(gate.observe(sample(binding(1), 3, 30), now + Duration::from_secs(5)), Ok(ReceiverTelemetryDecision::Baseline));
    assert!(matches!(gate.observe(sample(binding(1), 4, 34), now + Duration::from_secs(10)), Ok(ReceiverTelemetryDecision::Interval(_))));
    assert_eq!(gate.observe(sample(binding(1), 5, 100), now + Duration::from_secs(45)), Ok(ReceiverTelemetryDecision::Baseline));
    assert!(matches!(gate.observe(sample(binding(1), 6, 104), now + Duration::from_secs(50)), Ok(ReceiverTelemetryDecision::Interval(_))));
}

#[test]
fn too_frequent_reports_do_not_count_toward_adaptation() {
    let mut gate = ReceiverTelemetryGate::default();
    gate.activate(binding(1)).unwrap();
    let now = Instant::now();
    gate.observe(sample(binding(1), 1, 10), now).unwrap();
    assert_eq!(gate.observe(sample(binding(1), 2, 11), now + Duration::from_millis(100)), Err(ReceiverTelemetryError::TooFrequent));
    assert!(matches!(gate.observe(sample(binding(1), 2, 12), now + Duration::from_secs(5)), Ok(ReceiverTelemetryDecision::Interval(_))));
}

#[test]
fn identical_activation_must_not_rearm_replays_but_exact_revocation_does() {
    let mut gate = ReceiverTelemetryGate::default();
    let now = Instant::now();
    gate.activate(binding(1)).unwrap();
    gate.observe(sample(binding(1), 1, 10), now).unwrap();
    gate.activate(binding(1)).unwrap();
    assert_eq!(gate.observe(sample(binding(1), 1, 10), now + Duration::from_secs(5)), Err(ReceiverTelemetryError::Replay));
    assert!(!gate.clear_if_matches(binding(2)));
    assert!(gate.clear_if_matches(binding(1)));
    assert_eq!(gate.observe(sample(binding(1), 2, 12), now + Duration::from_secs(5)), Err(ReceiverTelemetryError::NoActiveBinding));
    gate.activate(binding(2)).unwrap();
    assert_eq!(gate.observe(sample(binding(2), 1, 2), now + Duration::from_secs(5)), Ok(ReceiverTelemetryDecision::Baseline));
}

#[test]
fn invalid_identity_or_sequence_fail_closed() {
    let mut gate = ReceiverTelemetryGate::default();
    let mut wrong = binding(1);
    wrong.worker_generation = 0;
    assert_eq!(gate.activate(wrong), Err(ReceiverTelemetryError::InvalidBinding));
    gate.activate(binding(1)).unwrap();
    assert_eq!(gate.observe(sample(binding(1), 0, 10), Instant::now()), Err(ReceiverTelemetryError::InvalidSequence));
}
