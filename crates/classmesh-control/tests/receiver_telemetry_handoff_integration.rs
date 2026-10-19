//! Portable qualification of the passive, pre-IPC Worker -> Service seam.
//!
//! This models a separately authenticated Service owner by explicitly
//! activating its admission gate; encoded bytes must NEVER activate it.
//! It does not test a real privileged Windows pipe, attest a process token,
//! or authorize adaptive-quality promotion.
use std::time::{Duration, Instant};

use classmesh_control::receiver_telemetry::{
    ReceiverPlaybackCounters, ReceiverTelemetryBinding, ReceiverTelemetryDecision,
    ReceiverTelemetryError, ReceiverTelemetryInterval, ReceiverTelemetrySnapshot,
};
use classmesh_control::receiver_telemetry_ingress::{
    ReceiverTelemetryIngress, ReceiverTelemetryIngressError,
};
use classmesh_control::receiver_telemetry_transport::{
    RECEIVER_TELEMETRY_WIRE_LEN, ReceiverTelemetryConcurrentMailbox, ReceiverTelemetrySendLease,
    ReceiverTelemetryWireError, encode_receiver_telemetry,
};

fn binding(worker_generation: u64, receiver_generation: u64) -> ReceiverTelemetryBinding {
    ReceiverTelemetryBinding {
        process_id: 87,
        session_id: 21,
        worker_generation,
        control_session_id: 1001,
        request_id: 1002,
        presentation_id: 1003,
        stream_id: 2,
        epoch: 7,
        receiver_generation,
    }
}

fn report(
    identity: ReceiverTelemetryBinding,
    sequence: u64,
    decoded: u64,
) -> ReceiverTelemetrySnapshot {
    ReceiverTelemetrySnapshot {
        binding: identity,
        sequence,
        counters: ReceiverPlaybackCounters {
            authenticated_frames: decoded + 3,
            rejected_frames: 1,
            decoded_frames: decoded,
            presented_frames: decoded.saturating_sub(1),
            present_errors: 0,
            decode_errors: 0,
            keyframe_waits: 0,
            queue_drops: 2,
        },
    }
}

/// Only a stand-in for a dedicated sender. Real IPC must additionally
/// independently authenticate the peer and revalidate owner/runtime on arrival.
fn verify_and_encode(
    worker: &ReceiverTelemetryConcurrentMailbox,
    lease: &ReceiverTelemetrySendLease,
) -> Option<[u8; RECEIVER_TELEMETRY_WIRE_LEN]> {
    worker
        .try_lease_is_current(lease)
        .ok()
        .filter(|authorized| *authorized)
        .and_then(|_| encode_receiver_telemetry(&lease.snapshot()).ok())
}

#[test]
fn exact_verified_service_binding_distinguishes_auth_open_decode_and_present() {
    let now = Instant::now();
    let id = binding(4, 5);
    let worker = ReceiverTelemetryConcurrentMailbox::default();
    let mut service = ReceiverTelemetryIngress::default();
    worker.try_activate(id).unwrap();

    worker.try_offer(report(id, 1, 10)).unwrap();
    let first = worker.try_checkout_matching(id).unwrap().unwrap();
    let bytes = verify_and_encode(&worker, &first).unwrap();
    assert_eq!(
        service.observe_verified(&bytes, now),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::NoActiveBinding
        ))
    );
    assert!(!service.has_fresh_report(now));

    // The Service owner independently authenticated this exact Worker and
    // current receiver runtime; decoded bytes did not authorize themselves.
    service.activate_verified(id).unwrap();
    assert_eq!(
        service.observe_verified(&bytes, now),
        Ok(ReceiverTelemetryDecision::Baseline)
    );

    worker.try_offer(report(id, 2, 16)).unwrap();
    let second = worker.try_checkout_matching(id).unwrap().unwrap();
    let second_bytes = verify_and_encode(&worker, &second).unwrap();
    let decision = service
        .observe_verified(&second_bytes, now + Duration::from_secs(5))
        .unwrap();
    assert_eq!(
        decision,
        ReceiverTelemetryDecision::Interval(ReceiverTelemetryInterval {
            elapsed: Duration::from_secs(5),
            authenticated_frames: 6,
            rejected_frames: 0,
            decoded_frames: 6,
            presented_frames: 6,
            present_errors: 0,
            decode_errors: 0,
            keyframe_waits: 0,
            queue_drops: 0,
        })
    );
    // The 30s diagnostic liveness limit is not the 2s adaptive quality
    // sample TTL, nor a permission to synthesize network RTT or packet loss.
    assert!(service.has_fresh_report(now + Duration::from_secs(6)));
}

#[test]
fn backpressure_coalescing_causes_baseline_not_false_contiguous_interval() {
    let now = Instant::now();
    let id = binding(4, 5);
    let worker = ReceiverTelemetryConcurrentMailbox::default();
    let mut service = ReceiverTelemetryIngress::default();
    worker.try_activate(id).unwrap();
    service.activate_verified(id).unwrap();

    worker.try_offer(report(id, 1, 10)).unwrap();
    let baseline = worker.try_checkout_matching(id).unwrap().unwrap();
    let bytes = verify_and_encode(&worker, &baseline).unwrap();
    assert_eq!(
        service.observe_verified(&bytes, now),
        Ok(ReceiverTelemetryDecision::Baseline)
    );

    // One slot, no unbounded backlog and no catch-up burst on slow IPC.
    for sequence in 2..=4_000 {
        worker
            .try_offer(report(id, sequence, 10 + sequence))
            .unwrap();
    }
    let latest = worker.try_checkout_matching(id).unwrap().unwrap();
    assert_eq!(latest.snapshot().sequence, 4_000);
    let bytes = verify_and_encode(&worker, &latest).unwrap();
    assert_eq!(
        service.observe_verified(&bytes, now + Duration::from_secs(5)),
        Ok(ReceiverTelemetryDecision::Baseline)
    );

    worker.try_offer(report(id, 4_001, 4_011)).unwrap();
    let continuation = worker.try_checkout_matching(id).unwrap().unwrap();
    let bytes = verify_and_encode(&worker, &continuation).unwrap();
    assert!(matches!(
        service.observe_verified(&bytes, now + Duration::from_secs(10)),
        Ok(ReceiverTelemetryDecision::Interval(_))
    ));
}

#[test]
fn revoked_old_worker_lease_and_late_wire_cannot_cross_service_generation() {
    let now = Instant::now();
    let old = binding(4, 5);
    let new = binding(5, 6);
    let worker = ReceiverTelemetryConcurrentMailbox::default();
    let mut service = ReceiverTelemetryIngress::default();
    worker.try_activate(old).unwrap();
    service.activate_verified(old).unwrap();

    worker.try_offer(report(old, 1, 10)).unwrap();
    let checked_out = worker.try_checkout_matching(old).unwrap().unwrap();
    let already_encoded = verify_and_encode(&worker, &checked_out).unwrap();

    assert_eq!(worker.try_clear_if_matches(old), Ok(true));
    worker.try_activate(new).unwrap();
    service.activate_verified(new).unwrap();
    assert!(verify_and_encode(&worker, &checked_out).is_none());
    // Even if a byte array was copied before the revocation, the separately
    // owned Service generation rejects it on arrival.
    assert_eq!(
        service.observe_verified(&already_encoded, now + Duration::from_secs(1)),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::BindingMismatch
        ))
    );
    assert!(!service.clear_if_matches(old));

    worker.try_offer(report(new, 1, 1)).unwrap();
    let fresh = worker.try_checkout_matching(new).unwrap().unwrap();
    let bytes = verify_and_encode(&worker, &fresh).unwrap();
    assert_eq!(
        service.observe_verified(&bytes, now + Duration::from_secs(2)),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
}

#[test]
fn service_revocation_rejects_in_flight_bytes_even_if_sender_lease_still_valid() {
    let now = Instant::now();
    let id = binding(4, 5);
    let worker = ReceiverTelemetryConcurrentMailbox::default();
    let mut service = ReceiverTelemetryIngress::default();
    worker.try_activate(id).unwrap();
    service.activate_verified(id).unwrap();

    worker.try_offer(report(id, 1, 10)).unwrap();
    let lease = worker.try_checkout_matching(id).unwrap().unwrap();
    let bytes = verify_and_encode(&worker, &lease).unwrap();
    // The Service revoked the protected Worker while the notification that
    // would clear the Worker-local mailbox has not arrived.
    assert!(service.clear_if_matches(id));
    assert_eq!(worker.try_lease_is_current(&lease), Ok(true));
    assert_eq!(
        service.observe_verified(&bytes, now),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::NoActiveBinding
        ))
    );
    // The Service's revoked state cannot be refreshed by the old report.
    assert!(!service.has_fresh_report(now));
}

#[test]
fn invalid_wire_does_not_consume_verified_service_sequence() {
    let now = Instant::now();
    let id = binding(4, 5);
    let worker = ReceiverTelemetryConcurrentMailbox::default();
    let mut service = ReceiverTelemetryIngress::default();
    worker.try_activate(id).unwrap();
    service.activate_verified(id).unwrap();
    worker.try_offer(report(id, 1, 10)).unwrap();
    let lease = worker.try_checkout_matching(id).unwrap().unwrap();
    let good = verify_and_encode(&worker, &lease).unwrap();

    let mut tampered = good;
    tampered[0] ^= 0xFF;
    assert_eq!(
        service.observe_verified(&tampered, now),
        Err(ReceiverTelemetryIngressError::Wire(
            ReceiverTelemetryWireError::BadMagic
        ))
    );
    assert_eq!(
        service.observe_verified(&good, now),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    assert_eq!(
        service.observe_verified(&good, now + Duration::from_secs(5)),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::Replay
        ))
    );
}

#[test]
fn independent_receiver_sessions_never_share_consumer_state() {
    let now = Instant::now();
    let first = binding(4, 5);
    let second = binding(4, 6);
    let a = ReceiverTelemetryConcurrentMailbox::default();
    let b = ReceiverTelemetryConcurrentMailbox::default();
    let mut admission_a = ReceiverTelemetryIngress::default();
    let mut admission_b = ReceiverTelemetryIngress::default();
    a.try_activate(first).unwrap();
    b.try_activate(second).unwrap();
    admission_a.activate_verified(first).unwrap();
    admission_b.activate_verified(second).unwrap();

    a.try_offer(report(first, 1, 10)).unwrap();
    b.try_offer(report(second, 1, 20)).unwrap();
    let a_lease = a.try_checkout_matching(first).unwrap().unwrap();
    let b_lease = b.try_checkout_matching(second).unwrap().unwrap();
    assert!(verify_and_encode(&b, &a_lease).is_none());
    let a_bytes = verify_and_encode(&a, &a_lease).unwrap();
    let b_bytes = verify_and_encode(&b, &b_lease).unwrap();

    assert_eq!(
        admission_b.observe_verified(&a_bytes, now),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::BindingMismatch
        ))
    );
    assert_eq!(
        admission_a.observe_verified(&a_bytes, now),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    assert_eq!(
        admission_b.observe_verified(&b_bytes, now),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
}

#[test]
fn diagnostic_liveness_boundary_never_authorizes_adaptive_freshness() {
    use classmesh_core::receiver_quality::ReceiverQualityPolicy;

    let now = Instant::now();
    let id = binding(4, 5);
    let mut service = ReceiverTelemetryIngress::default();
    service.activate_verified(id).unwrap();
    let first = encode_receiver_telemetry(&report(id, 1, 10)).unwrap();
    assert_eq!(
        service.observe_verified(&first, now),
        Ok(ReceiverTelemetryDecision::Baseline)
    );

    let adaptive_ttl = Duration::from_micros(ReceiverQualityPolicy::default().max_sample_age_us);
    assert_eq!(adaptive_ttl, Duration::from_secs(2));
    assert!(
        service.has_fresh_report(now + Duration::from_secs(5)),
        "diagnostic liveness is deliberately longer than adaptive sample TTL"
    );
    assert!(service.has_fresh_report(now + Duration::from_secs(30)));
    assert!(!service.has_fresh_report(now + Duration::from_secs(30) + Duration::from_millis(1)));

    // Replaying old bytes cannot extend the diagnostic liveness window.
    assert_eq!(
        service.observe_verified(&first, now + Duration::from_secs(31)),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::Replay
        ))
    );
    assert!(!service.has_fresh_report(now + Duration::from_secs(31)));

    // A legitimate new sequence after a long pause is only a baseline,
    // not an interval eligible to fabricate adaptive-quality recovery.
    let next = encode_receiver_telemetry(&report(id, 2, 16)).unwrap();
    assert_eq!(
        service.observe_verified(&next, now + Duration::from_secs(31)),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    assert!(service.has_fresh_report(now + Duration::from_secs(31)));
}

#[test]
fn service_binding_reactivation_does_not_erase_replay_protection() {
    let now = Instant::now();
    let id = binding(4, 5);
    let mut service = ReceiverTelemetryIngress::default();
    service.activate_verified(id).unwrap();
    let first = encode_receiver_telemetry(&report(id, 1, 10)).unwrap();
    assert_eq!(
        service.observe_verified(&first, now),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    // A redundant owner refresh is not a new Worker generation.
    service.activate_verified(id).unwrap();
    assert_eq!(
        service.observe_verified(&first, now + Duration::from_secs(5)),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::Replay
        ))
    );
    assert!(service.clear_if_matches(id));
    assert!(!service.has_fresh_report(now + Duration::from_secs(5)));
    assert_eq!(
        service.observe_verified(&first, now + Duration::from_secs(10)),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::NoActiveBinding
        ))
    );
}
