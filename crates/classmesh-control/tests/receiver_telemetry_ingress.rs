use std::time::{Duration, Instant};

use classmesh_control::receiver_telemetry::{
    ReceiverPlaybackCounters, ReceiverTelemetryBinding, ReceiverTelemetryDecision,
    ReceiverTelemetryError, ReceiverTelemetrySnapshot,
};
use classmesh_control::receiver_telemetry_ingress::{
    ReceiverTelemetryIngress, ReceiverTelemetryIngressError,
};
use classmesh_control::receiver_telemetry_transport::{
    ReceiverTelemetryWireError, encode_receiver_telemetry,
};

fn binding(epoch: u32) -> ReceiverTelemetryBinding {
    ReceiverTelemetryBinding {
        process_id: 123,
        session_id: 2,
        worker_generation: 4,
        control_session_id: 5,
        request_id: 6,
        presentation_id: 7,
        stream_id: 8,
        epoch,
        receiver_generation: 9,
    }
}

fn frame(binding: ReceiverTelemetryBinding, sequence: u64, decoded: u64) -> [u8; 136] {
    encode_receiver_telemetry(&ReceiverTelemetrySnapshot {
        binding,
        sequence,
        counters: ReceiverPlaybackCounters {
            decoded_frames: decoded,
            ..ReceiverPlaybackCounters::default()
        },
    })
    .unwrap()
}

#[test]
fn bytes_cannot_self_activate_without_service_authority() {
    let now = Instant::now();
    let mut ingress = ReceiverTelemetryIngress::default();
    assert_eq!(
        ingress.observe_verified(&frame(binding(1), 1, 2), now),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::NoActiveBinding
        ))
    );
    assert!(!ingress.has_fresh_report(now));
}

#[test]
fn invalid_wire_and_wrong_epoch_do_not_poison_authorized_continuity() {
    let now = Instant::now();
    let mut ingress = ReceiverTelemetryIngress::default();
    ingress.activate_verified(binding(1)).unwrap();
    let mut malformed = frame(binding(1), 1, 1);
    malformed[0] = b'X';
    assert_eq!(
        ingress.observe_verified(&malformed, now),
        Err(ReceiverTelemetryIngressError::Wire(
            ReceiverTelemetryWireError::BadMagic
        ))
    );
    assert_eq!(
        ingress.observe_verified(&frame(binding(2), 1, 1), now),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::BindingMismatch
        ))
    );
    assert_eq!(
        ingress.observe_verified(&frame(binding(1), 1, 1), now),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    assert_eq!(
        ingress.observe_verified(&frame(binding(1), 1, 2), now + Duration::from_secs(1)),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::Replay
        ))
    );
    let accepted = ingress
        .observe_verified(&frame(binding(1), 2, 3), now + Duration::from_secs(2))
        .unwrap();
    let ReceiverTelemetryDecision::Interval(interval) = accepted else {
        panic!("contiguous verified frame must yield a measurement");
    };
    assert_eq!(interval.decoded_frames, 2);
    assert!(ingress.has_fresh_report(now + Duration::from_secs(2)));
}

#[test]
fn stale_revocation_cannot_remove_replacement_and_exact_revocation_clears() {
    let now = Instant::now();
    let mut ingress = ReceiverTelemetryIngress::default();
    ingress.activate_verified(binding(1)).unwrap();
    ingress
        .observe_verified(&frame(binding(1), 1, 1), now)
        .unwrap();
    ingress.activate_verified(binding(2)).unwrap();
    assert!(!ingress.clear_if_matches(binding(1)));
    assert_eq!(
        ingress.observe_verified(&frame(binding(2), 1, 4), now + Duration::from_secs(1)),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    assert!(ingress.clear_if_matches(binding(2)));
    assert!(!ingress.has_fresh_report(now + Duration::from_secs(1)));
    assert_eq!(
        ingress.observe_verified(&frame(binding(2), 2, 5), now + Duration::from_secs(2)),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::NoActiveBinding
        ))
    );
}

#[test]
fn service_live_owner_mismatch_rejects_old_valid_bytes_without_advancing_state() {
    let now = Instant::now();
    let old = binding(1);
    let next = binding(2);
    let mut ingress = ReceiverTelemetryIngress::default();
    ingress.activate_verified(old).unwrap();
    let first = frame(old, 1, 2);
    assert_eq!(
        ingress.observe_for_current_owner(old, &first, now),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    // The independently verified active Worker changed, but the old gate has
    // not received teardown/replacement notification. Bytes alone must not
    // retain the old owner, even when they exactly match the stale gate.
    assert_eq!(
        ingress.observe_for_current_owner(next, &frame(old, 2, 3), now + Duration::from_secs(1)),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::BindingMismatch
        ))
    );
    assert_eq!(ingress.has_fresh_for_current_owner(next, now), false);
    // The rejected attempt cannot spend old owner's monotonic sequence.
    assert!(matches!(
        ingress.observe_for_current_owner(old, &frame(old, 2, 3), now + Duration::from_secs(2)),
        Ok(ReceiverTelemetryDecision::Interval(_))
    ));
    ingress.activate_verified(next).unwrap();
    assert_eq!(
        ingress.observe_for_current_owner(old, &frame(old, 3, 4), now + Duration::from_secs(3)),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::BindingMismatch
        ))
    );
    assert_eq!(
        ingress.observe_for_current_owner(next, &frame(next, 1, 1), now + Duration::from_secs(4)),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    assert_eq!(ingress.has_fresh_for_current_owner(next, now + Duration::from_secs(4)), true);
    assert_eq!(ingress.has_fresh_for_current_owner(old, now + Duration::from_secs(4)), false);
}

#[test]
fn service_live_owner_validation_precedes_parsing_or_liveness() {
    let now = Instant::now();
    let old = binding(1);
    let next = binding(2);
    let mut ingress = ReceiverTelemetryIngress::default();
    let good = frame(old, 1, 2);
    assert_eq!(
        ingress.observe_for_current_owner(old, &good, now),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::NoActiveBinding
        ))
    );
    ingress.activate_verified(old).unwrap();
    let mut invalid_owner = old;
    invalid_owner.worker_generation = 0;
    assert_eq!(
        ingress.observe_for_current_owner(invalid_owner, &good, now),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::InvalidBinding
        ))
    );
    assert_eq!(ingress.has_fresh_for_current_owner(invalid_owner, now), false);
    // An old or malformed payload must not be even decoded if the live owner
    // differs from this gate. Its provenance is Service-owned, not in bytes.
    assert_eq!(
        ingress.observe_for_current_owner(next, b"bad wire", now),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::BindingMismatch
        ))
    );
    assert_eq!(ingress.observe_for_current_owner(old, &good, now), Ok(ReceiverTelemetryDecision::Baseline));
    assert_eq!(
        ingress.observe_for_current_owner(old, &good, now + Duration::from_secs(1)),
        Err(ReceiverTelemetryIngressError::Admission(ReceiverTelemetryError::Replay))
    );
}
