use classmesh_control::receiver_telemetry::ReceiverTelemetryBinding;
use classmesh_control::receiver_telemetry_service_lifecycle::{
    ReceiverTelemetryServiceLifecycle, ReceiverTelemetryServiceLifecycleError,
    ReceiverTelemetryStart,
};

fn started() -> ReceiverTelemetryStart {
    ReceiverTelemetryStart {
        process_id: 501,
        session_id: 3,
        worker_generation: 7,
        control_session_id: 11,
        request_id: 13,
        presentation_id: 17,
        stream_id: 19,
        epoch: 23,
    }
}

#[test]
fn service_allocates_new_runtime_generation_not_supplied_by_worker() {
    let mut service = ReceiverTelemetryServiceLifecycle::default();
    assert!(service.current().is_none());
    let first = service.activate_after_verified_start(started()).unwrap();
    assert_eq!(first.receiver_generation, 1);
    assert_eq!(first.process_id, 501);
    assert_eq!(first.worker_generation, 7);
    assert_eq!(first.epoch, 23);
    assert_eq!(service.current(), Some(first));
    let second = service.activate_after_verified_start(started()).unwrap();
    assert_eq!(second.receiver_generation, 2);
    assert_ne!(first, second);
    assert!(!service.clear_if_matches(first));
    assert_eq!(service.current(), Some(second));
    assert!(service.clear_if_matches(second));
    assert_eq!(service.current(), None);
    let third = service.activate_after_verified_start(started()).unwrap();
    assert_eq!(third.receiver_generation, 3);
}

#[test]
fn invalid_worker_or_presentation_identity_must_not_spend_generation() {
    let mut service = ReceiverTelemetryServiceLifecycle::default();
    let original = started();
    let invalid_fields = [
        ReceiverTelemetryStart {
            process_id: 0,
            ..original
        },
        ReceiverTelemetryStart {
            session_id: 0,
            ..original
        },
        ReceiverTelemetryStart {
            worker_generation: 0,
            ..original
        },
        ReceiverTelemetryStart {
            control_session_id: 0,
            ..original
        },
        ReceiverTelemetryStart {
            request_id: 0,
            ..original
        },
        ReceiverTelemetryStart {
            presentation_id: 0,
            ..original
        },
        ReceiverTelemetryStart {
            stream_id: 0,
            ..original
        },
        ReceiverTelemetryStart {
            epoch: 0,
            ..original
        },
    ];
    for candidate in invalid_fields {
        assert_eq!(
            service.activate_after_verified_start(candidate),
            Err(ReceiverTelemetryServiceLifecycleError::InvalidBinding)
        );
        assert_eq!(service.current(), None);
    }
    assert_eq!(
        service
            .activate_after_verified_start(original)
            .unwrap()
            .receiver_generation,
        1
    );
}

#[test]
fn service_refuses_stale_worker_and_exact_teardown_cannot_revoke_successor() {
    let mut service = ReceiverTelemetryServiceLifecycle::default();
    let first = service.activate_after_verified_start(started()).unwrap();
    let mut restarted = started();
    restarted.worker_generation += 1;
    restarted.process_id += 1;
    let second = service.activate_after_verified_start(restarted).unwrap();
    assert_eq!(second.receiver_generation, 2);
    assert!(!service.clear_if_matches(first));
    assert!(!service.is_current_after_verified_peer(first));
    assert!(service.is_current_after_verified_peer(second));
    assert_eq!(service.current(), Some(second));
    assert!(service.clear_if_matches(second));
    assert!(!service.is_current_after_verified_peer(second));
}

#[test]
fn owner_binding_has_no_untrusted_generation_field_in_start_contract() {
    let mut service = ReceiverTelemetryServiceLifecycle::default();
    let active: ReceiverTelemetryBinding =
        service.activate_after_verified_start(started()).unwrap();
    assert!(active.is_valid());
    let mut forged = active;
    forged.receiver_generation += 1;
    assert!(!service.is_current_after_verified_peer(forged));
    assert!(!service.clear_if_matches(forged));
    assert!(service.is_current_after_verified_peer(active));
}

#[test]
fn service_owned_runtime_replacement_invalidates_old_bytes_without_reusing_key_epoch() {
    use classmesh_control::receiver_telemetry::{
        ReceiverPlaybackCounters, ReceiverTelemetryDecision, ReceiverTelemetryError,
        ReceiverTelemetrySnapshot,
    };
    use classmesh_control::receiver_telemetry_ingress::{
        ReceiverTelemetryIngress, ReceiverTelemetryIngressError,
    };
    use classmesh_control::receiver_telemetry_transport::encode_receiver_telemetry;
    use std::time::{Duration, Instant};

    let at = Instant::now();
    let mut service = ReceiverTelemetryServiceLifecycle::default();
    let mut ingress = ReceiverTelemetryIngress::default();
    let old = service.activate_after_verified_start(started()).unwrap();
    ingress.activate_verified(old).unwrap();
    let sample = |binding, sequence| ReceiverTelemetrySnapshot {
        binding,
        sequence,
        counters: ReceiverPlaybackCounters {
            authenticated_frames: sequence + 3,
            rejected_frames: 1,
            decoded_frames: sequence,
            presented_frames: sequence,
            present_errors: 0,
            decode_errors: 0,
            keyframe_waits: 0,
            queue_drops: 0,
        },
    };
    let first = encode_receiver_telemetry(&sample(old, 1)).unwrap();
    assert_eq!(
        ingress.observe_for_current_owner(old, &first, at),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    // The same key epoch may be installed on a REPLACED runtime. Worker
    // report sequence can restart from 1; only the Service ledger generates
    // a new lifetime and can decide which reports belong to it.
    let next = service.activate_after_verified_start(started()).unwrap();
    assert_eq!(next.epoch, old.epoch);
    assert_eq!(next.receiver_generation, old.receiver_generation + 1);
    assert!(!service.is_current_after_verified_peer(old));
    assert!(!service.clear_if_matches(old));
    assert_eq!(
        ingress.observe_for_current_owner(
            next,
            &encode_receiver_telemetry(&sample(old, 2)).unwrap(),
            at + Duration::from_secs(1)
        ),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::BindingMismatch
        ))
    );
    // Gate notification may be delayed. The sender cannot force this gate
    // to accept a successor without explicit Service activation.
    assert_eq!(
        ingress.observe_for_current_owner(
            next,
            &encode_receiver_telemetry(&sample(next, 1)).unwrap(),
            at + Duration::from_secs(2)
        ),
        Err(ReceiverTelemetryIngressError::Admission(
            ReceiverTelemetryError::BindingMismatch
        ))
    );
    ingress.activate_verified(next).unwrap();
    assert_eq!(
        ingress.observe_for_current_owner(
            next,
            &encode_receiver_telemetry(&sample(next, 1)).unwrap(),
            at + Duration::from_secs(3)
        ),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    assert!(service.clear_if_matches(next));
    assert!(service.current().is_none());
    assert!(!service.is_current_after_verified_peer(next));
}
