//! In-process lifecycle + Service ingress composition only; NOT real IPC.
use std::time::{Duration, Instant};

use classmesh_control::receiver_telemetry::{
    ReceiverPlaybackCounters, ReceiverTelemetryBinding, ReceiverTelemetryDecision,
    ReceiverTelemetryError, ReceiverTelemetrySnapshot,
};
use classmesh_control::receiver_telemetry_ingress::ReceiverTelemetryIngressError;
use classmesh_control::receiver_telemetry_service_admission::{
    ReceiverTelemetryServiceAdmission, ReceiverTelemetryServiceAdmissionError,
};
use classmesh_control::receiver_telemetry_service_lifecycle::{
    ReceiverTelemetryCurrentWorker, ReceiverTelemetryServiceLifecycleError,
    ReceiverTelemetryStart, ReceiverTelemetryStartAck, ReceiverTelemetryStartAckStatus,
};
use classmesh_control::receiver_telemetry_transport::encode_receiver_telemetry;

fn pending() -> ReceiverTelemetryStart {
    ReceiverTelemetryStart {
        process_id: 501,
        session_id: 2,
        worker_generation: 12,
        control_session_id: 3,
        request_id: 4,
        presentation_id: 5,
        stream_id: 6,
        epoch: 7,
    }
}

fn peer() -> ReceiverTelemetryCurrentWorker {
    ReceiverTelemetryCurrentWorker {
        process_id: 501,
        session_id: 2,
        worker_generation: 12,
    }
}

fn acknowledged() -> ReceiverTelemetryStartAck {
    ReceiverTelemetryStartAck {
        process_id: 501,
        session_id: 2,
        control_session_id: 3,
        request_id: 4,
        presentation_id: 5,
        stream_id: 6,
        status: ReceiverTelemetryStartAckStatus::Started,
    }
}

fn report(binding: ReceiverTelemetryBinding, sequence: u64) -> Vec<u8> {
    encode_receiver_telemetry(&ReceiverTelemetrySnapshot {
        binding,
        sequence,
        counters: ReceiverPlaybackCounters {
            authenticated_frames: sequence + 5,
            rejected_frames: 0,
            decoded_frames: sequence + 3,
            presented_frames: sequence + 1,
            present_errors: 0,
            decode_errors: 0,
            keyframe_waits: 0,
            queue_drops: 0,
        },
    }).unwrap().to_vec()
}

#[test]
fn admission_is_closed_until_verified_start_then_bound_to_live_peer() {
    let at = Instant::now();
    let mut service = ReceiverTelemetryServiceAdmission::default();
    assert_eq!(
        service.observe_after_verified_peer(peer(), b"invalid", at),
        Err(ReceiverTelemetryServiceAdmissionError::NoActiveRuntime)
    );
    let owner = service.activate_after_correlated_reply(pending(), peer(), acknowledged()).unwrap();
    assert_eq!(owner.receiver_generation, 1);
    assert_eq!(service.current(), Some(owner));
    assert_eq!(
        service.observe_after_verified_peer(peer(), &report(owner, 1), at),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    assert!(matches!(
        service.observe_after_verified_peer(
            peer(), &report(owner, 2), at + Duration::from_secs(5)
        ),
        Ok(ReceiverTelemetryDecision::Interval(_))
    ));
    assert!(service.has_fresh_for_verified_peer(peer(), at + Duration::from_secs(5)));
}

#[test]
fn replacement_with_same_key_epoch_revokes_old_report_and_restarts_baseline() {
    let at = Instant::now();
    let mut service = ReceiverTelemetryServiceAdmission::default();
    let first = service.activate_after_correlated_reply(pending(), peer(), acknowledged()).unwrap();
    assert_eq!(
        service.observe_after_verified_peer(peer(), &report(first, 1), at),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    let second = service.activate_after_correlated_reply(pending(), peer(), acknowledged()).unwrap();
    assert_eq!(second.receiver_generation, first.receiver_generation + 1);
    assert_eq!(second.epoch, first.epoch);
    assert!(!service.clear_if_matches(first));
    assert_eq!(service.current(), Some(second));
    assert_eq!(
        service.observe_after_verified_peer(
            peer(), &report(first, 2), at + Duration::from_secs(1)
        ),
        Err(ReceiverTelemetryServiceAdmissionError::Ingress(
            ReceiverTelemetryIngressError::Admission(ReceiverTelemetryError::BindingMismatch)
        ))
    );
    assert_eq!(
        service.observe_after_verified_peer(
            peer(), &report(second, 1), at + Duration::from_secs(2)
        ),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    assert!(service.clear_if_matches(second));
    assert!(!service.has_fresh_for_verified_peer(peer(), at + Duration::from_secs(3)));
    assert_eq!(service.current(), None);
    assert_eq!(
        service.observe_after_verified_peer(
            peer(), &report(second, 2), at + Duration::from_secs(4)
        ),
        Err(ReceiverTelemetryServiceAdmissionError::NoActiveRuntime)
    );
    assert!(!service.clear_if_matches(second));
}

#[test]
fn wrong_live_os_peer_fails_before_decoding_and_cannot_spend_sequence() {
    let at = Instant::now();
    let mut service = ReceiverTelemetryServiceAdmission::default();
    let owner = service.activate_after_correlated_reply(pending(), peer(), acknowledged()).unwrap();
    for altered in 0..3 {
        let mut wrong = peer();
        match altered {
            0 => wrong.process_id += 1,
            1 => wrong.session_id += 1,
            2 => wrong.worker_generation += 1,
            _ => unreachable!(),
        }
        assert_eq!(
            service.observe_after_verified_peer(wrong, b"invalid wire", at),
            Err(ReceiverTelemetryServiceAdmissionError::WorkerMismatch)
        );
        assert!(!service.has_fresh_for_verified_peer(wrong, at));
    }
    assert_eq!(
        service.observe_after_verified_peer(peer(), &report(owner, 1), at),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
}

#[test]
fn rejected_or_stale_start_reply_cannot_revoke_existing_runtime() {
    let at = Instant::now();
    let mut service = ReceiverTelemetryServiceAdmission::default();
    let first = service.activate_after_correlated_reply(pending(), peer(), acknowledged()).unwrap();
    let mut rejected = acknowledged();
    rejected.status = ReceiverTelemetryStartAckStatus::Rejected;
    assert_eq!(
        service.activate_after_correlated_reply(pending(), peer(), rejected),
        Err(ReceiverTelemetryServiceLifecycleError::RejectedStart)
    );
    let mut wrong = acknowledged();
    wrong.request_id += 1;
    assert_eq!(
        service.activate_after_correlated_reply(pending(), peer(), wrong),
        Err(ReceiverTelemetryServiceLifecycleError::UncorrelatedStart)
    );
    assert_eq!(service.current(), Some(first));
    assert_eq!(
        service.observe_after_verified_peer(peer(), &report(first, 1), at),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    assert!(service.has_fresh_for_verified_peer(peer(), at));
}
