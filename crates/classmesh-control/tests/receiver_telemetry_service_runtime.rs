use std::time::{Duration, Instant};

use classmesh_control::receiver_telemetry::{
    ReceiverPlaybackCounters, ReceiverTelemetryBinding, ReceiverTelemetryDecision,
    ReceiverTelemetrySnapshot,
};
use classmesh_control::receiver_telemetry_service_lifecycle::{
    ReceiverTelemetryCurrentWorker, ReceiverTelemetryStart, ReceiverTelemetryStartAck,
    ReceiverTelemetryStartAckStatus,
};
use classmesh_control::receiver_telemetry_service_runtime::{
    ReceiverTelemetryAuthorizedKey, ReceiverTelemetryServiceRuntime,
    ReceiverTelemetryServiceRuntimeError,
};
use classmesh_control::receiver_telemetry_transport::encode_receiver_telemetry;

fn key() -> ReceiverTelemetryAuthorizedKey {
    ReceiverTelemetryAuthorizedKey {
        control_session_id: 50,
        key_grant_request_id: 60,
        presentation_id: 70,
        stream_id: 8,
        epoch: 9,
    }
}
fn peer() -> ReceiverTelemetryCurrentWorker {
    ReceiverTelemetryCurrentWorker {
        process_id: 501,
        session_id: 7,
        worker_generation: 4,
    }
}
fn requested() -> ReceiverTelemetryStart {
    ReceiverTelemetryStart {
        process_id: 501,
        session_id: 7,
        worker_generation: 4,
        control_session_id: 50,
        request_id: 61,
        presentation_id: 70,
        stream_id: 8,
        epoch: 9,
    }
}
fn ack() -> ReceiverTelemetryStartAck {
    ReceiverTelemetryStartAck {
        process_id: 501,
        session_id: 7,
        control_session_id: 50,
        request_id: 61,
        presentation_id: 70,
        stream_id: 8,
        status: ReceiverTelemetryStartAckStatus::Started,
    }
}
fn report(owner: ReceiverTelemetryBinding, seq: u64) -> Vec<u8> {
    encode_receiver_telemetry(&ReceiverTelemetrySnapshot {
        binding: owner,
        sequence: seq,
        counters: ReceiverPlaybackCounters {
            authenticated_frames: seq + 12,
            decoded_frames: seq + 6,
            presented_frames: seq + 3,
            ..ReceiverPlaybackCounters::default()
        },
    })
    .unwrap()
    .to_vec()
}

#[test]
fn no_authorized_key_means_successful_ack_cannot_start_report_admission() {
    let mut service = ReceiverTelemetryServiceRuntime::default();
    assert_eq!(
        service.activate_correlated_start(requested(), peer(), ack()),
        Err(ReceiverTelemetryServiceRuntimeError::KeyNotConfirmed)
    );
    assert!(service.current().is_none());
    assert_eq!(service.confirm_key_installed(key(), peer()), Ok(()));
    assert_eq!(
        service
            .activate_correlated_start(requested(), peer(), ack())
            .unwrap()
            .receiver_generation,
        1
    );
}

#[test]
fn different_worker_key_and_epoch_never_activate_even_with_matching_ack() {
    let mut service = ReceiverTelemetryServiceRuntime::default();
    service.confirm_key_installed(key(), peer()).unwrap();
    let mut changed = peer();
    changed.worker_generation += 1;
    assert_eq!(
        service.activate_correlated_start(requested(), changed, ack()),
        Err(ReceiverTelemetryServiceRuntimeError::KeyOwnerMismatch)
    );

    let mut changed = requested();
    changed.epoch += 1;
    assert_eq!(
        service.activate_correlated_start(changed, peer(), ack()),
        Err(ReceiverTelemetryServiceRuntimeError::KeyMismatch)
    );

    changed = requested();
    changed.stream_id += 1;
    assert_eq!(
        service.activate_correlated_start(changed, peer(), ack()),
        Err(ReceiverTelemetryServiceRuntimeError::KeyMismatch)
    );

    assert!(service.current().is_none());
    assert_eq!(
        service
            .activate_correlated_start(requested(), peer(), ack())
            .unwrap()
            .receiver_generation,
        1
    );
}

#[test]
fn revocation_is_exact_and_clears_both_runtime_and_replay_on_same_key_epoch_retry() {
    let at = Instant::now();
    let mut service = ReceiverTelemetryServiceRuntime::default();
    service.confirm_key_installed(key(), peer()).unwrap();
    let first = service
        .activate_correlated_start(requested(), peer(), ack())
        .unwrap();
    assert_eq!(
        service.observe_after_verified_peer(peer(), &report(first, 1), at),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
    let mut stale_grant = key();
    stale_grant.key_grant_request_id += 1;
    assert!(!service.revoke_matching_key(stale_grant));
    assert_eq!(service.current(), Some(first));
    assert!(service.revoke_matching_key(key()));
    assert!(service.current().is_none());
    assert!(!service.has_fresh_for_verified_peer(peer(), at));

    service.confirm_key_installed(key(), peer()).unwrap();
    let next = service
        .activate_correlated_start(requested(), peer(), ack())
        .unwrap();
    assert_eq!(next.epoch, first.epoch);
    assert_eq!(next.receiver_generation, first.receiver_generation + 1);
    assert_eq!(
        service.observe_after_verified_peer(peer(), &report(next, 1), at + Duration::from_secs(1)),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
}

#[test]
fn beginning_any_key_install_revokes_previous_admission_before_ack() {
    let at = Instant::now();
    let mut service = ReceiverTelemetryServiceRuntime::default();
    service.confirm_key_installed(key(), peer()).unwrap();
    let first = service
        .activate_correlated_start(requested(), peer(), ack())
        .unwrap();
    service
        .observe_after_verified_peer(peer(), &report(first, 1), at)
        .unwrap();

    service.key_install_started();
    assert!(service.current().is_none());
    assert!(!service.has_fresh_for_verified_peer(peer(), at));
    assert_eq!(
        service.activate_correlated_start(requested(), peer(), ack()),
        Err(ReceiverTelemetryServiceRuntimeError::KeyNotConfirmed)
    );
    let mut newer_key = key();
    newer_key.epoch += 1;
    service.confirm_key_installed(newer_key, peer()).unwrap();
    let mut next_start = requested();
    next_start.epoch += 1;
    let next = service
        .activate_correlated_start(next_start, peer(), ack())
        .unwrap();
    assert_eq!(next.receiver_generation, first.receiver_generation + 1);
}

#[test]
fn worker_exit_revokes_key_and_receiver_without_reusing_generation() {
    let at = Instant::now();
    let mut service = ReceiverTelemetryServiceRuntime::default();
    service.confirm_key_installed(key(), peer()).unwrap();
    let first = service
        .activate_correlated_start(requested(), peer(), ack())
        .unwrap();
    service
        .observe_after_verified_peer(peer(), &report(first, 1), at)
        .unwrap();
    service.worker_changed();
    assert!(service.current().is_none());
    assert!(!service.has_fresh_for_verified_peer(peer(), at));
    assert_eq!(
        service.activate_correlated_start(requested(), peer(), ack()),
        Err(ReceiverTelemetryServiceRuntimeError::KeyNotConfirmed)
    );
    let mut new_peer = peer();
    new_peer.process_id += 1;
    new_peer.worker_generation += 1;
    let mut new_start = requested();
    new_start.process_id += 1;
    new_start.worker_generation += 1;
    let mut new_ack = ack();
    new_ack.process_id += 1;
    service.confirm_key_installed(key(), new_peer).unwrap();
    let next = service
        .activate_correlated_start(new_start, new_peer, new_ack)
        .unwrap();
    assert_eq!(next.receiver_generation, first.receiver_generation + 1);
}
