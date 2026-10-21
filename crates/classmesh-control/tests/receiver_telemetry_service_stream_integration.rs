//! Passive Service-owned telemetry stream reassembly + admission qualification.
//! A real Worker pipe must still independently attest the live OS peer and
//! serialize these calls with Service key/start/revocation lifecycle.
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
    ReceiverTelemetryServiceStreamError,
};
use classmesh_control::receiver_telemetry_stream_framing::ReceiverTelemetryFrameStreamError;
use classmesh_control::receiver_telemetry_transport::{
    RECEIVER_TELEMETRY_WIRE_LEN, ReceiverTelemetryWireError, encode_receiver_telemetry,
};
use std::time::{Duration, Instant};

fn peer() -> ReceiverTelemetryCurrentWorker {
    ReceiverTelemetryCurrentWorker {
        process_id: 501,
        session_id: 7,
        worker_generation: 4,
    }
}
fn key() -> ReceiverTelemetryAuthorizedKey {
    ReceiverTelemetryAuthorizedKey {
        control_session_id: 50,
        key_grant_request_id: 60,
        presentation_id: 70,
        stream_id: 8,
        epoch: 9,
    }
}
fn start() -> ReceiverTelemetryStart {
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
fn armed() -> (ReceiverTelemetryServiceRuntime, ReceiverTelemetryBinding) {
    let mut s = ReceiverTelemetryServiceRuntime::default();
    s.confirm_key_installed(key(), peer()).unwrap();
    let binding = s.activate_correlated_start(start(), peer(), ack()).unwrap();
    (s, binding)
}
fn report(binding: ReceiverTelemetryBinding, sequence: u64) -> [u8; RECEIVER_TELEMETRY_WIRE_LEN] {
    encode_receiver_telemetry(&ReceiverTelemetrySnapshot {
        binding,
        sequence,
        counters: ReceiverPlaybackCounters {
            authenticated_frames: sequence + 10,
            decoded_frames: sequence + 5,
            presented_frames: sequence,
            ..Default::default()
        },
    })
    .unwrap()
}

#[test]
fn fragmented_bytes_do_not_create_fresh_service_sample_until_complete() {
    let (mut service, owner) = armed();
    let at = Instant::now();
    let bytes = report(owner, 1);
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[..41], at),
        Ok(None)
    );
    assert!(!service.has_fresh_for_verified_peer(peer(), at));
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[41..], at),
        Ok(Some(ReceiverTelemetryDecision::Baseline))
    );
    assert!(service.has_fresh_for_verified_peer(peer(), at));
}

#[test]
fn coalesced_reports_admit_latest_only_and_rebaseline_skipped_sequences() {
    let (mut service, owner) = armed();
    let at = Instant::now();
    let batch: Vec<_> = (1..=3).flat_map(|seq| report(owner, seq)).collect();
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &batch, at),
        Ok(Some(ReceiverTelemetryDecision::Baseline))
    );
    // The next contiguous report becomes a normal verified interval.
    assert!(matches!(
        service.observe_stream_chunk_after_verified_peer(
            peer(),
            &report(owner, 4),
            at + Duration::from_secs(2)
        ),
        Ok(Some(ReceiverTelemetryDecision::Interval(_)))
    ));
    assert!(service.has_fresh_for_verified_peer(peer(), at + Duration::from_secs(2)));
}

#[test]
fn stale_verified_worker_cannot_consume_current_partial() {
    let (mut service, owner) = armed();
    let at = Instant::now();
    let bytes = report(owner, 1);
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[..67], at),
        Ok(None)
    );
    let mut wrong = peer();
    wrong.worker_generation += 1;
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(wrong, &bytes[67..], at),
        Err(ReceiverTelemetryServiceStreamError::NotAuthorized)
    );
    assert_eq!(service.current(), Some(owner));
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[67..], at),
        Ok(Some(ReceiverTelemetryDecision::Baseline))
    );
}

#[test]
fn starting_key_replacement_immediately_revokes_partial_and_old_grant() {
    let (mut service, owner) = armed();
    let at = Instant::now();
    let bytes = report(owner, 1);
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[..70], at),
        Ok(None)
    );
    service.key_install_started();
    assert!(service.current().is_none());
    assert!(!service.has_fresh_for_verified_peer(peer(), at));
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[70..], at),
        Err(ReceiverTelemetryServiceStreamError::NotAuthorized)
    );
    service.confirm_key_installed(key(), peer()).unwrap();
    let next = service
        .activate_correlated_start(start(), peer(), ack())
        .unwrap();
    assert_eq!(next.receiver_generation, owner.receiver_generation + 1);
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(
            peer(),
            &report(next, 1),
            at + Duration::from_secs(1)
        ),
        Ok(Some(ReceiverTelemetryDecision::Baseline))
    );
}

#[test]
fn stale_key_revocation_does_not_clear_pending_but_exact_revoke_does() {
    let (mut service, owner) = armed();
    let at = Instant::now();
    let bytes = report(owner, 1);
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[..19], at),
        Ok(None)
    );
    let mut stale = key();
    stale.key_grant_request_id += 1;
    assert!(!service.revoke_matching_key(stale));
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[19..], at),
        Ok(Some(ReceiverTelemetryDecision::Baseline))
    );
    assert!(service.revoke_matching_key(key()));
    assert!(!service.has_fresh_for_verified_peer(peer(), at));
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(
            peer(),
            &report(owner, 2),
            at + Duration::from_secs(2)
        ),
        Err(ReceiverTelemetryServiceStreamError::NotAuthorized)
    );
}

#[test]
fn malformed_wire_closes_service_runtime_and_does_not_reactivate_old_key() {
    let (mut service, owner) = armed();
    let at = Instant::now();
    let mut malformed = report(owner, 1);
    malformed[0] ^= 1;
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &malformed, at),
        Err(ReceiverTelemetryServiceStreamError::Framing(
            ReceiverTelemetryFrameStreamError::Wire(ReceiverTelemetryWireError::BadMagic)
        ))
    );
    assert!(service.current().is_none());
    assert!(service.worker_grant_after_verified_peer(peer()).is_none());
    assert!(!service.has_fresh_for_verified_peer(peer(), at));
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &report(owner, 1), at),
        Err(ReceiverTelemetryServiceStreamError::NotAuthorized)
    );
}

#[test]
fn out_of_order_coalesced_batch_fails_closed_without_creating_freshness() {
    let (mut service, owner) = armed();
    let at = Instant::now();
    let batch: Vec<_> = [report(owner, 2), report(owner, 1)].concat();
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &batch, at),
        Err(ReceiverTelemetryServiceStreamError::NonmonotonicBatch)
    );
    assert!(service.current().is_none());
    assert!(!service.has_fresh_for_verified_peer(peer(), at));
}

#[test]
fn forbidden_payload_owner_invalidates_service_runtime_and_key() {
    let (mut service, owner) = armed();
    let mut forged = owner;
    forged.epoch += 1;
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(
            peer(),
            &report(forged, 1),
            Instant::now()
        ),
        Err(ReceiverTelemetryServiceStreamError::Framing(
            ReceiverTelemetryFrameStreamError::ReportBindingMismatch
        ))
    );
    assert!(service.current().is_none());
    assert!(service.worker_grant_after_verified_peer(peer()).is_none());
}

#[test]
fn partial_then_worker_exit_cannot_admit_after_reactivation() {
    let (mut service, owner) = armed();
    let bytes = report(owner, 1);
    let at = Instant::now();
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[..55], at),
        Ok(None)
    );
    service.worker_changed();
    assert!(service.current().is_none());
    service.confirm_key_installed(key(), peer()).unwrap();
    let next = service
        .activate_correlated_start(start(), peer(), ack())
        .unwrap();
    assert_ne!(next, owner);
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[55..], at),
        Ok(None),
        "old incomplete bytes are not a complete authorized report"
    );
    // Any later bytes joining old half must not become a valid new report.
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &report(next, 1), at),
        Err(ReceiverTelemetryServiceStreamError::Framing(
            ReceiverTelemetryFrameStreamError::Wire(ReceiverTelemetryWireError::BadMagic)
        ))
    );
    assert!(service.current().is_none());
}

#[test]
fn zero_read_retires_all_current_service_telemetry_authority() {
    let (mut service, owner) = armed();
    let at = Instant::now();
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &[], at),
        Err(ReceiverTelemetryServiceStreamError::Framing(
            ReceiverTelemetryFrameStreamError::Disconnected
        ))
    );
    assert!(service.current().is_none());
    assert!(service.worker_grant_after_verified_peer(peer()).is_none());
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &report(owner, 1), at),
        Err(ReceiverTelemetryServiceStreamError::NotAuthorized)
    );
}

#[test]
fn stale_replay_across_reads_revokes_service_key_and_report_liveness() {
    use classmesh_control::receiver_telemetry::ReceiverTelemetryError;
    use classmesh_control::receiver_telemetry_ingress::ReceiverTelemetryIngressError;
    use classmesh_control::receiver_telemetry_service_admission::ReceiverTelemetryServiceAdmissionError;

    let (mut service, owner) = armed();
    let at = Instant::now();
    let first = report(owner, 1);
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &first, at),
        Ok(Some(ReceiverTelemetryDecision::Baseline))
    );
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(
            peer(),
            &first,
            at + Duration::from_secs(2)
        ),
        Err(ReceiverTelemetryServiceStreamError::Admission(
            ReceiverTelemetryServiceAdmissionError::Ingress(
                ReceiverTelemetryIngressError::Admission(ReceiverTelemetryError::Replay)
            )
        ))
    );
    assert!(service.current().is_none());
    assert!(!service.has_fresh_for_verified_peer(peer(), at + Duration::from_secs(2)));
    assert!(service.worker_grant_after_verified_peer(peer()).is_none());
}

#[test]
fn partial_byte_stream_times_out_on_next_read_and_revokes_service_key() {
    use classmesh_control::receiver_telemetry_stream_framing::MAX_RECEIVER_TELEMETRY_PARTIAL_AGE;
    let (mut service, owner) = armed();
    let at = Instant::now();
    let bytes = report(owner, 1);
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[..45], at),
        Ok(None)
    );
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(
            peer(),
            &bytes[45..],
            at + MAX_RECEIVER_TELEMETRY_PARTIAL_AGE + Duration::from_nanos(1)
        ),
        Err(ReceiverTelemetryServiceStreamError::Framing(
            ReceiverTelemetryFrameStreamError::PartialTimedOut
        ))
    );
    assert_eq!(service.current(), None);
    assert!(service.worker_grant_after_verified_peer(peer()).is_none());
    assert!(!service.has_fresh_for_verified_peer(peer(), at));
}

#[test]
fn service_tick_retires_idle_partial_without_another_pipe_read() {
    use classmesh_control::receiver_telemetry_stream_framing::MAX_RECEIVER_TELEMETRY_PARTIAL_AGE;
    let (mut service, owner) = armed();
    let at = Instant::now();
    let bytes = report(owner, 1);
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[..32], at),
        Ok(None)
    );
    assert_eq!(
        service.expire_partial_stream_after_verified_peer(
            peer(),
            at + MAX_RECEIVER_TELEMETRY_PARTIAL_AGE
        ),
        Ok(())
    );
    assert_eq!(
        service.expire_partial_stream_after_verified_peer(
            peer(),
            at + MAX_RECEIVER_TELEMETRY_PARTIAL_AGE + Duration::from_nanos(1)
        ),
        Err(ReceiverTelemetryServiceStreamError::Framing(
            ReceiverTelemetryFrameStreamError::PartialTimedOut
        ))
    );
    assert_eq!(service.current(), None);
    assert!(!service.has_fresh_for_verified_peer(peer(), at));
}

#[test]
fn stale_worker_tick_never_expires_newer_receiver_partial() {
    use classmesh_control::receiver_telemetry_stream_framing::MAX_RECEIVER_TELEMETRY_PARTIAL_AGE;
    let (mut service, owner) = armed();
    let at = Instant::now();
    let bytes = report(owner, 1);
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[..30], at),
        Ok(None)
    );
    let mut old_worker = peer();
    old_worker.worker_generation += 1;
    assert_eq!(
        service.expire_partial_stream_after_verified_peer(
            old_worker,
            at + MAX_RECEIVER_TELEMETRY_PARTIAL_AGE + Duration::from_secs(10)
        ),
        Err(ReceiverTelemetryServiceStreamError::NotAuthorized)
    );
    assert_eq!(service.current(), Some(owner));
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[30..], at),
        Ok(Some(ReceiverTelemetryDecision::Baseline))
    );
}

#[test]
fn service_partial_clock_regression_fails_closed_without_admission() {
    let (mut service, owner) = armed();
    let at = Instant::now() + Duration::from_secs(2);
    let bytes = report(owner, 1);
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &bytes[..30], at),
        Ok(None)
    );
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(
            peer(),
            &bytes[30..],
            at - Duration::from_nanos(1)
        ),
        Err(ReceiverTelemetryServiceStreamError::Framing(
            ReceiverTelemetryFrameStreamError::PartialClockRegression
        ))
    );
    assert_eq!(service.current(), None);
    assert!(!service.has_fresh_for_verified_peer(peer(), at));
}

#[test]
fn completed_frames_do_not_expire_or_reset_freshness_on_later_idle_tick() {
    use classmesh_control::receiver_telemetry_stream_framing::MAX_RECEIVER_TELEMETRY_PARTIAL_AGE;
    let (mut service, owner) = armed();
    let at = Instant::now();
    assert_eq!(
        service.observe_stream_chunk_after_verified_peer(peer(), &report(owner, 1), at),
        Ok(Some(ReceiverTelemetryDecision::Baseline))
    );
    assert_eq!(
        service.expire_partial_stream_after_verified_peer(
            peer(),
            at + MAX_RECEIVER_TELEMETRY_PARTIAL_AGE + Duration::from_secs(1)
        ),
        Ok(())
    );
    assert_eq!(service.current(), Some(owner));
    assert!(service.has_fresh_for_verified_peer(peer(), at + MAX_RECEIVER_TELEMETRY_PARTIAL_AGE));
}
