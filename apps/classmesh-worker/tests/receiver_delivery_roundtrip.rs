//! Cross-thread, bounded *in-process* qualification of the already-merged
//! pre-IPC Worker outbox -> best-effort dispatcher -> Service runtime.
//!
//! This test uses a standard library bounded channel and injects a verified
//! Worker identity into Service. The harness does NOT authenticate Windows
//! Named Pipe peers, register a protocol message, or run the production loop.
//! An independently OS-authenticated Worker identity must be pinned by the
//! future Service transport before calling observe_after_verified_peer.

use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::time::{Duration, Instant};

use classmesh_control::receiver_telemetry::{ReceiverTelemetryBinding, ReceiverTelemetryDecision};
use classmesh_control::receiver_telemetry_service_admission::ReceiverTelemetryServiceAdmissionError;
use classmesh_control::receiver_telemetry_service_lifecycle::{
    ReceiverTelemetryCurrentWorker, ReceiverTelemetryStart, ReceiverTelemetryStartAck,
    ReceiverTelemetryStartAckStatus,
};
use classmesh_control::receiver_telemetry_service_runtime::{
    ReceiverTelemetryAuthorizedKey, ReceiverTelemetryServiceRuntime,
};
use classmesh_control::receiver_telemetry_transport::RECEIVER_TELEMETRY_WIRE_LEN;
use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;
use classmesh_worker::group_media_receive::WorkerGroupMediaAuthenticationStats;
use classmesh_worker::presentation_delivery_dispatch::{
    TelemetryDispatchOutcome, TelemetryTryWriteError, try_dispatch_once,
};
use classmesh_worker::presentation_delivery_publisher::{
    PresentationDeliveryPublisher, PresentationDeliveryReadonlySender,
    WorkerReceiverTelemetryAuthorization,
};

fn verified_worker(generation: u64) -> ReceiverTelemetryCurrentWorker {
    ReceiverTelemetryCurrentWorker {
        process_id: 501,
        session_id: 7,
        worker_generation: generation,
    }
}

fn installed_key() -> PresentationKeyInstallBinding {
    PresentationKeyInstallBinding {
        control_session_id: 30,
        request_id: 51,
        presentation_id: 40,
        stream_id: 8,
        epoch: 2,
    }
}

fn service_started(
    generation: u64,
) -> (
    ReceiverTelemetryServiceRuntime,
    WorkerReceiverTelemetryAuthorization,
    ReceiverTelemetryCurrentWorker,
) {
    let mut service = ReceiverTelemetryServiceRuntime::default();
    let key = installed_key();
    let worker = verified_worker(generation);
    service
        .confirm_key_installed(
            ReceiverTelemetryAuthorizedKey {
                control_session_id: key.control_session_id,
                key_grant_request_id: key.request_id,
                presentation_id: key.presentation_id,
                stream_id: key.stream_id,
                epoch: key.epoch,
            },
            worker,
        )
        .unwrap();
    let start = ReceiverTelemetryStart {
        process_id: worker.process_id,
        session_id: worker.session_id,
        worker_generation: worker.worker_generation,
        control_session_id: key.control_session_id,
        request_id: 91, // media start, deliberately separate from key grant 51
        presentation_id: key.presentation_id,
        stream_id: key.stream_id,
        epoch: key.epoch,
    };
    service
        .activate_correlated_start(
            start,
            worker,
            ReceiverTelemetryStartAck {
                process_id: worker.process_id,
                session_id: worker.session_id,
                control_session_id: start.control_session_id,
                request_id: start.request_id,
                presentation_id: start.presentation_id,
                stream_id: start.stream_id,
                status: ReceiverTelemetryStartAckStatus::Started,
            },
        )
        .unwrap();
    let grant = service.worker_grant_after_verified_peer(worker).unwrap();
    let permit = WorkerReceiverTelemetryAuthorization::from_service_grant(grant, key).unwrap();
    assert_eq!(service.current(), Some(permit.owner()));
    (service, permit, worker)
}

fn started_publisher(
    permit: WorkerReceiverTelemetryAuthorization,
    now: Instant,
) -> PresentationDeliveryPublisher {
    let mut publisher = PresentationDeliveryPublisher::default();
    publisher.activate_from_service(permit).unwrap();
    // Worker-local report cadence: no report at first call; one every 5s.
    assert_eq!(publisher.offer_if_due(now, counters(10), 1).unwrap(), None);
    publisher
}

fn counters(n: u64) -> WorkerGroupMediaAuthenticationStats {
    WorkerGroupMediaAuthenticationStats {
        opened_frames: n,
        rejected_frames: 2,
    }
}

fn emit(publisher: &mut PresentationDeliveryPublisher, at: Instant, n: u64) {
    assert!(
        publisher
            .offer_if_due(at, counters(n), n)
            .unwrap()
            .is_some()
    );
}

type Frame = [u8; RECEIVER_TELEMETRY_WIRE_LEN];

fn send_once(
    sender: &PresentationDeliveryReadonlySender,
    receiver: ReceiverTelemetryBinding,
    tx: &SyncSender<Frame>,
) -> TelemetryDispatchOutcome {
    // Stand-in verifier ONLY: this closed-over exact owner is not a Windows
    // credential. A real caller must attest Service OS identity and version.
    try_dispatch_once(
        sender,
        receiver,
        |current| current == receiver,
        |frame| {
            tx.try_send(*frame).map_err(|err| match err {
                TrySendError::Full(_) => TelemetryTryWriteError::WouldBlock,
                TrySendError::Disconnected(_) => TelemetryTryWriteError::Disconnected,
            })
        },
    )
}

#[test]
fn cross_thread_dispatch_and_service_admission_produce_only_five_second_deltas() {
    let (mut service, permit, worker) = service_started(11);
    let now = Instant::now();
    let mut publisher = started_publisher(permit, now);
    emit(&mut publisher, now + Duration::from_secs(5), 15);
    let reader = publisher.readonly_sender();
    let owner = permit.owner();
    let (tx, rx) = mpsc::sync_channel::<Frame>(1);

    // Exactly one copy leaves the independent Worker diagnostic dispatch
    // thread; it never waits on the Service's read or the render loop.
    let outbound = std::thread::spawn(move || send_once(&reader, owner, &tx));
    assert_eq!(outbound.join().unwrap(), TelemetryDispatchOutcome::Sent);
    let first = rx.try_recv().unwrap();
    assert_eq!(
        service
            .observe_after_verified_peer(worker, &first, now + Duration::from_secs(5))
            .unwrap(),
        ReceiverTelemetryDecision::Baseline
    );
    assert!(service.has_fresh_for_verified_peer(worker, now + Duration::from_secs(6)));

    emit(&mut publisher, now + Duration::from_secs(10), 25);
    let reader = publisher.readonly_sender();
    let (tx2, rx2) = mpsc::sync_channel::<Frame>(1);
    assert_eq!(
        send_once(&reader, owner, &tx2),
        TelemetryDispatchOutcome::Sent
    );
    let second = rx2.try_recv().unwrap();
    let ReceiverTelemetryDecision::Interval(interval) = service
        .observe_after_verified_peer(worker, &second, now + Duration::from_secs(10))
        .unwrap()
    else {
        panic!("two contiguous five-second reports should produce an interval");
    };
    assert_eq!(interval.elapsed, Duration::from_secs(5));
    assert_eq!(interval.authenticated_frames, 10);
    assert_eq!(interval.rejected_frames, 0);
    assert_eq!(interval.queue_drops, 10);
    // An authenticated AEAD open does not prove decode or presentation.
    assert_eq!(interval.decoded_frames, 0);
    assert_eq!(interval.presented_frames, 0);
}

#[test]
fn bounded_channel_congestion_discards_once_and_forces_service_rebaseline() {
    let (mut service, permit, worker) = service_started(12);
    let now = Instant::now();
    let mut publisher = started_publisher(permit, now);
    let reader = publisher.readonly_sender();
    let (tx, rx) = mpsc::sync_channel::<Frame>(1);

    emit(&mut publisher, now + Duration::from_secs(5), 20);
    assert_eq!(
        send_once(&reader, permit.owner(), &tx),
        TelemetryDispatchOutcome::Sent
    );
    emit(&mut publisher, now + Duration::from_secs(10), 30);
    assert_eq!(
        send_once(&reader, permit.owner(), &tx),
        TelemetryDispatchOutcome::DroppedBackpressure
    );
    assert_eq!(
        send_once(&reader, permit.owner(), &tx),
        TelemetryDispatchOutcome::NoReport
    );
    assert_eq!(
        service
            .observe_after_verified_peer(
                worker,
                &rx.try_recv().unwrap(),
                now + Duration::from_secs(5)
            )
            .unwrap(),
        ReceiverTelemetryDecision::Baseline
    );

    // Sequence 2 was discarded during congestion. Sequence 3 MUST establish
    // a new baseline, never be misreported as uninterrupted healthy delivery.
    emit(&mut publisher, now + Duration::from_secs(15), 40);
    assert_eq!(
        send_once(&reader, permit.owner(), &tx),
        TelemetryDispatchOutcome::Sent
    );
    assert_eq!(
        service
            .observe_after_verified_peer(
                worker,
                &rx.try_recv().unwrap(),
                now + Duration::from_secs(15)
            )
            .unwrap(),
        ReceiverTelemetryDecision::Baseline
    );

    emit(&mut publisher, now + Duration::from_secs(20), 50);
    assert_eq!(
        send_once(&reader, permit.owner(), &tx),
        TelemetryDispatchOutcome::Sent
    );
    let ReceiverTelemetryDecision::Interval(delta) = service
        .observe_after_verified_peer(
            worker,
            &rx.try_recv().unwrap(),
            now + Duration::from_secs(20),
        )
        .unwrap()
    else {
        panic!("new contiguous reports should restore interval");
    };
    assert_eq!(delta.authenticated_frames, 10);
    assert_eq!(delta.queue_drops, 10);
}

#[test]
fn already_sent_bytes_are_rejected_after_service_worker_replacement() {
    let (mut service, permit, worker) = service_started(13);
    let now = Instant::now();
    let mut publisher = started_publisher(permit, now);
    let reader = publisher.readonly_sender();
    let (tx, rx) = mpsc::sync_channel::<Frame>(1);

    emit(&mut publisher, now + Duration::from_secs(5), 20);
    assert_eq!(
        send_once(&reader, permit.owner(), &tx),
        TelemetryDispatchOutcome::Sent
    );
    // The Worker did not see the revocation before sending, and its local
    // lease was valid. Service independently rejects in-flight old bytes.
    service.worker_changed();
    let queued = rx.try_recv().unwrap();
    assert_eq!(
        service.observe_after_verified_peer(worker, &queued, now + Duration::from_secs(5)),
        Err(ReceiverTelemetryServiceAdmissionError::NoActiveRuntime)
    );
    assert!(!service.has_fresh_for_verified_peer(worker, now + Duration::from_secs(5)));
}

#[test]
fn service_rejects_correct_wire_bytes_claimed_by_wrong_verified_worker() {
    let (mut service, permit, worker) = service_started(14);
    let now = Instant::now();
    let mut publisher = started_publisher(permit, now);
    let reader = publisher.readonly_sender();
    let (tx, rx) = mpsc::sync_channel::<Frame>(1);

    emit(&mut publisher, now + Duration::from_secs(5), 20);
    assert_eq!(
        send_once(&reader, permit.owner(), &tx),
        TelemetryDispatchOutcome::Sent
    );
    let payload = rx.try_recv().unwrap();
    let wrong_worker = verified_worker(worker.worker_generation + 1);
    assert_eq!(
        service.observe_after_verified_peer(wrong_worker, &payload, now + Duration::from_secs(5),),
        Err(ReceiverTelemetryServiceAdmissionError::WorkerMismatch)
    );
    // Bad peer evidence must not poison the valid Service admission baseline.
    assert_eq!(
        service
            .observe_after_verified_peer(worker, &payload, now + Duration::from_secs(5))
            .unwrap(),
        ReceiverTelemetryDecision::Baseline
    );
}
