use std::time::{Duration, Instant};

use classmesh_control::receiver_telemetry_service_lifecycle::{
    ReceiverTelemetryCurrentWorker, ReceiverTelemetryStart, ReceiverTelemetryStartAck,
    ReceiverTelemetryStartAckStatus,
};
use classmesh_control::receiver_telemetry_service_runtime::{
    ReceiverTelemetryAuthorizedKey, ReceiverTelemetryServiceRuntime, ReceiverTelemetryWorkerGrant,
};
use classmesh_control::receiver_telemetry_transport::{
    decode_receiver_telemetry, encode_receiver_telemetry,
};
use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;
use classmesh_worker::group_media_receive::WorkerGroupMediaAuthenticationStats;
use classmesh_worker::presentation_delivery_publisher::{
    PresentationDeliveryPublisher, PresentationDeliveryPublisherError,
    WorkerReceiverTelemetryAuthorization,
};

fn service_grant(
    generation: u64,
    start_request_id: u64,
) -> (ReceiverTelemetryWorkerGrant, PresentationKeyInstallBinding) {
    assert!(generation > 0);
    let worker = ReceiverTelemetryCurrentWorker {
        process_id: 501,
        session_id: 7,
        worker_generation: 11,
    };
    let installed_key = PresentationKeyInstallBinding {
        control_session_id: 30,
        request_id: 51,
        presentation_id: 40,
        stream_id: 8,
        epoch: 2,
    };
    let mut service = ReceiverTelemetryServiceRuntime::default();
    service
        .confirm_key_installed(
            ReceiverTelemetryAuthorizedKey {
                control_session_id: installed_key.control_session_id,
                key_grant_request_id: installed_key.request_id,
                presentation_id: installed_key.presentation_id,
                stream_id: installed_key.stream_id,
                epoch: installed_key.epoch,
            },
            worker,
        )
        .unwrap();
    let start = ReceiverTelemetryStart {
        process_id: worker.process_id,
        session_id: worker.session_id,
        worker_generation: worker.worker_generation,
        control_session_id: installed_key.control_session_id,
        request_id: start_request_id,
        presentation_id: installed_key.presentation_id,
        stream_id: installed_key.stream_id,
        epoch: installed_key.epoch,
    };
    let ack = ReceiverTelemetryStartAck {
        process_id: worker.process_id,
        session_id: worker.session_id,
        control_session_id: start.control_session_id,
        request_id: start.request_id,
        presentation_id: start.presentation_id,
        stream_id: start.stream_id,
        status: ReceiverTelemetryStartAckStatus::Started,
    };
    for _ in 0..generation {
        service
            .activate_correlated_start(start, worker, ack)
            .unwrap();
    }
    let grant = service.worker_grant_after_verified_peer(worker).unwrap();
    (grant, installed_key)
}

fn permit(generation: u64, start_request_id: u64) -> WorkerReceiverTelemetryAuthorization {
    let (grant, installed_key) = service_grant(generation, start_request_id);
    WorkerReceiverTelemetryAuthorization::from_service_grant(grant, installed_key).unwrap()
}

fn counters(n: u64) -> WorkerGroupMediaAuthenticationStats {
    WorkerGroupMediaAuthenticationStats {
        opened_frames: n,
        rejected_frames: 2,
    }
}

#[test]
fn service_minted_owner_is_stamped_at_emission_not_at_checkout() {
    let now = Instant::now();
    let mut outbox = PresentationDeliveryPublisher::default();
    let grant = permit(1, 91);
    assert_eq!(outbox.offer_if_due(now, counters(10), 3).unwrap(), None);
    outbox.activate_from_service(grant).unwrap();
    assert_eq!(outbox.current(), Some(grant.owner()));
    assert_eq!(outbox.offer_if_due(now, counters(10), 3).unwrap(), None);
    assert_eq!(
        outbox
            .offer_if_due(now + Duration::from_secs(5), counters(10), 3)
            .unwrap(),
        Some(false)
    );
    let lease = outbox.try_checkout().unwrap().unwrap();
    assert!(outbox.lease_is_current(&lease).unwrap());
    let snap = lease.snapshot();
    assert_eq!(snap.binding, grant.owner());
    assert_eq!(snap.binding.request_id, 91);
    assert_eq!(grant.installed_key().request_id, 51);
    assert_eq!(snap.sequence, 1);
    assert_eq!(snap.counters.authenticated_frames, 10);
    assert_eq!(snap.counters.queue_drops, 3);
    let bytes = encode_receiver_telemetry(&snap).unwrap();
    assert_eq!(decode_receiver_telemetry(&bytes).unwrap(), snap);
}

#[test]
fn same_key_runtime_replacement_revokes_old_lease_and_resets_report_sequence() {
    let now = Instant::now();
    let mut outbox = PresentationDeliveryPublisher::default();
    outbox.activate_from_service(permit(1, 91)).unwrap();
    outbox.offer_if_due(now, counters(10), 0).unwrap();
    outbox
        .offer_if_due(now + Duration::from_secs(5), counters(11), 0)
        .unwrap();
    let stale_lease = outbox.try_checkout().unwrap().unwrap();
    let next = permit(2, 91); // Same key/start IDs; new Service receiver generation.
    outbox.activate_from_service(next).unwrap();
    assert!(!outbox.lease_is_current(&stale_lease).unwrap());
    assert!(outbox.try_checkout().unwrap().is_none());
    outbox
        .offer_if_due(now + Duration::from_secs(6), counters(1), 0)
        .unwrap();
    outbox
        .offer_if_due(now + Duration::from_secs(11), counters(2), 0)
        .unwrap();
    let fresh = outbox.try_checkout().unwrap().unwrap();
    assert_eq!(fresh.snapshot().binding.receiver_generation, 2);
    assert_eq!(fresh.snapshot().sequence, 1);
    assert_eq!(fresh.snapshot().counters.authenticated_frames, 2);
    assert!(outbox.lease_is_current(&fresh).unwrap());
}

#[test]
fn invalid_permit_and_stale_generation_never_replace_live_receiver() {
    let mut outbox = PresentationDeliveryPublisher::default();
    let original = permit(4, 91);
    outbox.activate_from_service(original).unwrap();
    // Integration callers can no longer construct or corrupt a permit.
    // Deliberately incorrect Worker-installed key cannot form one.
    let (grant, mut wrong_key) = service_grant(5, 92);
    wrong_key.epoch += 1;
    assert!(WorkerReceiverTelemetryAuthorization::from_service_grant(grant, wrong_key).is_none());
    assert_eq!(outbox.activate_from_service(original), Ok(()));
    assert_eq!(
        outbox.activate_from_service(permit(3, 91)),
        Err(PresentationDeliveryPublisherError::StaleReceiverGeneration)
    );
    assert_eq!(
        outbox.activate_from_service(permit(4, 92)),
        Err(PresentationDeliveryPublisherError::StaleReceiverGeneration)
    );
    assert!(!outbox.clear_if_matches(permit(5, 91).owner()).unwrap());
    assert_eq!(outbox.current(), Some(original.owner()));
}

#[test]
fn revocation_rejects_old_checked_out_report_and_never_reuses_generation() {
    let now = Instant::now();
    let mut outbox = PresentationDeliveryPublisher::default();
    let original = permit(6, 91);
    outbox.activate_from_service(original).unwrap();
    outbox.offer_if_due(now, counters(10), 0).unwrap();
    outbox
        .offer_if_due(now + Duration::from_secs(5), counters(11), 0)
        .unwrap();
    let checked_out = outbox.try_checkout().unwrap().unwrap();
    assert!(outbox.clear_if_matches(original.owner()).unwrap());
    assert!(!outbox.lease_is_current(&checked_out).unwrap());
    assert!(outbox.current().is_none());
    assert!(outbox.try_checkout().unwrap().is_none());
    assert_eq!(
        outbox
            .offer_if_due(now + Duration::from_secs(10), counters(12), 0)
            .unwrap(),
        None
    );
    assert_eq!(
        outbox.activate_from_service(original),
        Err(PresentationDeliveryPublisherError::StaleReceiverGeneration)
    );
    outbox.activate_from_service(permit(7, 91)).unwrap();
    assert_eq!(outbox.current().unwrap().receiver_generation, 7);
}

#[test]
fn bounded_mailbox_coalesces_old_samples_without_blocking_on_pipe() {
    let now = Instant::now();
    let mut outbox = PresentationDeliveryPublisher::default();
    let permit = permit(8, 97);
    outbox.activate_from_service(permit).unwrap();
    outbox.offer_if_due(now, counters(1), 0).unwrap();
    assert_eq!(
        outbox
            .offer_if_due(now + Duration::from_secs(5), counters(2), 0)
            .unwrap(),
        Some(false)
    );
    assert_eq!(
        outbox
            .offer_if_due(now + Duration::from_secs(10), counters(3), 0)
            .unwrap(),
        Some(true)
    );
    let checkout = outbox.try_checkout().unwrap().unwrap();
    assert_eq!(checkout.snapshot().sequence, 2);
    assert_eq!(checkout.snapshot().binding, permit.owner());
    assert_eq!(checkout.snapshot().counters.authenticated_frames, 3);
    assert!(outbox.try_checkout().unwrap().is_none());
}

#[test]
fn publisher_can_accept_only_exact_service_minted_grant_and_confirmed_worker_key() {
    let trusted_worker = ReceiverTelemetryCurrentWorker {
        process_id: 501,
        session_id: 7,
        worker_generation: 11,
    };
    let key = permit(1, 91).installed_key();
    let mut service = ReceiverTelemetryServiceRuntime::default();
    service
        .confirm_key_installed(
            ReceiverTelemetryAuthorizedKey {
                control_session_id: key.control_session_id,
                key_grant_request_id: key.request_id,
                presentation_id: key.presentation_id,
                stream_id: key.stream_id,
                epoch: key.epoch,
            },
            trusted_worker,
        )
        .unwrap();

    let requested = ReceiverTelemetryStart {
        process_id: trusted_worker.process_id,
        session_id: trusted_worker.session_id,
        worker_generation: trusted_worker.worker_generation,
        control_session_id: key.control_session_id,
        request_id: 91, // Not the grant's request 51.
        presentation_id: key.presentation_id,
        stream_id: key.stream_id,
        epoch: key.epoch,
    };
    let ack = ReceiverTelemetryStartAck {
        process_id: trusted_worker.process_id,
        session_id: trusted_worker.session_id,
        control_session_id: key.control_session_id,
        request_id: 91,
        presentation_id: key.presentation_id,
        stream_id: key.stream_id,
        status: ReceiverTelemetryStartAckStatus::Started,
    };
    let owner = service
        .activate_correlated_start(requested, trusted_worker, ack)
        .unwrap();
    let grant = service
        .worker_grant_after_verified_peer(trusted_worker)
        .unwrap();
    let permit = WorkerReceiverTelemetryAuthorization::from_service_grant(grant, key)
        .expect("exact Service mint and installed Worker key");
    assert_eq!(permit.owner(), owner);
    assert_eq!(permit.authorized_start_request_id(), 91);
    assert_eq!(permit.installed_key().request_id, 51);

    assert!(
        WorkerReceiverTelemetryAuthorization::from_service_grant(
            grant,
            PresentationKeyInstallBinding {
                request_id: 52,
                ..key
            },
        )
        .is_none()
    );
    assert!(
        WorkerReceiverTelemetryAuthorization::from_service_grant(
            grant,
            PresentationKeyInstallBinding { epoch: 3, ..key },
        )
        .is_none()
    );

    let now = Instant::now();
    let mut outbox = PresentationDeliveryPublisher::default();
    outbox.activate_from_service(permit).unwrap();
    outbox.offer_if_due(now, counters(1), 0).unwrap();
    outbox
        .offer_if_due(now + Duration::from_secs(5), counters(3), 0)
        .unwrap();
    let leased = outbox.try_checkout().unwrap().unwrap();
    assert_eq!(leased.snapshot().binding, owner);
}

#[test]
fn detached_sender_reader_receives_only_current_immutable_worker_reports() {
    let now = Instant::now();
    let mut publisher = PresentationDeliveryPublisher::default();
    let reader = publisher.readonly_sender();
    let owner = permit(1, 91);
    assert!(
        reader
            .try_checkout_matching(owner.owner())
            .unwrap()
            .is_none()
    );

    publisher.activate_from_service(owner).unwrap();
    publisher.offer_if_due(now, counters(10), 0).unwrap();
    publisher
        .offer_if_due(now + Duration::from_secs(5), counters(11), 0)
        .unwrap();

    let detached = reader.clone();
    let lease = std::thread::spawn(move || detached.try_checkout_matching(owner.owner()))
        .join()
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(lease.snapshot().binding, owner.owner());
    assert!(reader.lease_is_current(&lease).unwrap());

    let replacement = permit(2, 91);
    publisher.activate_from_service(replacement).unwrap();
    assert!(!reader.lease_is_current(&lease).unwrap());
    assert!(
        reader
            .try_checkout_matching(owner.owner())
            .unwrap()
            .is_none()
    );
    publisher
        .offer_if_due(now + Duration::from_secs(6), counters(1), 0)
        .unwrap();
    publisher
        .offer_if_due(now + Duration::from_secs(11), counters(2), 0)
        .unwrap();
    let fresh = reader
        .try_checkout_matching(replacement.owner())
        .unwrap()
        .unwrap();
    assert_eq!(fresh.snapshot().binding, replacement.owner());
    assert!(reader.lease_is_current(&fresh).unwrap());
}

#[test]
fn detached_sender_reader_fails_closed_on_revocation_and_publisher_drop() {
    let now = Instant::now();
    let reader;
    let lease;
    let owner = permit(1, 91);
    {
        let mut publisher = PresentationDeliveryPublisher::default();
        reader = publisher.readonly_sender();
        publisher.activate_from_service(owner).unwrap();
        publisher.offer_if_due(now, counters(1), 0).unwrap();
        publisher
            .offer_if_due(now + Duration::from_secs(5), counters(2), 0)
            .unwrap();
        lease = reader
            .try_checkout_matching(owner.owner())
            .unwrap()
            .unwrap();
        assert!(reader.lease_is_current(&lease).unwrap());
        assert!(publisher.clear_if_matches(owner.owner()).unwrap());
        assert!(!reader.lease_is_current(&lease).unwrap());
        let replacement = permit(2, 91);
        publisher.activate_from_service(replacement).unwrap();
        publisher
            .offer_if_due(now + Duration::from_secs(6), counters(1), 0)
            .unwrap();
        publisher
            .offer_if_due(now + Duration::from_secs(11), counters(2), 0)
            .unwrap();
        // Leave the replacement generation's report pending on publisher drop.
        assert!(
            reader
                .try_checkout_matching(owner.owner())
                .unwrap()
                .is_none()
        );
    }
    assert!(!reader.lease_is_current(&lease).unwrap());
    assert!(
        reader
            .try_checkout_matching(owner.owner())
            .unwrap()
            .is_none()
    );
    assert!(
        reader
            .try_checkout_matching(permit(2, 91).owner())
            .unwrap()
            .is_none()
    );
}
