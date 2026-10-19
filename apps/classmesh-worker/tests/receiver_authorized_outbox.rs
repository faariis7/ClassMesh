use std::time::{Duration, Instant};

use classmesh_control::receiver_telemetry::ReceiverTelemetryBinding;
use classmesh_control::receiver_telemetry_transport::{
    decode_receiver_telemetry, encode_receiver_telemetry,
};
use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;
use classmesh_worker::group_media_receive::WorkerGroupMediaAuthenticationStats;
use classmesh_worker::presentation_delivery_publisher::{
    PresentationDeliveryPublisher, PresentationDeliveryPublisherError,
    WorkerReceiverTelemetryAuthorization,
};

fn permit(generation: u64, start_request_id: u64) -> WorkerReceiverTelemetryAuthorization {
    WorkerReceiverTelemetryAuthorization {
        owner: ReceiverTelemetryBinding {
            process_id: 501,
            session_id: 7,
            worker_generation: 11,
            control_session_id: 30,
            request_id: start_request_id,
            presentation_id: 40,
            stream_id: 8,
            epoch: 2,
            receiver_generation: generation,
        },
        installed_key: PresentationKeyInstallBinding {
            control_session_id: 30,
            request_id: 51,
            presentation_id: 40,
            stream_id: 8,
            epoch: 2,
        },
        authorized_start_request_id: start_request_id,
    }
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
    assert_eq!(outbox.current(), Some(grant.owner));
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
    assert_eq!(snap.binding, grant.owner);
    assert_eq!(snap.binding.request_id, 91);
    assert_eq!(grant.installed_key.request_id, 51);
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
    let mut invalid = permit(5, 92);
    invalid.authorized_start_request_id = 91;
    assert_eq!(
        outbox.activate_from_service(invalid),
        Err(PresentationDeliveryPublisherError::InvalidAuthorization)
    );
    invalid = permit(5, 92);
    invalid.installed_key.epoch += 1;
    assert_eq!(
        outbox.activate_from_service(invalid),
        Err(PresentationDeliveryPublisherError::InvalidAuthorization)
    );
    assert_eq!(outbox.activate_from_service(original), Ok(()));
    assert_eq!(
        outbox.activate_from_service(permit(3, 91)),
        Err(PresentationDeliveryPublisherError::StaleReceiverGeneration)
    );
    assert_eq!(
        outbox.activate_from_service(permit(4, 92)),
        Err(PresentationDeliveryPublisherError::StaleReceiverGeneration)
    );
    assert!(!outbox.clear_if_matches(permit(5, 91).owner).unwrap());
    assert_eq!(outbox.current(), Some(original.owner));
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
    assert!(outbox.clear_if_matches(original.owner).unwrap());
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
    assert_eq!(checkout.snapshot().binding, permit.owner);
    assert_eq!(checkout.snapshot().counters.authenticated_frames, 3);
    assert!(outbox.try_checkout().unwrap().is_none());
}

#[test]
fn publisher_can_accept_only_exact_service_minted_grant_and_confirmed_worker_key() {
    use classmesh_control::receiver_telemetry_service_lifecycle::{
        ReceiverTelemetryCurrentWorker, ReceiverTelemetryStart, ReceiverTelemetryStartAck,
        ReceiverTelemetryStartAckStatus,
    };
    use classmesh_control::receiver_telemetry_service_runtime::{
        ReceiverTelemetryAuthorizedKey, ReceiverTelemetryServiceRuntime,
    };

    let trusted_worker = ReceiverTelemetryCurrentWorker {
        process_id: 501,
        session_id: 7,
        worker_generation: 11,
    };
    let key = permit(1, 91).installed_key;
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
    assert_eq!(permit.owner, owner);
    assert_eq!(permit.authorized_start_request_id, 91);
    assert_eq!(permit.installed_key.request_id, 51);

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
