//! Future grant payload only: this is NOT an authenticated IPC message.

use classmesh_control::receiver_telemetry_grant_wire::{
    GRANT_WIRE_LEN, ReceiverGrantWireError, decode_untrusted_worker_grant,
    encode_service_worker_grant,
};
use classmesh_control::receiver_telemetry_service_lifecycle::{
    ReceiverTelemetryCurrentWorker, ReceiverTelemetryStart, ReceiverTelemetryStartAck,
    ReceiverTelemetryStartAckStatus,
};
use classmesh_control::receiver_telemetry_service_runtime::{
    ReceiverTelemetryAuthorizedKey, ReceiverTelemetryServiceRuntime, ReceiverTelemetryWorkerGrant,
};

fn service_minted_grant() -> ReceiverTelemetryWorkerGrant {
    let worker = ReceiverTelemetryCurrentWorker {
        process_id: 501,
        session_id: 3,
        worker_generation: 7,
    };
    let key = ReceiverTelemetryAuthorizedKey {
        control_session_id: 11,
        key_grant_request_id: 12,
        presentation_id: 13,
        stream_id: 14,
        epoch: 15,
    };
    let start = ReceiverTelemetryStart {
        process_id: worker.process_id,
        session_id: worker.session_id,
        worker_generation: worker.worker_generation,
        control_session_id: key.control_session_id,
        request_id: 16, // Distinct from protected key grant request 12.
        presentation_id: key.presentation_id,
        stream_id: key.stream_id,
        epoch: key.epoch,
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
    let mut service = ReceiverTelemetryServiceRuntime::default();
    service.confirm_key_installed(key, worker).unwrap();
    service
        .activate_correlated_start(start, worker, ack)
        .unwrap();
    service.worker_grant_after_verified_peer(worker).unwrap()
}

#[test]
fn service_minted_grant_roundtrip_preserves_both_independent_request_ids() {
    let grant = service_minted_grant();
    let frame = encode_service_worker_grant(grant);
    assert_eq!(frame.len(), GRANT_WIRE_LEN);
    assert_eq!(&frame[..4], b"CMRG");
    assert_eq!(frame[4], 1);
    let untrusted = decode_untrusted_worker_grant(&frame).unwrap();
    assert_eq!(untrusted.receiver(), grant.receiver());
    assert_eq!(untrusted.protected_key_grant(), grant.protected_key_grant());
    assert_eq!(untrusted.receiver().request_id, 16);
    assert_eq!(untrusted.protected_key_grant().key_grant_request_id, 12);
    assert_eq!(untrusted.receiver().receiver_generation, 1);
}

#[test]
fn grant_payload_enforces_fixed_size_magic_version_and_reserved_bytes() {
    let valid = encode_service_worker_grant(service_minted_grant());
    for bad_len in [0, 1, GRANT_WIRE_LEN - 1] {
        assert_eq!(
            decode_untrusted_worker_grant(&valid[..bad_len]),
            Err(ReceiverGrantWireError::InvalidLength)
        );
    }
    let mut too_long = valid.to_vec();
    too_long.push(0);
    assert_eq!(
        decode_untrusted_worker_grant(&too_long),
        Err(ReceiverGrantWireError::InvalidLength)
    );

    let mut wrong = valid;
    wrong[0] ^= 1;
    assert_eq!(
        decode_untrusted_worker_grant(&wrong),
        Err(ReceiverGrantWireError::BadMagic)
    );
    let mut wrong = valid;
    wrong[4] = 2;
    assert_eq!(
        decode_untrusted_worker_grant(&wrong),
        Err(ReceiverGrantWireError::UnsupportedVersion)
    );
    for index in [5, 6, 7] {
        let mut wrong = valid;
        wrong[index] = 1;
        assert_eq!(
            decode_untrusted_worker_grant(&wrong),
            Err(ReceiverGrantWireError::NonzeroReserved)
        );
    }
}

#[test]
fn grant_payload_rejects_zero_ownership_and_unrelated_key_epoch() {
    let valid = encode_service_worker_grant(service_minted_grant());
    // 8-byte envelope, 56-byte receiver, 32-byte protected grant.
    for (from, to) in [(8, 12), (16, 24), (56, 64), (72, 80), (92, 96)] {
        let mut wrong = valid;
        wrong[from..to].fill(0);
        assert_eq!(
            decode_untrusted_worker_grant(&wrong),
            Err(ReceiverGrantWireError::InvalidBinding),
            "zero field at {from}..{to}"
        );
    }
    for (offset, value) in [(64, 99_u64), (80, 99_u64)] {
        let mut wrong = valid;
        wrong[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        assert_eq!(
            decode_untrusted_worker_grant(&wrong),
            Err(ReceiverGrantWireError::MismatchedGrant),
            "key ownership conflict at {offset}"
        );
    }
    let mut wrong_epoch = valid;
    wrong_epoch[92..96].copy_from_slice(&99_u32.to_be_bytes());
    assert_eq!(
        decode_untrusted_worker_grant(&wrong_epoch),
        Err(ReceiverGrantWireError::MismatchedGrant)
    );
}

#[test]
fn byte_payload_is_explicitly_untrusted_and_cannot_reissue_a_service_grant() {
    let legitimate = service_minted_grant();
    let raw = encode_service_worker_grant(legitimate);
    // The decoder must yield only an untrusted record, never the private
    // Service-minted grant or a capability to activate the Worker outbox.
    let parsed = decode_untrusted_worker_grant(&raw).unwrap();
    assert_eq!(parsed.receiver().worker_generation, 7);
    assert_eq!(parsed.protected_key_grant().epoch, 15);
}

#[test]
fn untrusted_wire_requires_independently_verified_worker_key_and_media_start() {
    let grant = service_minted_grant();
    let parsed = decode_untrusted_worker_grant(&encode_service_worker_grant(grant)).unwrap();
    let current = ReceiverTelemetryCurrentWorker {
        process_id: 501,
        session_id: 3,
        worker_generation: 7,
    };
    let installed_key = grant.protected_key_grant();
    assert!(parsed.matches_verified_local_state(
        current,
        installed_key,
        16,
        grant.receiver().receiver_generation
    ));
    for field in 0..3 {
        let mut stale = current;
        match field {
            0 => stale.process_id += 1,
            1 => stale.session_id += 1,
            2 => stale.worker_generation += 1,
            _ => unreachable!(),
        }
        assert!(!parsed.matches_verified_local_state(
            stale,
            installed_key,
            16,
            grant.receiver().receiver_generation
        ));
    }
    assert!(!parsed.matches_verified_local_state(
        current,
        installed_key,
        17,
        grant.receiver().receiver_generation
    ));
    let mut stale_key = installed_key;
    stale_key.key_grant_request_id += 1;
    assert!(!parsed.matches_verified_local_state(
        current,
        stale_key,
        16,
        grant.receiver().receiver_generation
    ));
    stale_key = installed_key;
    stale_key.epoch += 1;
    assert!(!parsed.matches_verified_local_state(
        current,
        stale_key,
        16,
        grant.receiver().receiver_generation
    ));
    stale_key = installed_key;
    stale_key.stream_id += 1;
    assert!(!parsed.matches_verified_local_state(
        current,
        stale_key,
        16,
        grant.receiver().receiver_generation
    ));
}

#[test]
fn receiver_grant_replay_rejects_stale_or_missing_independently_pinned_generation() {
    let grant = service_minted_grant();
    let untrusted = decode_untrusted_worker_grant(&encode_service_worker_grant(grant)).unwrap();
    let worker = ReceiverTelemetryCurrentWorker {
        process_id: 501,
        session_id: 3,
        worker_generation: 7,
    };
    let key = grant.protected_key_grant();
    // This generation is assumed to be independently pinned from the authenticated
    // Service lifetime, not copied from the untrusted decoded payload.
    let pinned_generation = grant.receiver().receiver_generation;
    assert!(untrusted.matches_verified_local_state(worker, key, 16, pinned_generation));
    assert!(!untrusted.matches_verified_local_state(worker, key, 16, 0));
    assert!(!untrusted.matches_verified_local_state(worker, key, 16, pinned_generation + 1));
}

#[test]
fn untrusted_wire_relabeling_cannot_reuse_an_old_authorized_receiver_generation() {
    let grant = service_minted_grant();
    let mut tampered = encode_service_worker_grant(grant);
    // Receiver generation is offset 56..64 (not the independent protected key).
    tampered[56..64].copy_from_slice(&2_u64.to_be_bytes());
    let parsed = decode_untrusted_worker_grant(&tampered).unwrap();
    let worker = ReceiverTelemetryCurrentWorker {
        process_id: 501,
        session_id: 3,
        worker_generation: 7,
    };
    assert!(!parsed.matches_verified_local_state(
        worker,
        grant.protected_key_grant(),
        16,
        grant.receiver().receiver_generation,
    ));
}
