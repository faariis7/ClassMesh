use classmesh_control::receiver_telemetry::{
    ReceiverPlaybackCounters, ReceiverTelemetryBinding, ReceiverTelemetrySnapshot,
};
use classmesh_control::receiver_telemetry_transport::{
    ReceiverTelemetryMailbox, ReceiverTelemetryWireError, decode_receiver_telemetry,
    encode_receiver_telemetry, RECEIVER_TELEMETRY_WIRE_LEN,
};

fn binding(epoch: u32) -> ReceiverTelemetryBinding {
    ReceiverTelemetryBinding {
        process_id: 101,
        session_id: 22,
        worker_generation: 3,
        control_session_id: 4,
        request_id: 5,
        presentation_id: 6,
        stream_id: 7,
        epoch,
        receiver_generation: 8,
    }
}

fn sample(epoch: u32, sequence: u64) -> ReceiverTelemetrySnapshot {
    ReceiverTelemetrySnapshot {
        binding: binding(epoch),
        sequence,
        counters: ReceiverPlaybackCounters {
            authenticated_frames: 201,
            rejected_frames: 9,
            decoded_frames: 175,
            presented_frames: 160,
            present_errors: 4,
            decode_errors: 3,
            keyframe_waits: 5,
            queue_drops: 12,
        },
    }
}

#[test]
fn fixed_width_versioned_payload_preserves_distinct_counter_meanings() {
    let original = sample(1, 13);
    let encoded = encode_receiver_telemetry(&original).unwrap();
    assert_eq!(encoded.len(), RECEIVER_TELEMETRY_WIRE_LEN);
    assert_eq!(&encoded[..4], b"CMRT");
    assert_eq!(decode_receiver_telemetry(&encoded), Ok(original));
    assert_ne!(
        original.counters.authenticated_frames,
        original.counters.presented_frames
    );
}

#[test]
fn malformed_header_reserved_bytes_or_trailing_content_fail_closed() {
    let baseline = encode_receiver_telemetry(&sample(1, 1)).unwrap();
    for len in [0, 1, 7, RECEIVER_TELEMETRY_WIRE_LEN - 1] {
        assert_eq!(
            decode_receiver_telemetry(&baseline[..len]),
            Err(ReceiverTelemetryWireError::InvalidLength)
        );
    }
    let mut longer = baseline.to_vec();
    longer.push(0);
    assert_eq!(
        decode_receiver_telemetry(&longer),
        Err(ReceiverTelemetryWireError::InvalidLength)
    );
    let mut bad_magic = baseline;
    bad_magic[0] ^= 1;
    assert_eq!(
        decode_receiver_telemetry(&bad_magic),
        Err(ReceiverTelemetryWireError::BadMagic)
    );
    let mut bad_version = baseline;
    bad_version[5] = 2;
    assert_eq!(
        decode_receiver_telemetry(&bad_version),
        Err(ReceiverTelemetryWireError::UnsupportedVersion(2))
    );
    let mut bad_reserved = baseline;
    bad_reserved[7] = 1;
    assert_eq!(
        decode_receiver_telemetry(&bad_reserved),
        Err(ReceiverTelemetryWireError::NonzeroReserved)
    );
}

#[test]
fn invalid_binding_and_zero_sequence_reject_on_both_boundaries() {
    let mut no_worker = sample(1, 1);
    no_worker.binding.worker_generation = 0;
    assert_eq!(
        encode_receiver_telemetry(&no_worker),
        Err(ReceiverTelemetryWireError::InvalidBinding)
    );
    let mut no_sequence = sample(1, 0);
    assert_eq!(
        encode_receiver_telemetry(&no_sequence),
        Err(ReceiverTelemetryWireError::InvalidSequence)
    );
    let mut bad_wire = encode_receiver_telemetry(&sample(1, 1)).unwrap();
    // Worker-generation offset is 8-byte header + pid + session = 16.
    bad_wire[16..24].fill(0);
    assert_eq!(
        decode_receiver_telemetry(&bad_wire),
        Err(ReceiverTelemetryWireError::InvalidBinding)
    );
    no_sequence.sequence = 1;
    let mut sequence_wire = encode_receiver_telemetry(&no_sequence).unwrap();
    // Header 8 + exact identity binding 56 = 64.
    sequence_wire[64..72].fill(0);
    assert_eq!(
        decode_receiver_telemetry(&sequence_wire),
        Err(ReceiverTelemetryWireError::InvalidSequence)
    );
}

#[test]
fn mailbox_is_latest_only_and_has_no_unbounded_backlog() {
    let mut mailbox = ReceiverTelemetryMailbox::default();
    mailbox.activate(binding(1)).unwrap();
    assert!(!mailbox.offer(sample(1, 1)).unwrap());
    for sequence in 2..=10_000 {
        assert!(mailbox.offer(sample(1, sequence)).unwrap());
    }
    assert_eq!(mailbox.take_matching(binding(1)).unwrap().sequence, 10_000);
    assert!(mailbox.take_matching(binding(1)).is_none());
}

#[test]
fn mailbox_does_not_rearm_on_identical_activation_or_allow_replayed_reports() {
    let mut mailbox = ReceiverTelemetryMailbox::default();
    mailbox.activate(binding(1)).unwrap();
    mailbox.offer(sample(1, 1)).unwrap();
    mailbox.activate(binding(1)).unwrap();
    assert_eq!(
        mailbox.offer(sample(1, 1)),
        Err(ReceiverTelemetryWireError::NonmonotonicSequence)
    );
    assert_eq!(mailbox.take_matching(binding(1)).unwrap().sequence, 1);
    assert_eq!(
        mailbox.offer(sample(1, 1)),
        Err(ReceiverTelemetryWireError::NonmonotonicSequence)
    );
    assert!(!mailbox.offer(sample(1, 2)).unwrap());
}

#[test]
fn inactive_and_old_generation_reports_cannot_be_emitted_or_revoke_new_one() {
    let mut mailbox = ReceiverTelemetryMailbox::default();
    assert_eq!(
        mailbox.offer(sample(1, 1)),
        Err(ReceiverTelemetryWireError::Inactive)
    );
    mailbox.activate(binding(1)).unwrap();
    mailbox.offer(sample(1, 1)).unwrap();
    mailbox.activate(binding(2)).unwrap();
    assert!(mailbox.take_matching(binding(1)).is_none());
    assert!(!mailbox.clear_if_matches(binding(1)));
    assert_eq!(
        mailbox.offer(sample(1, 2)),
        Err(ReceiverTelemetryWireError::BindingMismatch)
    );
    assert!(!mailbox.offer(sample(2, 1)).unwrap());
    assert_eq!(mailbox.take_matching(binding(2)).unwrap().sequence, 1);
    assert!(mailbox.clear_if_matches(binding(2)));
    assert_eq!(
        mailbox.offer(sample(2, 2)),
        Err(ReceiverTelemetryWireError::Inactive)
    );
}

#[test]
fn invalid_sequence_or_binding_cannot_poison_latest_valid_pending_report() {
    let mut mailbox = ReceiverTelemetryMailbox::default();
    mailbox.activate(binding(1)).unwrap();
    mailbox.offer(sample(1, 4)).unwrap();
    assert_eq!(
        mailbox.offer(sample(1, 0)),
        Err(ReceiverTelemetryWireError::InvalidSequence)
    );
    assert_eq!(
        mailbox.offer(sample(1, 3)),
        Err(ReceiverTelemetryWireError::NonmonotonicSequence)
    );
    assert_eq!(mailbox.take_matching(binding(1)).unwrap().sequence, 4);
}
