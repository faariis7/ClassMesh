//! Contract for a fixed-space byte-stream reader behind an independently
//! authenticated Windows Worker pipe. Parsing never grants Service authority.
use classmesh_control::receiver_telemetry::{
    ReceiverPlaybackCounters, ReceiverTelemetryBinding, ReceiverTelemetryDecision,
    ReceiverTelemetrySnapshot,
};
use classmesh_control::receiver_telemetry_ingress::ReceiverTelemetryIngress;
use classmesh_control::receiver_telemetry_stream_framing::{
    MAX_RECEIVER_TELEMETRY_READ_BYTES, ReceiverTelemetryFrameStream,
    ReceiverTelemetryFrameStreamError,
};
use classmesh_control::receiver_telemetry_transport::{
    RECEIVER_TELEMETRY_WIRE_LEN, ReceiverTelemetryWireError, encode_receiver_telemetry,
};
use std::time::Instant;

fn binding(receiver_generation: u64) -> ReceiverTelemetryBinding {
    ReceiverTelemetryBinding {
        process_id: 1001,
        session_id: 7,
        worker_generation: 10,
        control_session_id: 30,
        request_id: 31,
        presentation_id: 32,
        stream_id: 33,
        epoch: 34,
        receiver_generation,
    }
}

fn frame(owner: ReceiverTelemetryBinding, sequence: u64) -> [u8; RECEIVER_TELEMETRY_WIRE_LEN] {
    encode_receiver_telemetry(&ReceiverTelemetrySnapshot {
        binding: owner,
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
fn splits_one_native_pipe_frame_at_every_byte_boundary() {
    let owner = binding(1);
    let bytes = frame(owner, 1);
    for split in 1..RECEIVER_TELEMETRY_WIRE_LEN {
        let mut reader = ReceiverTelemetryFrameStream::default();
        reader.activate_verified(owner).unwrap();
        assert!(
            reader
                .accept_verified(owner, &bytes[..split])
                .unwrap()
                .is_empty()
        );
        let reports = reader.accept_verified(owner, &bytes[split..]).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].binding, owner);
        assert_eq!(reports[0].sequence, 1);
    }
}

#[test]
fn coalesced_frames_are_bounded_and_decode_in_order() {
    let owner = binding(1);
    let mut reader = ReceiverTelemetryFrameStream::default();
    reader.activate_verified(owner).unwrap();
    let bytes: Vec<u8> = (1..=4)
        .flat_map(|sequence| frame(owner, sequence))
        .collect();
    assert_eq!(bytes.len(), MAX_RECEIVER_TELEMETRY_READ_BYTES);
    let reports = reader.accept_verified(owner, &bytes).unwrap();
    assert_eq!(
        reports
            .iter()
            .map(|report| report.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert!(
        reader
            .accept_verified(owner, &frame(owner, 5)[..1])
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        reader
            .accept_verified(owner, &frame(owner, 5)[1..])
            .unwrap()[0]
            .sequence,
        5
    );
}

#[test]
fn max_read_after_partial_keeps_four_frame_limit_and_one_partial() {
    let owner = binding(1);
    let mut stream = ReceiverTelemetryFrameStream::default();
    stream.activate_verified(owner).unwrap();
    let first = frame(owner, 1);
    assert!(
        stream
            .accept_verified(owner, &first[..135])
            .unwrap()
            .is_empty()
    );
    // A 544-byte read combined with 135 buffered bytes can finish at most
    // four full frames, retaining no more than 135 bytes of the next frame.
    let next: Vec<u8> = [
        first[135..].to_vec(),
        (2..=4)
            .flat_map(|seq| frame(owner, seq))
            .collect::<Vec<_>>(),
        frame(owner, 5)[..135].to_vec(),
    ]
    .concat();
    assert_eq!(next.len(), MAX_RECEIVER_TELEMETRY_READ_BYTES);
    let reports = stream.accept_verified(owner, &next).unwrap();
    assert_eq!(
        reports.iter().map(|r| r.sequence).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert_eq!(
        stream
            .accept_verified(owner, &frame(owner, 5)[135..])
            .unwrap()[0]
            .sequence,
        5
    );
}

#[test]
fn parsing_does_not_authorize_service_telemetry() {
    let owner = binding(1);
    let mut stream = ReceiverTelemetryFrameStream::default();
    let mut service = ReceiverTelemetryIngress::default();
    stream.activate_verified(owner).unwrap();
    let first = stream.accept_verified(owner, &frame(owner, 1)).unwrap();
    assert_eq!(first.len(), 1);
    assert!(!service.has_fresh_report(Instant::now()));
    // The independently trusted Service owner still has to activate the
    // existing admission gate and make replay/continuity decisions itself.
    service.activate_verified(owner).unwrap();
    assert_eq!(
        service.observe_verified(&frame(owner, 1), Instant::now()),
        Ok(ReceiverTelemetryDecision::Baseline)
    );
}

#[test]
fn same_owner_refresh_does_not_erase_a_partial_frame() {
    let owner = binding(1);
    let frame = frame(owner, 1);
    let mut stream = ReceiverTelemetryFrameStream::default();
    stream.activate_verified(owner).unwrap();
    assert!(
        stream
            .accept_verified(owner, &frame[..75])
            .unwrap()
            .is_empty()
    );
    stream.activate_verified(owner).unwrap();
    let reports = stream.accept_verified(owner, &frame[75..]).unwrap();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].sequence, 1);
}

#[test]
fn replacement_revokes_partial_data_and_old_teardown_cannot_revoke_new_owner() {
    let old = binding(1);
    let new = binding(2);
    let mut stream = ReceiverTelemetryFrameStream::default();
    stream.activate_verified(old).unwrap();
    assert!(
        stream
            .accept_verified(old, &frame(old, 1)[..85])
            .unwrap()
            .is_empty()
    );
    stream.activate_verified(new).unwrap();
    assert!(!stream.clear_if_matches(old));
    assert_eq!(
        stream.accept_verified(old, &frame(old, 1)),
        Err(ReceiverTelemetryFrameStreamError::WrongServiceOwner)
    );
    assert!(
        stream
            .accept_verified(new, &frame(new, 1)[..85])
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        stream.accept_verified(new, &frame(new, 1)[85..]).unwrap()[0].binding,
        new
    );
    assert!(stream.clear_if_matches(new));
    assert_eq!(
        stream.accept_verified(new, &frame(new, 2)),
        Err(ReceiverTelemetryFrameStreamError::Inactive)
    );
}

#[test]
fn wrong_service_owner_never_spends_or_mutates_pending_data() {
    let owner = binding(1);
    let mut stream = ReceiverTelemetryFrameStream::default();
    stream.activate_verified(owner).unwrap();
    let bytes = frame(owner, 1);
    assert!(
        stream
            .accept_verified(owner, &bytes[..40])
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        stream.accept_verified(binding(2), &bytes[40..]),
        Err(ReceiverTelemetryFrameStreamError::WrongServiceOwner)
    );
    let completed = stream.accept_verified(owner, &bytes[40..]).unwrap();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].sequence, 1);
}

#[test]
fn malformed_complete_frame_fails_closed_and_drops_partial_or_valid_batch() {
    let owner = binding(1);
    let mut stream = ReceiverTelemetryFrameStream::default();
    stream.activate_verified(owner).unwrap();
    let mut malformed = frame(owner, 2);
    malformed[0] ^= 0xff;
    let payload = [frame(owner, 1).as_slice(), malformed.as_slice()].concat();
    assert_eq!(
        stream.accept_verified(owner, &payload),
        Err(ReceiverTelemetryFrameStreamError::Wire(
            ReceiverTelemetryWireError::BadMagic
        ))
    );
    assert_eq!(
        stream.accept_verified(owner, &frame(owner, 3)),
        Err(ReceiverTelemetryFrameStreamError::Inactive)
    );
}

#[test]
fn forged_receiver_binding_is_rejected_without_emitting_a_sample() {
    let owner = binding(1);
    let mut stream = ReceiverTelemetryFrameStream::default();
    stream.activate_verified(owner).unwrap();
    assert_eq!(
        stream.accept_verified(owner, &frame(binding(2), 1)),
        Err(ReceiverTelemetryFrameStreamError::ReportBindingMismatch)
    );
    assert_eq!(
        stream.accept_verified(owner, &frame(owner, 1)),
        Err(ReceiverTelemetryFrameStreamError::Inactive)
    );
}

#[test]
fn empty_pipe_read_and_excessive_coalescing_close_current_reader() {
    let owner = binding(1);
    let mut stream = ReceiverTelemetryFrameStream::default();
    stream.activate_verified(owner).unwrap();
    assert_eq!(
        stream.accept_verified(owner, &[]),
        Err(ReceiverTelemetryFrameStreamError::Disconnected)
    );
    assert_eq!(
        stream.accept_verified(owner, &frame(owner, 1)),
        Err(ReceiverTelemetryFrameStreamError::Inactive)
    );
    stream.activate_verified(owner).unwrap();
    assert_eq!(
        stream.accept_verified(owner, &vec![1_u8; MAX_RECEIVER_TELEMETRY_READ_BYTES + 1]),
        Err(ReceiverTelemetryFrameStreamError::OversizedRead)
    );
    assert_eq!(
        stream.accept_verified(owner, &frame(owner, 1)),
        Err(ReceiverTelemetryFrameStreamError::Inactive)
    );
}

#[test]
fn invalid_service_binding_cannot_arm_reader() {
    let mut stream = ReceiverTelemetryFrameStream::default();
    let mut invalid = binding(1);
    invalid.process_id = 0;
    assert_eq!(
        stream.activate_verified(invalid),
        Err(ReceiverTelemetryFrameStreamError::InvalidBinding)
    );
    assert_eq!(
        stream.accept_verified(invalid, &frame(binding(1), 1)),
        Err(ReceiverTelemetryFrameStreamError::Inactive)
    );
}
