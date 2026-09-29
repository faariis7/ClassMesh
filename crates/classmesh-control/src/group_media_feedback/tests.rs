use classmesh_protocol::ProtocolVersion;
use classmesh_protocol::control_wire::{Nack, ProtocolVersion as WireProtocolVersion, control_envelope};
use classmesh_protocol::feedback::{FeedbackMessage, MAX_NACK_PACKET_INDICES};

use super::{PresentationFeedbackError, build_presentation_feedback_envelope};

const VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 4 };

#[test]
fn outbound_nack_uses_uncorrelated_session_envelope() {
    let feedback = FeedbackMessage::Nack {
        stream_id: 7,
        frame_id: 41,
        missing_packet_indices: vec![0, 3, 9],
    };
    let envelope =
        build_presentation_feedback_envelope(77, VERSION, 5, &feedback).expect("valid NACK");

    assert_eq!(envelope.control_session_id, 77);
    assert_eq!(envelope.sequence, 5);
    assert_eq!(envelope.request_id, 0);
    assert_eq!(
        envelope.protocol_version,
        Some(WireProtocolVersion { major: 0, minor: 4 })
    );
    assert!(matches!(
        envelope.payload,
        Some(control_envelope::Payload::Nack(Nack {
            stream_id: 7,
            frame_id: 41,
            missing_packet_indices,
            recovery_deadline_us: 0,
        })) if missing_packet_indices == vec![0, 3, 9]
    ));
}

#[test]
fn outbound_feedback_rejects_invalid_stream_and_nack_bounds() {
    assert!(matches!(
        build_presentation_feedback_envelope(
            77,
            VERSION,
            2,
            &FeedbackMessage::RequestKeyframe {
                stream_id: 0,
                after_frame_id: 1,
            },
        ),
        Err(PresentationFeedbackError::InvalidFeedbackStream)
    ));
    assert!(matches!(
        build_presentation_feedback_envelope(
            77,
            VERSION,
            2,
            &FeedbackMessage::Nack {
                stream_id: 7,
                frame_id: 1,
                missing_packet_indices: Vec::new(),
            },
        ),
        Err(PresentationFeedbackError::EmptyNack)
    ));
    assert!(matches!(
        build_presentation_feedback_envelope(
            77,
            VERSION,
            2,
            &FeedbackMessage::Nack {
                stream_id: 7,
                frame_id: 1,
                missing_packet_indices: vec![1; MAX_NACK_PACKET_INDICES + 1],
            },
        ),
        Err(PresentationFeedbackError::TooManyMissingPackets)
    ));
}
