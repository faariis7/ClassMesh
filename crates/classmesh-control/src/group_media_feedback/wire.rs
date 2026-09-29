use classmesh_protocol::ProtocolVersion;
use classmesh_protocol::control_wire::{
    ControlEnvelope, KeyframeRequest, Nack, ProtocolVersion as WireProtocolVersion,
    control_envelope,
};
use classmesh_protocol::feedback::{FeedbackMessage, MAX_NACK_PACKET_INDICES};

use super::PresentationFeedbackError;

pub fn build_presentation_feedback_envelope(
    control_session_id: u64,
    protocol_version: ProtocolVersion,
    sequence: u64,
    feedback: &FeedbackMessage,
) -> Result<ControlEnvelope, PresentationFeedbackError> {
    if control_session_id == 0 {
        return Err(PresentationFeedbackError::InvalidControlSessionId);
    }
    if sequence == 0 {
        return Err(PresentationFeedbackError::ZeroSequence);
    }
    validate_feedback(feedback)?;

    let payload = match feedback {
        FeedbackMessage::Nack {
            stream_id,
            frame_id,
            missing_packet_indices,
        } => control_envelope::Payload::Nack(Nack {
            stream_id: u64::from(*stream_id),
            frame_id: *frame_id,
            missing_packet_indices: missing_packet_indices
                .iter()
                .map(|index| u32::from(*index))
                .collect(),
            recovery_deadline_us: 0,
        }),
        FeedbackMessage::RequestKeyframe {
            stream_id,
            after_frame_id,
        } => control_envelope::Payload::KeyframeRequest(KeyframeRequest {
            stream_id: u64::from(*stream_id),
            last_decodable_frame_id: *after_frame_id,
        }),
    };

    Ok(ControlEnvelope {
        control_session_id,
        sequence,
        protocol_version: Some(WireProtocolVersion {
            major: u32::from(protocol_version.major),
            minor: u32::from(protocol_version.minor),
        }),
        request_id: 0,
        payload: Some(payload),
    })
}

pub(super) fn feedback_from_envelope(
    envelope: &ControlEnvelope,
) -> Result<FeedbackMessage, PresentationFeedbackError> {
    match envelope.payload.as_ref() {
        Some(control_envelope::Payload::Nack(nack)) => {
            let stream_id = u32::try_from(nack.stream_id)
                .map_err(|_| PresentationFeedbackError::InvalidFeedbackStream)?;
            if stream_id == 0 {
                return Err(PresentationFeedbackError::InvalidFeedbackStream);
            }
            if nack.missing_packet_indices.is_empty() {
                return Err(PresentationFeedbackError::EmptyNack);
            }
            if nack.missing_packet_indices.len() > MAX_NACK_PACKET_INDICES {
                return Err(PresentationFeedbackError::TooManyMissingPackets);
            }
            let missing_packet_indices = nack
                .missing_packet_indices
                .iter()
                .copied()
                .map(|index| {
                    u16::try_from(index)
                        .map_err(|_| PresentationFeedbackError::PacketIndexOutOfRange)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(FeedbackMessage::Nack {
                stream_id,
                frame_id: nack.frame_id,
                missing_packet_indices,
            })
        }
        Some(control_envelope::Payload::KeyframeRequest(request)) => {
            let stream_id = u32::try_from(request.stream_id)
                .map_err(|_| PresentationFeedbackError::InvalidFeedbackStream)?;
            if stream_id == 0 {
                return Err(PresentationFeedbackError::InvalidFeedbackStream);
            }
            Ok(FeedbackMessage::RequestKeyframe {
                stream_id,
                after_frame_id: request.last_decodable_frame_id,
            })
        }
        _ => Err(PresentationFeedbackError::UnexpectedPayload),
    }
}

fn validate_feedback(feedback: &FeedbackMessage) -> Result<(), PresentationFeedbackError> {
    if feedback.stream_id() == 0 {
        return Err(PresentationFeedbackError::InvalidFeedbackStream);
    }
    if let FeedbackMessage::Nack {
        missing_packet_indices,
        ..
    } = feedback
    {
        if missing_packet_indices.is_empty() {
            return Err(PresentationFeedbackError::EmptyNack);
        }
        if missing_packet_indices.len() > MAX_NACK_PACKET_INDICES {
            return Err(PresentationFeedbackError::TooManyMissingPackets);
        }
    }
    Ok(())
}
