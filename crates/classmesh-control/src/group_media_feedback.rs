use std::error::Error;
use std::fmt::{Display, Formatter};

use classmesh_protocol::control_wire::{
    ControlEnvelope, KeyframeRequest, Nack, ProtocolVersion as WireProtocolVersion,
    control_envelope,
};
use classmesh_protocol::feedback::{FeedbackMessage, MAX_NACK_PACKET_INDICES};
use classmesh_protocol::ProtocolVersion;
use classmesh_security::{AuthorizationStore, Permission, PrincipalId};

use crate::authorization::{AuthenticatedControlGuard, CommandAuthorizationError};
use crate::client_session::ClientControlSession;
use crate::group_media_delivery::{
    TeacherGroupMediaDeliveryError, TeacherGroupMediaDeliveryManager,
};

#[derive(Debug)]
pub enum PresentationFeedbackError {
    InvalidControlSessionId,
    ZeroSequence,
    InvalidExpectedStream,
    InvalidFeedbackStream,
    EmptyNack,
    TooManyMissingPackets,
    PacketIndexOutOfRange,
    UnexpectedPayload,
    CorrelatedRequestUnsupported,
    PeerMismatch,
    StreamMismatch { expected: u32, received: u32 },
    Delivery(TeacherGroupMediaDeliveryError),
    Authorization(CommandAuthorizationError),
}

impl Display for PresentationFeedbackError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidControlSessionId => {
                formatter.write_str("presentation feedback control session id must be non-zero")
            }
            Self::ZeroSequence => {
                formatter.write_str("presentation feedback sequence must be non-zero")
            }
            Self::InvalidExpectedStream => {
                formatter.write_str("expected presentation feedback stream must be non-zero")
            }
            Self::InvalidFeedbackStream => {
                formatter.write_str("presentation feedback stream must be non-zero and fit u32")
            }
            Self::EmptyNack => formatter.write_str("presentation NACK must contain missing packets"),
            Self::TooManyMissingPackets => {
                formatter.write_str("presentation NACK missing-packet list exceeds the bound")
            }
            Self::PacketIndexOutOfRange => {
                formatter.write_str("presentation NACK packet index does not fit u16")
            }
            Self::UnexpectedPayload => {
                formatter.write_str("expected presentation NACK or keyframe request")
            }
            Self::CorrelatedRequestUnsupported => {
                formatter.write_str("presentation feedback must use request_id zero")
            }
            Self::PeerMismatch => {
                formatter.write_str("presentation feedback authenticated peer mismatch")
            }
            Self::StreamMismatch { expected, received } => write!(
                formatter,
                "presentation feedback stream mismatch: expected={expected}, received={received}"
            ),
            Self::Delivery(error) => write!(formatter, "presentation feedback delivery: {error}"),
            Self::Authorization(error) => {
                write!(formatter, "presentation feedback authorization: {error}")
            }
        }
    }
}

impl Error for PresentationFeedbackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Delivery(error) => Some(error),
            Self::Authorization(error) => Some(error),
            _ => None,
        }
    }
}

impl From<TeacherGroupMediaDeliveryError> for PresentationFeedbackError {
    fn from(value: TeacherGroupMediaDeliveryError) -> Self {
        Self::Delivery(value)
    }
}

impl From<CommandAuthorizationError> for PresentationFeedbackError {
    fn from(value: CommandAuthorizationError) -> Self {
        Self::Authorization(value)
    }
}

pub struct PresentationFeedbackRequest<'a> {
    receiver: PrincipalId,
    session: &'a ClientControlSession,
    envelope: &'a ControlEnvelope,
    expected_stream_id: u32,
}

impl<'a> PresentationFeedbackRequest<'a> {
    #[must_use]
    pub const fn new(
        receiver: PrincipalId,
        session: &'a ClientControlSession,
        envelope: &'a ControlEnvelope,
        expected_stream_id: u32,
    ) -> Self {
        Self {
            receiver,
            session,
            envelope,
            expected_stream_id,
        }
    }
}

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

pub fn accept_presentation_feedback(
    delivery: &TeacherGroupMediaDeliveryManager,
    request: PresentationFeedbackRequest<'_>,
    guard: &mut AuthenticatedControlGuard,
    authorization: &AuthorizationStore,
    now_unix_ms: u64,
) -> Result<FeedbackMessage, PresentationFeedbackError> {
    if request.expected_stream_id == 0 {
        return Err(PresentationFeedbackError::InvalidExpectedStream);
    }

    let feedback = feedback_from_envelope(request.envelope)?;

    delivery.validate_registered_client(
        request.receiver,
        request.session,
        authorization,
        now_unix_ms,
    )?;
    if guard.peer().principal_id() != request.receiver {
        return Err(PresentationFeedbackError::PeerMismatch);
    }

    guard.authorize(
        authorization,
        request.envelope,
        Permission::ReceivePresentation,
        now_unix_ms,
    )?;

    if request.envelope.request_id != 0 {
        return Err(PresentationFeedbackError::CorrelatedRequestUnsupported);
    }
    if feedback.stream_id() != request.expected_stream_id {
        return Err(PresentationFeedbackError::StreamMismatch {
            expected: request.expected_stream_id,
            received: feedback.stream_id(),
        });
    }

    Ok(feedback)
}

fn feedback_from_envelope(
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
