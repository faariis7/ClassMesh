use std::error::Error;
use std::fmt::{Display, Formatter};

use crate::authorization::CommandAuthorizationError;
use crate::group_media_delivery::TeacherGroupMediaDeliveryError;

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
