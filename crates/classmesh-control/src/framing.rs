use std::error::Error;
use std::fmt::{Display, Formatter};

use classmesh_protocol::control_wire::ControlEnvelope;
use prost::Message;
use zeroize::Zeroizing;

pub const CONTROL_LENGTH_PREFIX_BYTES: usize = 4;
pub const MAX_CONTROL_MESSAGE_BYTES: usize = 256 * 1024;

#[derive(Debug)]
pub enum FrameError {
    EmptyMessage,
    MessageTooLarge { length: usize, maximum: usize },
    LengthMismatch { declared: usize, actual: usize },
    Decode(prost::DecodeError),
}

impl Display for FrameError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyMessage => write!(formatter, "control message payload must not be empty"),
            Self::MessageTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "control message payload is {length} bytes; maximum is {maximum}"
                )
            }
            Self::LengthMismatch { declared, actual } => {
                write!(
                    formatter,
                    "control frame declares {declared} payload bytes but contains {actual}"
                )
            }
            Self::Decode(error) => write!(formatter, "invalid control protobuf: {error}"),
        }
    }
}

impl Error for FrameError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Decode(error) => Some(error),
            _ => None,
        }
    }
}

impl From<prost::DecodeError> for FrameError {
    fn from(error: prost::DecodeError) -> Self {
        Self::Decode(error)
    }
}

#[must_use]
pub fn encoded_payload_len(envelope: &ControlEnvelope) -> usize {
    envelope.encoded_len()
}

pub fn validate_payload_len(length: usize) -> Result<(), FrameError> {
    if length == 0 {
        return Err(FrameError::EmptyMessage);
    }
    if length > MAX_CONTROL_MESSAGE_BYTES {
        return Err(FrameError::MessageTooLarge {
            length,
            maximum: MAX_CONTROL_MESSAGE_BYTES,
        });
    }
    Ok(())
}

pub fn encode_frame(envelope: &ControlEnvelope) -> Result<Vec<u8>, FrameError> {
    let length = encoded_payload_len(envelope);
    validate_payload_len(length)?;

    let length_u32 = u32::try_from(length).map_err(|_| FrameError::MessageTooLarge {
        length,
        maximum: MAX_CONTROL_MESSAGE_BYTES,
    })?;

    // Protobuf payloads can contain transient secrets (for example Phase 7E
    // group-media key grants). Keep the intermediate encoded allocation
    // zeroizing even though the returned frame remains caller-owned.
    let payload = Zeroizing::new(envelope.encode_to_vec());
    debug_assert_eq!(payload.len(), length);

    let mut frame = Vec::with_capacity(CONTROL_LENGTH_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&length_u32.to_be_bytes());
    frame.extend_from_slice(payload.as_slice());
    Ok(frame)
}

pub fn declared_payload_len(
    prefix: [u8; CONTROL_LENGTH_PREFIX_BYTES],
) -> Result<usize, FrameError> {
    let length = u32::from_be_bytes(prefix) as usize;
    validate_payload_len(length)?;
    Ok(length)
}

pub fn decode_frame(frame: &[u8]) -> Result<ControlEnvelope, FrameError> {
    if frame.len() < CONTROL_LENGTH_PREFIX_BYTES {
        return Err(FrameError::LengthMismatch {
            declared: CONTROL_LENGTH_PREFIX_BYTES,
            actual: frame.len(),
        });
    }

    let prefix: [u8; CONTROL_LENGTH_PREFIX_BYTES] = frame[..CONTROL_LENGTH_PREFIX_BYTES]
        .try_into()
        .expect("length prefix size is fixed");
    let declared = declared_payload_len(prefix)?;
    let payload = &frame[CONTROL_LENGTH_PREFIX_BYTES..];
    if payload.len() != declared {
        return Err(FrameError::LengthMismatch {
            declared,
            actual: payload.len(),
        });
    }

    Ok(ControlEnvelope::decode(payload)?)
}

#[cfg(test)]
mod tests {
    use classmesh_protocol::control_wire::{
        ControlEnvelope, Heartbeat, ProtocolVersion, control_envelope,
    };

    use super::*;

    fn heartbeat_envelope() -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: 7,
            sequence: 11,
            protocol_version: Some(ProtocolVersion { major: 0, minor: 1 }),
            request_id: 0,
            payload: Some(control_envelope::Payload::Heartbeat(Heartbeat {
                monotonic_time_us: 99,
                control_session_id: 7,
                media: 3,
            })),
        }
    }

    #[test]
    fn bounded_frame_round_trips() {
        let envelope = heartbeat_envelope();
        let frame = encode_frame(&envelope).expect("valid envelope should encode");
        let decoded = decode_frame(&frame).expect("valid frame should decode");

        assert_eq!(decoded.control_session_id, 7);
        assert_eq!(decoded.sequence, 11);
    }

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let prefix = u32::try_from(MAX_CONTROL_MESSAGE_BYTES + 1)
            .expect("test size fits in u32")
            .to_be_bytes();
        assert!(matches!(
            declared_payload_len(prefix),
            Err(FrameError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn zero_length_frame_is_rejected() {
        assert!(matches!(
            declared_payload_len(0_u32.to_be_bytes()),
            Err(FrameError::EmptyMessage)
        ));
    }

    #[test]
    fn malformed_protobuf_is_rejected_after_length_validation() {
        let payload = [0xff_u8];
        let mut frame = Vec::with_capacity(CONTROL_LENGTH_PREFIX_BYTES + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);

        assert!(matches!(decode_frame(&frame), Err(FrameError::Decode(_))));
    }

    #[test]
    fn declared_length_must_match_payload() {
        let mut frame = encode_frame(&heartbeat_envelope()).expect("frame should encode");
        frame.pop();
        assert!(matches!(
            decode_frame(&frame),
            Err(FrameError::LengthMismatch { .. })
        ));
    }
}
