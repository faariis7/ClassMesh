use core::fmt;

use crate::PROTOCOL_VERSION;

pub const FEEDBACK_MAGIC: u32 = 0x434D_4631; // "CMF1"
pub const FEEDBACK_HEADER_LEN: usize = 24;
pub const MAX_NACK_PACKET_INDICES: usize = 64;

const KIND_NACK: u8 = 1;
const KIND_REQUEST_KEYFRAME: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedbackMessage {
    Nack {
        stream_id: u32,
        frame_id: u64,
        missing_packet_indices: Vec<u16>,
    },
    RequestKeyframe {
        stream_id: u32,
        after_frame_id: u64,
    },
}

impl FeedbackMessage {
    #[must_use]
    pub const fn stream_id(&self) -> u32 {
        match self {
            Self::Nack { stream_id, .. } | Self::RequestKeyframe { stream_id, .. } => *stream_id,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, FeedbackCodecError> {
        let major = u8::try_from(PROTOCOL_VERSION.major)
            .map_err(|_| FeedbackCodecError::VersionOutOfRange)?;
        let minor = u8::try_from(PROTOCOL_VERSION.minor)
            .map_err(|_| FeedbackCodecError::VersionOutOfRange)?;

        let (kind, stream_id, frame_id, missing): (u8, u32, u64, &[u16]) = match self {
            Self::Nack {
                stream_id,
                frame_id,
                missing_packet_indices,
            } => {
                if missing_packet_indices.is_empty() {
                    return Err(FeedbackCodecError::EmptyNack);
                }
                if missing_packet_indices.len() > MAX_NACK_PACKET_INDICES {
                    return Err(FeedbackCodecError::TooManyMissingPackets);
                }
                (KIND_NACK, *stream_id, *frame_id, missing_packet_indices)
            }
            Self::RequestKeyframe {
                stream_id,
                after_frame_id,
            } => (KIND_REQUEST_KEYFRAME, *stream_id, *after_frame_id, &[]),
        };

        let count = u16::try_from(missing.len())
            .map_err(|_| FeedbackCodecError::TooManyMissingPackets)?;
        let payload_len = missing.len().saturating_mul(2);
        let mut encoded = vec![0_u8; FEEDBACK_HEADER_LEN.saturating_add(payload_len)];
        encoded[0..4].copy_from_slice(&FEEDBACK_MAGIC.to_be_bytes());
        encoded[4] = major;
        encoded[5] = minor;
        encoded[6] = kind;
        encoded[7] = 0;
        encoded[8..12].copy_from_slice(&stream_id.to_be_bytes());
        encoded[12..20].copy_from_slice(&frame_id.to_be_bytes());
        encoded[20..22].copy_from_slice(&count.to_be_bytes());
        encoded[22..24].fill(0);

        for (index, packet_index) in missing.iter().enumerate() {
            let offset = FEEDBACK_HEADER_LEN + index * 2;
            encoded[offset..offset + 2].copy_from_slice(&packet_index.to_be_bytes());
        }

        Ok(encoded)
    }

    pub fn decode(data: &[u8]) -> Result<Self, FeedbackCodecError> {
        if data.len() < FEEDBACK_HEADER_LEN {
            return Err(FeedbackCodecError::Truncated);
        }
        if read_u32(data, 0) != FEEDBACK_MAGIC {
            return Err(FeedbackCodecError::BadMagic);
        }

        let expected_major = u8::try_from(PROTOCOL_VERSION.major)
            .map_err(|_| FeedbackCodecError::VersionOutOfRange)?;
        if data[4] != expected_major {
            return Err(FeedbackCodecError::IncompatibleMajorVersion {
                received: data[4],
                expected: expected_major,
            });
        }

        let kind = data[6];
        let stream_id = read_u32(data, 8);
        let frame_id = read_u64(data, 12);
        let count = usize::from(read_u16(data, 20));
        if count > MAX_NACK_PACKET_INDICES {
            return Err(FeedbackCodecError::TooManyMissingPackets);
        }
        let expected_len = FEEDBACK_HEADER_LEN.saturating_add(count.saturating_mul(2));
        if data.len() != expected_len {
            return Err(FeedbackCodecError::LengthMismatch);
        }

        match kind {
            KIND_NACK => {
                if count == 0 {
                    return Err(FeedbackCodecError::EmptyNack);
                }
                let mut missing_packet_indices = Vec::with_capacity(count);
                for index in 0..count {
                    let offset = FEEDBACK_HEADER_LEN + index * 2;
                    missing_packet_indices.push(read_u16(data, offset));
                }
                Ok(Self::Nack {
                    stream_id,
                    frame_id,
                    missing_packet_indices,
                })
            }
            KIND_REQUEST_KEYFRAME => {
                if count != 0 {
                    return Err(FeedbackCodecError::LengthMismatch);
                }
                Ok(Self::RequestKeyframe {
                    stream_id,
                    after_frame_id: frame_id,
                })
            }
            value => Err(FeedbackCodecError::UnknownKind(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackCodecError {
    Truncated,
    BadMagic,
    VersionOutOfRange,
    IncompatibleMajorVersion { received: u8, expected: u8 },
    UnknownKind(u8),
    EmptyNack,
    TooManyMissingPackets,
    LengthMismatch,
}

impl fmt::Display for FeedbackCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("feedback datagram is truncated"),
            Self::BadMagic => formatter.write_str("feedback datagram magic is invalid"),
            Self::VersionOutOfRange => {
                formatter.write_str("protocol version does not fit feedback wire format")
            }
            Self::IncompatibleMajorVersion { received, expected } => write!(
                formatter,
                "feedback protocol major version {received} is incompatible with {expected}"
            ),
            Self::UnknownKind(value) => write!(formatter, "unknown feedback message kind {value}"),
            Self::EmptyNack => formatter.write_str("NACK must contain at least one packet index"),
            Self::TooManyMissingPackets => formatter.write_str("NACK packet-index list is too large"),
            Self::LengthMismatch => formatter.write_str("feedback datagram length is inconsistent"),
        }
    }
}

impl std::error::Error for FeedbackCodecError {}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nack_round_trips() {
        let message = FeedbackMessage::Nack {
            stream_id: 9,
            frame_id: 42,
            missing_packet_indices: vec![0, 3, 17],
        };
        let encoded = message.encode().expect("NACK encodes");
        assert_eq!(FeedbackMessage::decode(&encoded), Ok(message));
    }

    #[test]
    fn keyframe_request_round_trips() {
        let message = FeedbackMessage::RequestKeyframe {
            stream_id: 9,
            after_frame_id: 42,
        };
        let encoded = message.encode().expect("keyframe request encodes");
        assert_eq!(FeedbackMessage::decode(&encoded), Ok(message));
    }

    #[test]
    fn malformed_lengths_and_versions_are_rejected() {
        let message = FeedbackMessage::RequestKeyframe {
            stream_id: 1,
            after_frame_id: 2,
        };
        let mut encoded = message.encode().expect("keyframe request encodes");
        encoded.push(0);
        assert_eq!(
            FeedbackMessage::decode(&encoded),
            Err(FeedbackCodecError::LengthMismatch)
        );

        let mut encoded = message.encode().expect("keyframe request encodes");
        encoded[4] = encoded[4].wrapping_add(1);
        assert!(matches!(
            FeedbackMessage::decode(&encoded),
            Err(FeedbackCodecError::IncompatibleMajorVersion { .. })
        ));
    }

    #[test]
    fn nack_size_is_bounded() {
        let message = FeedbackMessage::Nack {
            stream_id: 1,
            frame_id: 2,
            missing_packet_indices: vec![1; MAX_NACK_PACKET_INDICES + 1],
        };
        assert_eq!(
            message.encode(),
            Err(FeedbackCodecError::TooManyMissingPackets)
        );
    }
}
