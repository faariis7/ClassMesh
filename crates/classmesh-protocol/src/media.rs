use core::fmt;

pub const MEDIA_MAGIC: u32 = 0x434D_5631; // "CMV1"
pub const MEDIA_HEADER_LEN: usize = 40;
pub const MAX_PACKET_PAYLOAD: usize = 1_200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaFlags(u16);

impl MediaFlags {
    pub const NONE: Self = Self(0);
    pub const KEYFRAME: Self = Self(1 << 0);
    pub const FRAME_START: Self = Self(1 << 1);
    pub const FRAME_END: Self = Self(1 << 2);
    pub const RETRANSMIT: Self = Self(1 << 3);
    pub const FEC: Self = Self(1 << 4);

    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }
}

impl core::ops::BitOr for MediaFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaPacketHeader {
    pub protocol_major: u8,
    pub protocol_minor: u8,
    pub flags: MediaFlags,
    pub stream_id: u32,
    pub frame_id: u64,
    pub sequence: u32,
    pub packet_index: u16,
    pub packet_count: u16,
    pub timestamp_us: u64,
    pub payload_len: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaHeaderError {
    Truncated,
    BadMagic,
    InvalidPacketCount,
    InvalidPacketIndex,
    PayloadTooLarge,
}

impl fmt::Display for MediaHeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "media header is truncated",
            Self::BadMagic => "media header magic is invalid",
            Self::InvalidPacketCount => "packet count must be non-zero",
            Self::InvalidPacketIndex => "packet index is outside packet count",
            Self::PayloadTooLarge => "packet payload exceeds ClassMesh MTU budget",
        })
    }
}

impl std::error::Error for MediaHeaderError {}

impl MediaPacketHeader {
    pub fn validate(self) -> Result<(), MediaHeaderError> {
        if self.packet_count == 0 {
            return Err(MediaHeaderError::InvalidPacketCount);
        }
        if self.packet_index >= self.packet_count {
            return Err(MediaHeaderError::InvalidPacketIndex);
        }
        if usize::from(self.payload_len) > MAX_PACKET_PAYLOAD {
            return Err(MediaHeaderError::PayloadTooLarge);
        }
        Ok(())
    }

    pub fn encode(self) -> Result<[u8; MEDIA_HEADER_LEN], MediaHeaderError> {
        self.validate()?;
        let mut out = [0_u8; MEDIA_HEADER_LEN];
        out[0..4].copy_from_slice(&MEDIA_MAGIC.to_be_bytes());
        out[4] = self.protocol_major;
        out[5] = self.protocol_minor;
        out[6..8].copy_from_slice(&self.flags.bits().to_be_bytes());
        out[8..12].copy_from_slice(&self.stream_id.to_be_bytes());
        out[12..20].copy_from_slice(&self.frame_id.to_be_bytes());
        out[20..24].copy_from_slice(&self.sequence.to_be_bytes());
        out[24..26].copy_from_slice(&self.packet_index.to_be_bytes());
        out[26..28].copy_from_slice(&self.packet_count.to_be_bytes());
        out[28..36].copy_from_slice(&self.timestamp_us.to_be_bytes());
        out[36..38].copy_from_slice(&self.payload_len.to_be_bytes());
        // 38..40 reserved for future header extension; senders leave it zero.
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Result<Self, MediaHeaderError> {
        if data.len() < MEDIA_HEADER_LEN {
            return Err(MediaHeaderError::Truncated);
        }
        if read_u32(data, 0) != MEDIA_MAGIC {
            return Err(MediaHeaderError::BadMagic);
        }
        let header = Self {
            protocol_major: data[4],
            protocol_minor: data[5],
            flags: MediaFlags::from_bits(read_u16(data, 6)),
            stream_id: read_u32(data, 8),
            frame_id: read_u64(data, 12),
            sequence: read_u32(data, 20),
            packet_index: read_u16(data, 24),
            packet_count: read_u16(data, 26),
            timestamp_us: read_u64(data, 28),
            payload_len: read_u16(data, 36),
        };
        header.validate()?;
        Ok(header)
    }
}

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

    fn sample() -> MediaPacketHeader {
        MediaPacketHeader {
            protocol_major: 0,
            protocol_minor: 1,
            flags: MediaFlags::KEYFRAME | MediaFlags::FRAME_START,
            stream_id: 7,
            frame_id: 44,
            sequence: 100,
            packet_index: 1,
            packet_count: 3,
            timestamp_us: 1_234_567,
            payload_len: 1_000,
        }
    }

    #[test]
    fn media_header_round_trips() {
        let original = sample();
        let bytes = original.encode().expect("sample header must encode");
        let decoded = MediaPacketHeader::decode(&bytes).expect("encoded header must decode");
        assert_eq!(decoded, original);
        assert!(decoded.flags.contains(MediaFlags::KEYFRAME));
    }

    #[test]
    fn malformed_packet_index_is_rejected() {
        let mut header = sample();
        header.packet_index = header.packet_count;
        assert_eq!(header.encode(), Err(MediaHeaderError::InvalidPacketIndex));
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let mut header = sample();
        header.payload_len = 1_201;
        assert_eq!(header.encode(), Err(MediaHeaderError::PayloadTooLarge));
    }
}
