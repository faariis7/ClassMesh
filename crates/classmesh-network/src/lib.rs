#![forbid(unsafe_code)]

pub mod receiver;
pub mod reliability;
pub mod transport;
pub mod udp;

use classmesh_protocol::media::{
    MAX_PACKET_PAYLOAD, MediaFlags, MediaHeaderError, MediaPacketHeader,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaPacket {
    pub header: MediaPacketHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketizeMeta {
    pub protocol_major: u8,
    pub protocol_minor: u8,
    pub stream_id: u32,
    pub frame_id: u64,
    pub first_sequence: u32,
    pub timestamp_us: u64,
    pub keyframe: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketizeError {
    EmptyFrame,
    TooManyPackets,
    Header(MediaHeaderError),
}

impl From<MediaHeaderError> for PacketizeError {
    fn from(value: MediaHeaderError) -> Self {
        Self::Header(value)
    }
}

pub fn packetize_frame(
    frame: &[u8],
    meta: PacketizeMeta,
) -> Result<Vec<MediaPacket>, PacketizeError> {
    if frame.is_empty() {
        return Err(PacketizeError::EmptyFrame);
    }

    let packet_count = frame.len().div_ceil(MAX_PACKET_PAYLOAD);
    let packet_count_u16 =
        u16::try_from(packet_count).map_err(|_| PacketizeError::TooManyPackets)?;
    let mut packets = Vec::with_capacity(packet_count);

    for (index, chunk) in frame.chunks(MAX_PACKET_PAYLOAD).enumerate() {
        let packet_index = u16::try_from(index).map_err(|_| PacketizeError::TooManyPackets)?;
        let mut flags = MediaFlags::NONE;
        if meta.keyframe {
            flags = flags | MediaFlags::KEYFRAME;
        }
        if packet_index == 0 {
            flags = flags | MediaFlags::FRAME_START;
        }
        if packet_index + 1 == packet_count_u16 {
            flags = flags | MediaFlags::FRAME_END;
        }
        let sequence = meta
            .first_sequence
            .wrapping_add(u32::try_from(index).unwrap_or(u32::MAX));
        let payload_len = u16::try_from(chunk.len()).map_err(|_| PacketizeError::TooManyPackets)?;
        let header = MediaPacketHeader {
            protocol_major: meta.protocol_major,
            protocol_minor: meta.protocol_minor,
            flags,
            stream_id: meta.stream_id,
            frame_id: meta.frame_id,
            sequence,
            packet_index,
            packet_count: packet_count_u16,
            timestamp_us: meta.timestamp_us,
            payload_len,
        };
        header.validate()?;
        packets.push(MediaPacket {
            header,
            payload: chunk.to_vec(),
        });
    }

    Ok(packets)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssembleError {
    WrongFrame,
    WrongStream,
    PacketCountChanged,
    PayloadLengthMismatch,
    DuplicatePacketConflict,
}

#[derive(Debug)]
pub struct FrameAssembler {
    stream_id: u32,
    frame_id: u64,
    timestamp_us: u64,
    keyframe: bool,
    packets: Vec<Option<Vec<u8>>>,
    received: usize,
}

impl FrameAssembler {
    #[must_use]
    pub fn from_first(packet: &MediaPacket) -> Self {
        let count = usize::from(packet.header.packet_count);
        Self {
            stream_id: packet.header.stream_id,
            frame_id: packet.header.frame_id,
            timestamp_us: packet.header.timestamp_us,
            keyframe: packet.header.flags.contains(MediaFlags::KEYFRAME),
            packets: vec![None; count],
            received: 0,
        }
    }

    #[must_use]
    pub(crate) const fn stream_id_for_receiver(&self) -> u32 {
        self.stream_id
    }

    pub fn push(&mut self, packet: &MediaPacket) -> Result<(), AssembleError> {
        if packet.header.frame_id != self.frame_id {
            return Err(AssembleError::WrongFrame);
        }
        if packet.header.stream_id != self.stream_id {
            return Err(AssembleError::WrongStream);
        }
        if usize::from(packet.header.packet_count) != self.packets.len() {
            return Err(AssembleError::PacketCountChanged);
        }
        if usize::from(packet.header.payload_len) != packet.payload.len() {
            return Err(AssembleError::PayloadLengthMismatch);
        }

        let index = usize::from(packet.header.packet_index);
        match &self.packets[index] {
            Some(existing) if existing != &packet.payload => {
                return Err(AssembleError::DuplicatePacketConflict);
            }
            Some(_) => return Ok(()),
            None => {}
        }

        self.packets[index] = Some(packet.payload.clone());
        self.received += 1;
        Ok(())
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.received == self.packets.len()
    }

    #[must_use]
    pub fn missing_packet_indices(&self) -> Vec<u16> {
        self.packets
            .iter()
            .enumerate()
            .filter(|(_, packet)| packet.is_none())
            .map(|(index, _)| u16::try_from(index).expect("packet count is represented by u16"))
            .collect()
    }

    pub fn finish(self) -> Option<AssembledFrame> {
        if !self.is_complete() {
            return None;
        }
        let total_len = self
            .packets
            .iter()
            .map(|packet| packet.as_ref().map_or(0, Vec::len))
            .sum();
        let mut data = Vec::with_capacity(total_len);
        for packet in self.packets {
            data.extend(packet.expect("complete assembler contains every packet"));
        }
        Some(AssembledFrame {
            stream_id: self.stream_id,
            frame_id: self.frame_id,
            timestamp_us: self.timestamp_us,
            keyframe: self.keyframe,
            data,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledFrame {
    pub stream_id: u32,
    pub frame_id: u64,
    pub timestamp_us: u64,
    pub keyframe: bool,
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> PacketizeMeta {
        PacketizeMeta {
            protocol_major: 0,
            protocol_minor: 1,
            stream_id: 5,
            frame_id: 77,
            first_sequence: u32::MAX,
            timestamp_us: 1_000,
            keyframe: true,
        }
    }

    #[test]
    fn packetization_preserves_frame_and_wraps_sequence() {
        let frame = vec![9_u8; MAX_PACKET_PAYLOAD * 2 + 13];
        let packets = packetize_frame(&frame, meta()).expect("frame should packetize");
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].header.sequence, u32::MAX);
        assert_eq!(packets[1].header.sequence, 0);
        assert!(packets[0].header.flags.contains(MediaFlags::FRAME_START));
        assert!(packets[2].header.flags.contains(MediaFlags::FRAME_END));
    }

    #[test]
    fn reassembly_accepts_reordered_packets() {
        let frame: Vec<u8> = (0_u8..=250).cycle().take(3_500).collect();
        let packets = packetize_frame(&frame, meta()).expect("frame should packetize");
        let mut assembler = FrameAssembler::from_first(&packets[0]);
        for packet in packets.iter().rev() {
            assembler.push(packet).expect("packet should be accepted");
        }
        let complete = assembler.finish().expect("all packets were supplied");
        assert_eq!(complete.data, frame);
        assert!(complete.keyframe);
    }

    #[test]
    fn missing_indices_support_nack_generation() {
        let frame = vec![1_u8; MAX_PACKET_PAYLOAD * 3];
        let packets = packetize_frame(&frame, meta()).expect("frame should packetize");
        let mut assembler = FrameAssembler::from_first(&packets[0]);
        assembler
            .push(&packets[0])
            .expect("first packet should insert");
        assembler
            .push(&packets[2])
            .expect("third packet should insert");
        assert_eq!(assembler.missing_packet_indices(), vec![1]);
        assert!(!assembler.is_complete());
    }
}
