use std::io::ErrorKind;

use classmesh_protocol::media::{MEDIA_HEADER_LEN, MEDIA_PROTOCOL_VERSION};
use classmesh_security::AuthorizationStore;
use classmesh_security::group_media::{
    GroupMediaEpoch, GroupMediaError, GroupMediaFrameBinding, SealedGroupMediaFrame,
};
use classmesh_security::group_media_coordinator::{
    GroupMediaCoordinator, GroupMediaCoordinatorError,
};
use classmesh_video::Codec;
use classmesh_video::distributor::SharedEncodedFrame;

use crate::transport::SendFrameReport;
use crate::udp::DatagramError;
use crate::{MediaPacket, PacketizeError, PacketizeMeta, packetize_frame};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProtectedMediaBinding {
    presentation_id: u64,
    stream_id: u32,
    epoch: GroupMediaEpoch,
}

impl ProtectedMediaBinding {
    pub(crate) const fn new(presentation_id: u64, stream_id: u32, epoch: GroupMediaEpoch) -> Self {
        Self {
            presentation_id,
            stream_id,
            epoch,
        }
    }

    pub(crate) const fn presentation_id(self) -> u64 {
        self.presentation_id
    }

    pub(crate) const fn stream_id(self) -> u32 {
        self.stream_id
    }

    pub(crate) const fn epoch(self) -> GroupMediaEpoch {
        self.epoch
    }

    pub(crate) fn accepts(self, binding: GroupMediaFrameBinding) -> bool {
        binding.presentation_id() == self.presentation_id
            && binding.stream_id() == self.stream_id
            && binding.epoch() == self.epoch
    }
}

#[derive(Debug)]
pub(crate) enum ProtectedMediaCoreError {
    ProtocolVersionOutOfRange,
    FrameBindingMismatch,
    UnsupportedCodec,
    Security(GroupMediaError),
    Coordinator(GroupMediaCoordinatorError),
    Packetize(PacketizeError),
    Datagram(DatagramError),
    ShortDatagramWrite,
}

impl From<GroupMediaError> for ProtectedMediaCoreError {
    fn from(value: GroupMediaError) -> Self {
        Self::Security(value)
    }
}

impl From<GroupMediaCoordinatorError> for ProtectedMediaCoreError {
    fn from(value: GroupMediaCoordinatorError) -> Self {
        Self::Coordinator(value)
    }
}

impl From<PacketizeError> for ProtectedMediaCoreError {
    fn from(value: PacketizeError) -> Self {
        Self::Packetize(value)
    }
}

impl From<DatagramError> for ProtectedMediaCoreError {
    fn from(value: DatagramError) -> Self {
        Self::Datagram(value)
    }
}

pub(crate) fn protect_shared_h264_frame(
    binding: ProtectedMediaBinding,
    coordinator: &mut GroupMediaCoordinator,
    authorization: &AuthorizationStore,
    frame: &SharedEncodedFrame,
) -> Result<SealedGroupMediaFrame, ProtectedMediaCoreError> {
    if frame.codec != Codec::H264 {
        return Err(ProtectedMediaCoreError::UnsupportedCodec);
    }

    let frame_binding = GroupMediaFrameBinding::new(
        binding.presentation_id(),
        binding.stream_id(),
        binding.epoch(),
        frame.meta.frame_id,
        frame.meta.timestamp_us,
        frame.meta.keyframe,
    )?;
    coordinator
        .seal_bound_frame(authorization, frame.data.as_ref(), frame_binding)
        .map_err(Into::into)
}

#[derive(Debug)]
pub(crate) struct PreparedProtectedFrame {
    pub(crate) packets: Vec<MediaPacket>,
    pub(crate) first_sequence: u32,
    pub(crate) next_sequence: u32,
}

#[derive(Debug)]
pub(crate) struct ProtectedMediaPacketizer {
    binding: ProtectedMediaBinding,
    next_sequence: u32,
}

impl ProtectedMediaPacketizer {
    pub(crate) const fn new(binding: ProtectedMediaBinding) -> Self {
        Self {
            binding,
            next_sequence: 0,
        }
    }

    pub(crate) fn packetize(
        &mut self,
        frame: &SealedGroupMediaFrame,
    ) -> Result<PreparedProtectedFrame, ProtectedMediaCoreError> {
        let binding = frame.binding();
        if !self.binding.accepts(binding) {
            return Err(ProtectedMediaCoreError::FrameBindingMismatch);
        }

        let protocol_major = u8::try_from(MEDIA_PROTOCOL_VERSION.major)
            .map_err(|_| ProtectedMediaCoreError::ProtocolVersionOutOfRange)?;
        let protocol_minor = u8::try_from(MEDIA_PROTOCOL_VERSION.minor)
            .map_err(|_| ProtectedMediaCoreError::ProtocolVersionOutOfRange)?;
        let first_sequence = self.next_sequence;
        let packets = packetize_frame(
            frame.as_bytes(),
            PacketizeMeta {
                protocol_major,
                protocol_minor,
                stream_id: binding.stream_id(),
                frame_id: binding.frame_id(),
                first_sequence,
                timestamp_us: binding.timestamp_us(),
                keyframe: binding.keyframe(),
            },
        )?;
        let packet_count = u32::try_from(packets.len())
            .map_err(|_| ProtectedMediaCoreError::Packetize(PacketizeError::TooManyPackets))?;
        let next_sequence = first_sequence.wrapping_add(packet_count);
        self.next_sequence = next_sequence;

        Ok(PreparedProtectedFrame {
            packets,
            first_sequence,
            next_sequence,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProtectedMediaBackpressureDrop {
    pub(crate) frame_id: u64,
    pub(crate) packets_sent: usize,
    pub(crate) packets_total: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtectedMediaTrySendOutcome {
    Sent(SendFrameReport),
    DroppedBackpressure(ProtectedMediaBackpressureDrop),
}

pub(crate) fn send_prepared_frame<F>(
    frame: &SealedGroupMediaFrame,
    prepared: &PreparedProtectedFrame,
    mut send_packet: F,
) -> Result<SendFrameReport, ProtectedMediaCoreError>
where
    F: FnMut(&MediaPacket) -> Result<usize, DatagramError>,
{
    for packet in &prepared.packets {
        let expected = MEDIA_HEADER_LEN + packet.payload.len();
        let written = send_packet(packet)?;
        if written != expected {
            return Err(ProtectedMediaCoreError::ShortDatagramWrite);
        }
    }

    Ok(send_report(frame, prepared))
}

pub(crate) fn try_send_prepared_frame<F>(
    frame: &SealedGroupMediaFrame,
    prepared: &PreparedProtectedFrame,
    mut send_packet: F,
) -> Result<ProtectedMediaTrySendOutcome, ProtectedMediaCoreError>
where
    F: FnMut(&MediaPacket) -> Result<usize, DatagramError>,
{
    let binding = frame.binding();
    let mut packets_sent = 0_usize;

    for packet in &prepared.packets {
        let expected = MEDIA_HEADER_LEN + packet.payload.len();
        match send_packet(packet) {
            Ok(written) if written == expected => {
                packets_sent = packets_sent.saturating_add(1);
            }
            Ok(_) => return Err(ProtectedMediaCoreError::ShortDatagramWrite),
            Err(DatagramError::Io(error)) if error.kind() == ErrorKind::WouldBlock => {
                return Ok(ProtectedMediaTrySendOutcome::DroppedBackpressure(
                    ProtectedMediaBackpressureDrop {
                        frame_id: binding.frame_id(),
                        packets_sent,
                        packets_total: prepared.packets.len(),
                    },
                ));
            }
            Err(error) => return Err(ProtectedMediaCoreError::Datagram(error)),
        }
    }

    Ok(ProtectedMediaTrySendOutcome::Sent(send_report(
        frame, prepared,
    )))
}

fn send_report(
    frame: &SealedGroupMediaFrame,
    prepared: &PreparedProtectedFrame,
) -> SendFrameReport {
    SendFrameReport {
        frame_id: frame.binding().frame_id(),
        packets: prepared.packets.len(),
        payload_bytes: frame.len(),
        first_sequence: prepared.first_sequence,
        next_sequence: prepared.next_sequence,
    }
}
