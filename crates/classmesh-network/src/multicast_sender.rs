use std::fmt;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use classmesh_protocol::media::MEDIA_HEADER_LEN;
use classmesh_protocol::PROTOCOL_VERSION;
use classmesh_security::group_media::{
    GroupMediaEpoch, GroupMediaFrameBinding, SealedGroupMediaFrame,
};

use crate::multicast::{MulticastMembership, MulticastProbeOutcome};
use crate::udp::{DatagramError, UdpMediaSocket};
use crate::{packetize_frame, MediaPacket, PacketizeError, PacketizeMeta};

pub const MULTICAST_MEDIA_TTL: u32 = 1;
pub const DEFAULT_MULTICAST_WRITE_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedMulticastSenderConfig {
    membership: MulticastMembership,
    port: u16,
    presentation_id: u64,
    stream_id: u32,
    epoch: GroupMediaEpoch,
}

impl ProtectedMulticastSenderConfig {
    pub fn new(
        membership: MulticastMembership,
        port: u16,
        presentation_id: u64,
        stream_id: u32,
        epoch: GroupMediaEpoch,
        probe_outcome: MulticastProbeOutcome,
    ) -> Result<Self, ProtectedMulticastSendError> {
        if !probe_outcome.can_advertise_udp_multicast() {
            return Err(ProtectedMulticastSendError::MulticastUnavailable);
        }
        if port == 0 {
            return Err(ProtectedMulticastSendError::InvalidPort);
        }
        if presentation_id == 0 {
            return Err(ProtectedMulticastSendError::InvalidPresentationId);
        }
        if stream_id == 0 {
            return Err(ProtectedMulticastSendError::InvalidStreamId);
        }

        Ok(Self {
            membership,
            port,
            presentation_id,
            stream_id,
            epoch,
        })
    }

    #[must_use]
    pub const fn membership(self) -> MulticastMembership {
        self.membership
    }

    #[must_use]
    pub const fn presentation_id(self) -> u64 {
        self.presentation_id
    }

    #[must_use]
    pub const fn stream_id(self) -> u32 {
        self.stream_id
    }

    #[must_use]
    pub const fn epoch(self) -> GroupMediaEpoch {
        self.epoch
    }

    #[must_use]
    pub fn destination(self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(self.membership.group(), self.port))
    }

    #[must_use]
    pub fn local_bind(self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(self.membership.interface(), 0))
    }

    fn accepts_binding(self, binding: GroupMediaFrameBinding) -> bool {
        binding.presentation_id() == self.presentation_id
            && binding.stream_id() == self.stream_id
            && binding.epoch() == self.epoch
    }
}

#[derive(Debug)]
pub enum ProtectedMulticastSendError {
    MulticastUnavailable,
    InvalidPort,
    InvalidPresentationId,
    InvalidStreamId,
    ProtocolVersionOutOfRange,
    FrameBindingMismatch,
    Packetize(PacketizeError),
    Datagram(DatagramError),
    ShortDatagramWrite,
}

impl fmt::Display for ProtectedMulticastSendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MulticastUnavailable => {
                formatter.write_str("multicast runtime probe did not establish local availability")
            }
            Self::InvalidPort => formatter.write_str("multicast destination port must be non-zero"),
            Self::InvalidPresentationId => {
                formatter.write_str("multicast presentation id must be non-zero")
            }
            Self::InvalidStreamId => {
                formatter.write_str("multicast stream id must be non-zero")
            }
            Self::ProtocolVersionOutOfRange => {
                formatter.write_str("protocol version does not fit the media header")
            }
            Self::FrameBindingMismatch => {
                formatter.write_str("sealed group-media frame does not match multicast sender")
            }
            Self::Packetize(error) => write!(formatter, "multicast packetization failed: {error:?}"),
            Self::Datagram(error) => write!(formatter, "multicast UDP send failed: {error}"),
            Self::ShortDatagramWrite => {
                formatter.write_str("multicast UDP write did not send the complete datagram")
            }
        }
    }
}

impl std::error::Error for ProtectedMulticastSendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Datagram(error) => Some(error),
            Self::MulticastUnavailable
            | Self::InvalidPort
            | Self::InvalidPresentationId
            | Self::InvalidStreamId
            | Self::ProtocolVersionOutOfRange
            | Self::FrameBindingMismatch
            | Self::Packetize(_)
            | Self::ShortDatagramWrite => None,
        }
    }
}

impl From<PacketizeError> for ProtectedMulticastSendError {
    fn from(value: PacketizeError) -> Self {
        Self::Packetize(value)
    }
}

impl From<DatagramError> for ProtectedMulticastSendError {
    fn from(value: DatagramError) -> Self {
        Self::Datagram(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedMulticastSendReport {
    pub frame_id: u64,
    pub packets_sent: u16,
    pub ciphertext_bytes: usize,
}

#[derive(Debug)]
struct ProtectedMulticastPacketizer {
    config: ProtectedMulticastSenderConfig,
    next_sequence: u32,
}

impl ProtectedMulticastPacketizer {
    const fn new(config: ProtectedMulticastSenderConfig) -> Self {
        Self {
            config,
            next_sequence: 0,
        }
    }

    fn packetize(
        &mut self,
        frame: &SealedGroupMediaFrame,
    ) -> Result<Vec<MediaPacket>, ProtectedMulticastSendError> {
        let binding = frame.binding();
        if !self.config.accepts_binding(binding) {
            return Err(ProtectedMulticastSendError::FrameBindingMismatch);
        }

        let protocol_major = u8::try_from(PROTOCOL_VERSION.major)
            .map_err(|_| ProtectedMulticastSendError::ProtocolVersionOutOfRange)?;
        let protocol_minor = u8::try_from(PROTOCOL_VERSION.minor)
            .map_err(|_| ProtectedMulticastSendError::ProtocolVersionOutOfRange)?;
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
            .map_err(|_| ProtectedMulticastSendError::Packetize(PacketizeError::TooManyPackets))?;
        self.next_sequence = first_sequence.wrapping_add(packet_count);
        Ok(packets)
    }
}

#[derive(Debug)]
pub struct ProtectedMulticastFrameSender {
    socket: UdpMediaSocket,
    packetizer: ProtectedMulticastPacketizer,
    destination: SocketAddr,
}

impl ProtectedMulticastFrameSender {
    pub fn bind(
        config: ProtectedMulticastSenderConfig,
    ) -> Result<Self, ProtectedMulticastSendError> {
        let socket = UdpMediaSocket::bind(config.local_bind())?;
        socket.set_write_timeout(Some(DEFAULT_MULTICAST_WRITE_TIMEOUT))?;
        socket.set_multicast_ttl_v4(MULTICAST_MEDIA_TTL)?;

        Ok(Self {
            socket,
            packetizer: ProtectedMulticastPacketizer::new(config),
            destination: config.destination(),
        })
    }

    pub fn send_frame(
        &mut self,
        frame: &SealedGroupMediaFrame,
    ) -> Result<ProtectedMulticastSendReport, ProtectedMulticastSendError> {
        let binding = frame.binding();
        let packets = self.packetizer.packetize(frame)?;
        let packets_sent = u16::try_from(packets.len())
            .map_err(|_| ProtectedMulticastSendError::Packetize(PacketizeError::TooManyPackets))?;

        for packet in &packets {
            let expected = MEDIA_HEADER_LEN + packet.payload.len();
            let written = self.socket.send_packet_to(packet, self.destination)?;
            if written != expected {
                return Err(ProtectedMulticastSendError::ShortDatagramWrite);
            }
        }

        Ok(ProtectedMulticastSendReport {
            frame_id: binding.frame_id(),
            packets_sent,
            ciphertext_bytes: frame.len(),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ProtectedMulticastSendError> {
        self.socket.local_addr().map_err(Into::into)
    }

    #[must_use]
    pub const fn destination(&self) -> SocketAddr {
        self.destination
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use classmesh_protocol::media::{MAX_PACKET_PAYLOAD, MediaFlags};
    use classmesh_security::group_media::{GroupMediaKeyMaterial, GroupMediaSender};

    use crate::multicast::MulticastProbeFailure;

    use super::*;

    fn membership() -> MulticastMembership {
        MulticastMembership::new(
            Ipv4Addr::new(239, 10, 20, 30),
            Ipv4Addr::new(192, 168, 50, 10),
        )
        .expect("valid classroom multicast membership")
    }

    fn epoch(value: u32) -> GroupMediaEpoch {
        GroupMediaEpoch::new(value).expect("non-zero epoch")
    }

    fn config(epoch: GroupMediaEpoch) -> ProtectedMulticastSenderConfig {
        ProtectedMulticastSenderConfig::new(
            membership(),
            50_000,
            700,
            800,
            epoch,
            MulticastProbeOutcome::Available,
        )
        .expect("valid sender config")
    }

    fn sealed_frame(
        presentation_id: u64,
        stream_id: u32,
        epoch: GroupMediaEpoch,
        frame_id: u64,
        timestamp_us: u64,
        keyframe: bool,
        bytes: usize,
    ) -> SealedGroupMediaFrame {
        let material = GroupMediaKeyMaterial::generate().expect("test key");
        let mut sender = GroupMediaSender::new(epoch, &material).expect("test sender");
        let binding = GroupMediaFrameBinding::new(
            presentation_id,
            stream_id,
            epoch,
            frame_id,
            timestamp_us,
            keyframe,
        )
        .expect("valid binding");
        sender
            .seal_bound_frame(&vec![0x5a; bytes], binding)
            .expect("sealed frame")
    }

    #[test]
    fn sender_config_requires_runtime_probe_and_nonzero_binding() {
        assert!(matches!(
            ProtectedMulticastSenderConfig::new(
                membership(),
                50_000,
                700,
                800,
                epoch(1),
                MulticastProbeOutcome::Unavailable(MulticastProbeFailure::JoinFailed),
            ),
            Err(ProtectedMulticastSendError::MulticastUnavailable)
        ));
        assert!(matches!(
            ProtectedMulticastSenderConfig::new(
                membership(),
                0,
                700,
                800,
                epoch(1),
                MulticastProbeOutcome::Available,
            ),
            Err(ProtectedMulticastSendError::InvalidPort)
        ));
        assert!(matches!(
            ProtectedMulticastSenderConfig::new(
                membership(),
                50_000,
                0,
                800,
                epoch(1),
                MulticastProbeOutcome::Available,
            ),
            Err(ProtectedMulticastSendError::InvalidPresentationId)
        ));
        assert!(matches!(
            ProtectedMulticastSenderConfig::new(
                membership(),
                50_000,
                700,
                0,
                epoch(1),
                MulticastProbeOutcome::Available,
            ),
            Err(ProtectedMulticastSendError::InvalidStreamId)
        ));
    }

    #[test]
    fn packetizer_uses_authenticated_binding_and_advances_sequence() {
        let epoch = epoch(3);
        let mut packetizer = ProtectedMulticastPacketizer::new(config(epoch));
        let first = sealed_frame(
            700,
            800,
            epoch,
            91,
            123_456,
            true,
            MAX_PACKET_PAYLOAD * 2,
        );
        let packets = packetizer.packetize(&first).expect("packetized frame");

        assert!(packets.len() >= 2);
        assert_eq!(packets[0].header.protocol_major, 0);
        assert_eq!(packets[0].header.protocol_minor, 4);
        assert_eq!(packets[0].header.stream_id, 800);
        assert_eq!(packets[0].header.frame_id, 91);
        assert_eq!(packets[0].header.sequence, 0);
        assert_eq!(packets[0].header.timestamp_us, 123_456);
        assert!(packets[0].header.flags.contains(MediaFlags::KEYFRAME));

        let second = sealed_frame(700, 800, epoch, 92, 156_789, false, 32);
        let next = packetizer.packetize(&second).expect("second frame");
        assert_eq!(
            next[0].header.sequence,
            u32::try_from(packets.len()).expect("bounded packet count")
        );
        assert!(!next[0].header.flags.contains(MediaFlags::KEYFRAME));
    }

    #[test]
    fn binding_mismatch_is_rejected_without_consuming_sequence() {
        let epoch = epoch(4);
        let mut packetizer = ProtectedMulticastPacketizer::new(config(epoch));
        let wrong = sealed_frame(701, 800, epoch, 1, 1_000, false, 32);

        assert!(matches!(
            packetizer.packetize(&wrong),
            Err(ProtectedMulticastSendError::FrameBindingMismatch)
        ));

        let valid = sealed_frame(700, 800, epoch, 2, 2_000, false, 32);
        let packets = packetizer.packetize(&valid).expect("valid frame");
        assert_eq!(packets[0].header.sequence, 0);
    }

    #[test]
    fn config_pins_local_interface_and_classroom_destination() {
        let config = config(epoch(5));
        assert_eq!(
            config.local_bind(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 50, 10)), 0)
        );
        assert_eq!(
            config.destination(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 10, 20, 30)), 50_000)
        );
    }
}
