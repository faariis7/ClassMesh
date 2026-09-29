use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use classmesh_protocol::PROTOCOL_VERSION;
use classmesh_protocol::feedback::{FeedbackMessage, MAX_NACK_PACKET_INDICES};
use classmesh_protocol::media::MediaFlags;

use crate::multicast::{MulticastMembership, MulticastProbeOutcome};
use crate::receiver::{ReceiverEvent, ReceiverPolicy, ReceiverWindow};
use crate::udp::{DatagramError, UdpMediaSocket};
use crate::{AssembleError, AssembledFrame, MediaPacket};

pub const DEFAULT_MULTICAST_READ_TIMEOUT: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedMulticastReceiverConfig {
    membership: MulticastMembership,
    port: u16,
    expected_sender: Ipv4Addr,
    stream_id: u32,
}

impl ProtectedMulticastReceiverConfig {
    pub fn new(
        membership: MulticastMembership,
        port: u16,
        expected_sender: Ipv4Addr,
        stream_id: u32,
        probe_outcome: MulticastProbeOutcome,
    ) -> Result<Self, ProtectedMulticastReceiveError> {
        if !probe_outcome.can_advertise_udp_multicast() {
            return Err(ProtectedMulticastReceiveError::MulticastUnavailable);
        }
        if port == 0 {
            return Err(ProtectedMulticastReceiveError::InvalidPort);
        }
        if expected_sender.is_unspecified()
            || expected_sender.is_loopback()
            || expected_sender.is_multicast()
            || expected_sender == Ipv4Addr::BROADCAST
        {
            return Err(ProtectedMulticastReceiveError::InvalidExpectedSender);
        }
        if stream_id == 0 {
            return Err(ProtectedMulticastReceiveError::InvalidStreamId);
        }

        Ok(Self {
            membership,
            port,
            expected_sender,
            stream_id,
        })
    }

    #[must_use]
    pub const fn membership(self) -> MulticastMembership {
        self.membership
    }

    #[must_use]
    pub const fn expected_sender(self) -> Ipv4Addr {
        self.expected_sender
    }

    #[must_use]
    pub const fn stream_id(self) -> u32 {
        self.stream_id
    }

    #[must_use]
    pub fn local_bind(self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, self.port))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastPacketDropReason {
    UnexpectedSource,
    UnexpectedProtocolVersion,
    WrongStream,
    RetransmitUnsupported,
    FecUnsupported,
    Assembly(AssembleError),
}

#[derive(Debug)]
pub enum ProtectedMulticastReceiveError {
    MulticastUnavailable,
    InvalidPort,
    InvalidExpectedSender,
    InvalidStreamId,
    ProtocolVersionOutOfRange,
    Datagram(DatagramError),
}

impl fmt::Display for ProtectedMulticastReceiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MulticastUnavailable => {
                formatter.write_str("multicast runtime probe did not establish local availability")
            }
            Self::InvalidPort => formatter.write_str("multicast receive port must be non-zero"),
            Self::InvalidExpectedSender => {
                formatter.write_str("multicast expected sender must be a unicast IPv4 address")
            }
            Self::InvalidStreamId => formatter.write_str("multicast stream id must be non-zero"),
            Self::ProtocolVersionOutOfRange => {
                formatter.write_str("protocol version does not fit the media header")
            }
            Self::Datagram(error) => write!(formatter, "multicast UDP receive failed: {error}"),
        }
    }
}

impl std::error::Error for ProtectedMulticastReceiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Datagram(error) => Some(error),
            Self::MulticastUnavailable
            | Self::InvalidPort
            | Self::InvalidExpectedSender
            | Self::InvalidStreamId
            | Self::ProtocolVersionOutOfRange => None,
        }
    }
}

impl From<DatagramError> for ProtectedMulticastReceiveError {
    fn from(value: DatagramError) -> Self {
        Self::Datagram(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedGroupMediaCiphertext {
    stream_id: u32,
    frame_id: u64,
    timestamp_us: u64,
    keyframe: bool,
    ciphertext: Vec<u8>,
}

impl ReceivedGroupMediaCiphertext {
    fn from_assembled(frame: AssembledFrame) -> Self {
        Self {
            stream_id: frame.stream_id,
            frame_id: frame.frame_id,
            timestamp_us: frame.timestamp_us,
            keyframe: frame.keyframe,
            ciphertext: frame.data,
        }
    }

    #[must_use]
    pub const fn stream_id(&self) -> u32 {
        self.stream_id
    }

    #[must_use]
    pub const fn frame_id(&self) -> u64 {
        self.frame_id
    }

    #[must_use]
    pub const fn timestamp_us(&self) -> u64 {
        self.timestamp_us
    }

    #[must_use]
    pub const fn keyframe(&self) -> bool {
        self.keyframe
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    #[must_use]
    pub fn into_ciphertext(self) -> Vec<u8> {
        self.ciphertext
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProtectedMulticastReceiveBatch {
    pub frames: Vec<ReceivedGroupMediaCiphertext>,
    pub feedback: Vec<FeedbackMessage>,
    pub dropped_stale_frames: usize,
}

impl ProtectedMulticastReceiveBatch {
    fn from_receiver_events(events: Vec<ReceiverEvent>) -> Self {
        let mut frames = Vec::new();
        let mut feedback = Vec::new();
        let mut dropped_stale_frames = 0_usize;

        for event in events {
            match event {
                ReceiverEvent::FrameReady(frame) => {
                    frames.push(ReceivedGroupMediaCiphertext::from_assembled(frame));
                }
                ReceiverEvent::NeedNack {
                    stream_id,
                    frame_id,
                    mut missing_packet_indices,
                } => {
                    missing_packet_indices.truncate(MAX_NACK_PACKET_INDICES);
                    if !missing_packet_indices.is_empty() {
                        feedback.push(FeedbackMessage::Nack {
                            stream_id,
                            frame_id,
                            missing_packet_indices,
                        });
                    }
                }
                ReceiverEvent::NeedKeyframe {
                    stream_id,
                    after_frame_id,
                } => feedback.push(FeedbackMessage::RequestKeyframe {
                    stream_id,
                    after_frame_id,
                }),
                ReceiverEvent::DroppedStaleFrame { .. } => {
                    dropped_stale_frames = dropped_stale_frames.saturating_add(1);
                }
            }
        }

        Self {
            frames,
            feedback,
            dropped_stale_frames,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty() && self.feedback.is_empty() && self.dropped_stale_frames == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectedMulticastReceiveOutcome {
    Events(ProtectedMulticastReceiveBatch),
    Dropped(MulticastPacketDropReason),
}

#[derive(Debug)]
pub struct ProtectedMulticastReceiveState {
    config: ProtectedMulticastReceiverConfig,
    receiver: ReceiverWindow,
    protocol_major: u8,
    protocol_minor: u8,
}

impl ProtectedMulticastReceiveState {
    pub fn new(
        config: ProtectedMulticastReceiverConfig,
    ) -> Result<Self, ProtectedMulticastReceiveError> {
        let protocol_major = u8::try_from(PROTOCOL_VERSION.major)
            .map_err(|_| ProtectedMulticastReceiveError::ProtocolVersionOutOfRange)?;
        let protocol_minor = u8::try_from(PROTOCOL_VERSION.minor)
            .map_err(|_| ProtectedMulticastReceiveError::ProtocolVersionOutOfRange)?;

        Ok(Self {
            config,
            receiver: ReceiverWindow::new(ReceiverPolicy::default()),
            protocol_major,
            protocol_minor,
        })
    }

    pub fn push_packet(
        &mut self,
        now_us: u64,
        packet: &MediaPacket,
        source: SocketAddr,
    ) -> ProtectedMulticastReceiveOutcome {
        if source.ip() != IpAddr::V4(self.config.expected_sender()) {
            return ProtectedMulticastReceiveOutcome::Dropped(
                MulticastPacketDropReason::UnexpectedSource,
            );
        }
        if packet.header.protocol_major != self.protocol_major
            || packet.header.protocol_minor != self.protocol_minor
        {
            return ProtectedMulticastReceiveOutcome::Dropped(
                MulticastPacketDropReason::UnexpectedProtocolVersion,
            );
        }
        if packet.header.stream_id != self.config.stream_id() {
            return ProtectedMulticastReceiveOutcome::Dropped(MulticastPacketDropReason::WrongStream);
        }
        if packet.header.flags.contains(MediaFlags::RETRANSMIT) {
            return ProtectedMulticastReceiveOutcome::Dropped(
                MulticastPacketDropReason::RetransmitUnsupported,
            );
        }
        if packet.header.flags.contains(MediaFlags::FEC) {
            return ProtectedMulticastReceiveOutcome::Dropped(MulticastPacketDropReason::FecUnsupported);
        }

        match self.receiver.push(now_us, packet) {
            Ok(events) => ProtectedMulticastReceiveOutcome::Events(
                ProtectedMulticastReceiveBatch::from_receiver_events(events),
            ),
            Err(error) => ProtectedMulticastReceiveOutcome::Dropped(
                MulticastPacketDropReason::Assembly(error),
            ),
        }
    }

    #[must_use]
    pub fn tick(&mut self, now_us: u64) -> ProtectedMulticastReceiveBatch {
        ProtectedMulticastReceiveBatch::from_receiver_events(self.receiver.tick(now_us))
    }

    #[must_use]
    pub const fn dropped_frames(&self) -> u64 {
        self.receiver.dropped_frames()
    }
}

#[derive(Debug)]
pub struct ProtectedMulticastFrameReceiver {
    socket: UdpMediaSocket,
    membership: MulticastMembership,
    state: ProtectedMulticastReceiveState,
}

impl ProtectedMulticastFrameReceiver {
    pub fn bind(
        config: ProtectedMulticastReceiverConfig,
    ) -> Result<Self, ProtectedMulticastReceiveError> {
        let socket = UdpMediaSocket::bind(config.local_bind())?;
        socket.set_read_timeout(Some(DEFAULT_MULTICAST_READ_TIMEOUT))?;
        socket.join_multicast_v4(config.membership().group(), config.membership().interface())?;

        Ok(Self {
            socket,
            membership: config.membership(),
            state: ProtectedMulticastReceiveState::new(config)?,
        })
    }

    pub fn receive_once(
        &mut self,
        now_us: u64,
    ) -> Result<ProtectedMulticastReceiveOutcome, ProtectedMulticastReceiveError> {
        match self.socket.receive_packet() {
            Ok((packet, source)) => Ok(self.state.push_packet(now_us, &packet, source)),
            Err(DatagramError::Io(error))
                if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) =>
            {
                Ok(ProtectedMulticastReceiveOutcome::Events(
                    self.state.tick(now_us),
                ))
            }
            Err(error) => Err(error.into()),
        }
    }

    #[must_use]
    pub const fn dropped_frames(&self) -> u64 {
        self.state.dropped_frames()
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ProtectedMulticastReceiveError> {
        self.socket.local_addr().map_err(Into::into)
    }
}

impl Drop for ProtectedMulticastFrameReceiver {
    fn drop(&mut self) {
        let _ = self
            .socket
            .leave_multicast_v4(self.membership.group(), self.membership.interface());
    }
}

#[cfg(test)]
mod tests {
    use classmesh_protocol::media::MAX_PACKET_PAYLOAD;

    use crate::PacketizeMeta;
    use crate::multicast::MulticastProbeFailure;
    use crate::packetize_frame;

    use super::*;

    fn membership() -> MulticastMembership {
        MulticastMembership::new(
            Ipv4Addr::new(239, 10, 20, 30),
            Ipv4Addr::new(192, 168, 50, 10),
        )
        .expect("valid classroom multicast membership")
    }

    fn sender() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 50, 20)
    }

    fn config() -> ProtectedMulticastReceiverConfig {
        ProtectedMulticastReceiverConfig::new(
            membership(),
            50_000,
            sender(),
            800,
            MulticastProbeOutcome::Available,
        )
        .expect("valid receiver config")
    }

    fn source() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(sender()), 49_999)
    }

    fn packets(frame_id: u64, keyframe: bool) -> Vec<MediaPacket> {
        packetize_frame(
            &vec![0x5a; MAX_PACKET_PAYLOAD * 2 + 17],
            PacketizeMeta {
                protocol_major: 0,
                protocol_minor: 4,
                stream_id: 800,
                frame_id,
                first_sequence: 10,
                timestamp_us: frame_id * 33_333,
                keyframe,
            },
        )
        .expect("test ciphertext packetizes")
    }

    #[test]
    fn config_requires_probe_unicast_sender_and_nonzero_binding() {
        assert!(matches!(
            ProtectedMulticastReceiverConfig::new(
                membership(),
                50_000,
                sender(),
                800,
                MulticastProbeOutcome::Unavailable(MulticastProbeFailure::JoinFailed),
            ),
            Err(ProtectedMulticastReceiveError::MulticastUnavailable)
        ));
        assert!(matches!(
            ProtectedMulticastReceiverConfig::new(
                membership(),
                0,
                sender(),
                800,
                MulticastProbeOutcome::Available,
            ),
            Err(ProtectedMulticastReceiveError::InvalidPort)
        ));
        for invalid in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(239, 1, 2, 3),
        ] {
            assert!(matches!(
                ProtectedMulticastReceiverConfig::new(
                    membership(),
                    50_000,
                    invalid,
                    800,
                    MulticastProbeOutcome::Available,
                ),
                Err(ProtectedMulticastReceiveError::InvalidExpectedSender)
            ));
        }
        assert!(matches!(
            ProtectedMulticastReceiverConfig::new(
                membership(),
                50_000,
                sender(),
                0,
                MulticastProbeOutcome::Available,
            ),
            Err(ProtectedMulticastReceiveError::InvalidStreamId)
        ));
    }

    #[test]
    fn exact_sender_stream_and_version_reassemble_ciphertext() {
        let mut state = ProtectedMulticastReceiveState::new(config()).expect("receiver state");
        let frame = packets(9, true);
        let expected: Vec<u8> = frame
            .iter()
            .flat_map(|packet| packet.payload.iter().copied())
            .collect();
        let mut ready = None;

        for packet in frame.iter().rev() {
            if let ProtectedMulticastReceiveOutcome::Events(batch) =
                state.push_packet(5_000, packet, source())
                && let Some(frame) = batch.frames.into_iter().next()
            {
                ready = Some(frame);
            }
        }

        let ready = ready.expect("complete ciphertext frame");
        assert_eq!(ready.stream_id(), 800);
        assert_eq!(ready.frame_id(), 9);
        assert_eq!(ready.timestamp_us(), 9 * 33_333);
        assert!(ready.keyframe());
        assert_eq!(ready.ciphertext(), expected);
    }

    #[test]
    fn unexpected_source_stream_version_and_group_retransmit_are_media_local_drops() {
        let cases = [
            (
                {
                    let packet = packets(1, false).remove(0);
                    packet
                },
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 50, 21)), 49_999),
                MulticastPacketDropReason::UnexpectedSource,
            ),
            (
                {
                    let mut packet = packets(1, false).remove(0);
                    packet.header.stream_id = 801;
                    packet
                },
                source(),
                MulticastPacketDropReason::WrongStream,
            ),
            (
                {
                    let mut packet = packets(1, false).remove(0);
                    packet.header.protocol_minor = 3;
                    packet
                },
                source(),
                MulticastPacketDropReason::UnexpectedProtocolVersion,
            ),
            (
                {
                    let mut packet = packets(1, false).remove(0);
                    packet.header.flags = packet.header.flags | MediaFlags::RETRANSMIT;
                    packet
                },
                source(),
                MulticastPacketDropReason::RetransmitUnsupported,
            ),
            (
                {
                    let mut packet = packets(1, false).remove(0);
                    packet.header.flags = packet.header.flags | MediaFlags::FEC;
                    packet
                },
                source(),
                MulticastPacketDropReason::FecUnsupported,
            ),
        ];

        for (packet, packet_source, expected) in cases {
            let mut state = ProtectedMulticastReceiveState::new(config()).expect("receiver state");
            assert_eq!(
                state.push_packet(0, &packet, packet_source),
                ProtectedMulticastReceiveOutcome::Dropped(expected)
            );
            assert_eq!(state.dropped_frames(), 0);
        }
    }

    #[test]
    fn receiver_window_feedback_is_exposed_without_transport_retransmission() {
        let mut state = ProtectedMulticastReceiveState::new(config()).expect("receiver state");
        let frame = packets(2, false);
        let _ = state.push_packet(0, &frame[0], source());
        let _ = state.push_packet(1_000, &frame[2], source());

        let nack = state.tick(25_000);
        assert!(matches!(
            nack.feedback.as_slice(),
            [FeedbackMessage::Nack {
                stream_id: 800,
                frame_id: 2,
                missing_packet_indices,
            }] if missing_packet_indices == &vec![1]
        ));

        let expired = state.tick(100_000);
        assert!(expired.feedback.iter().any(|feedback| matches!(
            feedback,
            FeedbackMessage::RequestKeyframe {
                stream_id: 800,
                after_frame_id: 2,
            }
        )));
        assert_eq!(expired.dropped_stale_frames, 1);
        assert_eq!(state.dropped_frames(), 1);
    }

    #[test]
    fn multicast_nack_feedback_is_bounded_to_control_contract() {
        let missing: Vec<u16> =
            (0..u16::try_from(MAX_NACK_PACKET_INDICES + 5).expect("small test bound")).collect();
        let batch = ProtectedMulticastReceiveBatch::from_receiver_events(vec![
            ReceiverEvent::NeedNack {
                stream_id: 800,
                frame_id: 44,
                missing_packet_indices: missing,
            },
        ]);

        let [FeedbackMessage::Nack {
            missing_packet_indices,
            ..
        }] = batch.feedback.as_slice()
        else {
            panic!("expected bounded NACK");
        };
        assert_eq!(missing_packet_indices.len(), MAX_NACK_PACKET_INDICES);
    }

    #[test]
    fn receiver_config_binds_all_ipv4_interfaces_but_joins_selected_interface() {
        let config = config();
        assert_eq!(
            config.local_bind(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 50_000)
        );
        assert_eq!(config.membership().interface(), Ipv4Addr::new(192, 168, 50, 10));
        assert_eq!(config.membership().group(), Ipv4Addr::new(239, 10, 20, 30));
    }
}
