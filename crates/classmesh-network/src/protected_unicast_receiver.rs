use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::MediaPacket;
use crate::protected_media_receive::{
    DatagramFailureDisposition, ProtectedMediaReceiveCoreError, ProtectedMediaReceiveState,
    classify_datagram_failure,
};
use crate::udp::{DatagramError, UdpMediaSocket};

pub use crate::protected_media_receive::{
    ProtectedMediaPacketDropReason as ProtectedUnicastPacketDropReason,
    ProtectedMediaReceiveBatch as ProtectedUnicastReceiveBatch,
    ProtectedMediaReceiveOutcome as ProtectedUnicastReceiveOutcome, ReceivedGroupMediaCiphertext,
};

pub const DEFAULT_UNICAST_READ_TIMEOUT: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedUnicastReceiverConfig {
    port: u16,
    expected_sender: IpAddr,
    stream_id: u32,
}

impl ProtectedUnicastReceiverConfig {
    pub fn new(
        port: u16,
        expected_sender: IpAddr,
        stream_id: u32,
    ) -> Result<Self, ProtectedUnicastReceiveError> {
        if port == 0 {
            return Err(ProtectedUnicastReceiveError::InvalidPort);
        }
        if invalid_expected_sender(expected_sender) {
            return Err(ProtectedUnicastReceiveError::InvalidExpectedSender);
        }
        if stream_id == 0 {
            return Err(ProtectedUnicastReceiveError::InvalidStreamId);
        }

        Ok(Self {
            port,
            expected_sender,
            stream_id,
        })
    }

    #[must_use]
    pub const fn expected_sender(self) -> IpAddr {
        self.expected_sender
    }

    #[must_use]
    pub const fn stream_id(self) -> u32 {
        self.stream_id
    }

    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }

    #[must_use]
    pub const fn local_bind(self) -> SocketAddr {
        match self.expected_sender {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.port),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), self.port),
        }
    }
}

fn invalid_expected_sender(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_unspecified() || address.is_multicast() || address == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(address) => address.is_unspecified() || address.is_multicast(),
    }
}

#[derive(Debug)]
pub enum ProtectedUnicastReceiveError {
    InvalidPort,
    InvalidExpectedSender,
    InvalidStreamId,
    ProtocolVersionOutOfRange,
    Datagram(DatagramError),
}

impl fmt::Display for ProtectedUnicastReceiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPort => {
                formatter.write_str("protected unicast receive port must be non-zero")
            }
            Self::InvalidExpectedSender => formatter
                .write_str("protected unicast expected sender must be a unicast IP address"),
            Self::InvalidStreamId => {
                formatter.write_str("protected unicast stream id must be non-zero")
            }
            Self::ProtocolVersionOutOfRange => {
                formatter.write_str("protocol version does not fit the media header")
            }
            Self::Datagram(error) => {
                write!(formatter, "protected unicast UDP receive failed: {error}")
            }
        }
    }
}

impl std::error::Error for ProtectedUnicastReceiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Datagram(error) => Some(error),
            Self::InvalidPort
            | Self::InvalidExpectedSender
            | Self::InvalidStreamId
            | Self::ProtocolVersionOutOfRange => None,
        }
    }
}

impl From<DatagramError> for ProtectedUnicastReceiveError {
    fn from(value: DatagramError) -> Self {
        Self::Datagram(value)
    }
}

#[derive(Debug)]
pub struct ProtectedUnicastReceiveState {
    inner: ProtectedMediaReceiveState,
}

impl ProtectedUnicastReceiveState {
    pub fn new(
        config: ProtectedUnicastReceiverConfig,
    ) -> Result<Self, ProtectedUnicastReceiveError> {
        let inner = ProtectedMediaReceiveState::new(config.expected_sender(), config.stream_id())
            .map_err(map_core_error)?;

        Ok(Self { inner })
    }

    pub fn push_packet(
        &mut self,
        now_us: u64,
        packet: &MediaPacket,
        source: SocketAddr,
    ) -> ProtectedUnicastReceiveOutcome {
        self.inner.push_packet(now_us, packet, source)
    }

    #[must_use]
    pub fn tick(&mut self, now_us: u64) -> ProtectedUnicastReceiveBatch {
        self.inner.tick(now_us)
    }

    #[must_use]
    pub const fn dropped_frames(&self) -> u64 {
        self.inner.dropped_frames()
    }
}

const fn map_core_error(error: ProtectedMediaReceiveCoreError) -> ProtectedUnicastReceiveError {
    match error {
        ProtectedMediaReceiveCoreError::InvalidStreamId => {
            ProtectedUnicastReceiveError::InvalidStreamId
        }
        ProtectedMediaReceiveCoreError::ProtocolVersionOutOfRange => {
            ProtectedUnicastReceiveError::ProtocolVersionOutOfRange
        }
    }
}

#[derive(Debug)]
pub struct ProtectedUnicastFrameReceiver {
    socket: UdpMediaSocket,
    state: ProtectedUnicastReceiveState,
}

impl ProtectedUnicastFrameReceiver {
    pub fn bind(
        config: ProtectedUnicastReceiverConfig,
    ) -> Result<Self, ProtectedUnicastReceiveError> {
        let socket = UdpMediaSocket::bind(config.local_bind())?;
        socket.set_read_timeout(Some(DEFAULT_UNICAST_READ_TIMEOUT))?;

        Ok(Self {
            socket,
            state: ProtectedUnicastReceiveState::new(config)?,
        })
    }

    pub fn receive_once(
        &mut self,
        now_us: u64,
    ) -> Result<ProtectedUnicastReceiveOutcome, ProtectedUnicastReceiveError> {
        match self.socket.receive_packet() {
            Ok((packet, source)) => Ok(self.state.push_packet(now_us, &packet, source)),
            Err(error) => match classify_datagram_failure(&error) {
                DatagramFailureDisposition::Tick => Ok(ProtectedUnicastReceiveOutcome::Events(
                    self.state.tick(now_us),
                )),
                DatagramFailureDisposition::DropMalformed => {
                    Ok(ProtectedUnicastReceiveOutcome::Dropped(
                        ProtectedUnicastPacketDropReason::MalformedDatagram,
                    ))
                }
                DatagramFailureDisposition::Fail => Err(error.into()),
            },
        }
    }

    #[must_use]
    pub const fn dropped_frames(&self) -> u64 {
        self.state.dropped_frames()
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ProtectedUnicastReceiveError> {
        self.socket.local_addr().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, UdpSocket};

    use classmesh_protocol::PROTOCOL_VERSION;
    use classmesh_protocol::media::MediaFlags;

    use crate::{PacketizeMeta, packetize_frame};

    use super::*;

    const STREAM_ID: u32 = 800;

    fn ipv4_config(port: u16) -> ProtectedUnicastReceiverConfig {
        ProtectedUnicastReceiverConfig::new(port, IpAddr::V4(Ipv4Addr::LOCALHOST), STREAM_ID)
            .expect("valid unicast receiver config")
    }

    fn packets(frame_id: u64) -> Vec<MediaPacket> {
        packetize_frame(
            &vec![0x5a; classmesh_protocol::media::MAX_PACKET_PAYLOAD * 2 + 17],
            PacketizeMeta {
                protocol_major: u8::try_from(PROTOCOL_VERSION.major).expect("protocol major fits"),
                protocol_minor: u8::try_from(PROTOCOL_VERSION.minor).expect("protocol minor fits"),
                stream_id: STREAM_ID,
                frame_id,
                first_sequence: 10,
                timestamp_us: frame_id * 33_333,
                keyframe: frame_id == 1,
            },
        )
        .expect("test ciphertext packetizes")
    }

    #[test]
    fn config_rejects_invalid_port_sender_and_stream() {
        assert!(matches!(
            ProtectedUnicastReceiverConfig::new(0, IpAddr::V4(Ipv4Addr::LOCALHOST), STREAM_ID),
            Err(ProtectedUnicastReceiveError::InvalidPort)
        ));

        for invalid in [
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::BROADCAST),
            IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6("ff02::1".parse().expect("multicast IPv6")),
        ] {
            assert!(matches!(
                ProtectedUnicastReceiverConfig::new(50_000, invalid, STREAM_ID),
                Err(ProtectedUnicastReceiveError::InvalidExpectedSender)
            ));
        }

        assert!(matches!(
            ProtectedUnicastReceiverConfig::new(50_000, IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            Err(ProtectedUnicastReceiveError::InvalidStreamId)
        ));
    }

    #[test]
    fn local_bind_uses_unspecified_address_for_expected_sender_family() {
        let ipv4 = ProtectedUnicastReceiverConfig::new(
            50_000,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)),
            STREAM_ID,
        )
        .expect("valid IPv4 config");
        assert_eq!(
            ipv4.local_bind(),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 50_000))
        );

        let ipv6 = ProtectedUnicastReceiverConfig::new(
            50_001,
            IpAddr::V6("2001:db8::44".parse().expect("test IPv6")),
            STREAM_ID,
        )
        .expect("valid IPv6 config");
        assert_eq!(
            ipv6.local_bind(),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 50_001, 0, 0))
        );
    }

    #[test]
    fn wrong_source_and_retransmit_marker_are_media_local_drops() {
        let config = ipv4_config(50_000);
        let mut state = ProtectedUnicastReceiveState::new(config).expect("receiver state");
        let packet = packets(2).remove(0);

        assert_eq!(
            state.push_packet(
                0,
                &packet,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 49_999),
            ),
            ProtectedUnicastReceiveOutcome::Dropped(
                ProtectedUnicastPacketDropReason::UnexpectedSource
            )
        );

        let mut retransmit = packet;
        retransmit.header.flags = retransmit.header.flags | MediaFlags::RETRANSMIT;
        assert_eq!(
            state.push_packet(
                0,
                &retransmit,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49_999),
            ),
            ProtectedUnicastReceiveOutcome::Dropped(
                ProtectedUnicastPacketDropReason::RetransmitUnsupported
            )
        );
    }

    #[test]
    fn loopback_runtime_reassembles_ciphertext_without_exposing_plaintext() {
        let reservation =
            UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .expect("reserve test port");
        let port = reservation.local_addr().expect("reserved address").port();
        drop(reservation);

        let mut receiver =
            ProtectedUnicastFrameReceiver::bind(ipv4_config(port)).expect("receiver binds");
        let sender =
            UdpMediaSocket::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
                .expect("sender binds");
        let destination = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
        let frame = packets(1);
        let expected: Vec<u8> = frame
            .iter()
            .flat_map(|packet| packet.payload.iter().copied())
            .collect();

        for packet in frame.iter().rev() {
            sender
                .send_packet_to(packet, destination)
                .expect("packet sends");
        }

        let mut ready = None;
        for index in 0..frame.len() {
            let outcome = receiver
                .receive_once(u64::try_from(index).expect("small index"))
                .expect("packet receives");
            if let ProtectedUnicastReceiveOutcome::Events(batch) = outcome {
                if let Some(frame) = batch.frames.into_iter().next() {
                    ready = Some(frame);
                }
            }
        }

        let ready = ready.expect("complete ciphertext frame");
        assert_eq!(ready.stream_id(), STREAM_ID);
        assert_eq!(ready.frame_id(), 1);
        assert!(ready.keyframe());
        assert_eq!(ready.ciphertext(), expected);
    }
}
