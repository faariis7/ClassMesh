use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use classmesh_security::AuthorizationStore;
use classmesh_security::group_media::{GroupMediaEpoch, GroupMediaError, SealedGroupMediaFrame};
use classmesh_security::group_media_coordinator::{
    GroupMediaCoordinator, GroupMediaCoordinatorError,
};
use classmesh_video::distributor::SharedEncodedFrame;

use crate::PacketizeError;
use crate::protected_media::{
    ProtectedMediaBackpressureDrop, ProtectedMediaBinding, ProtectedMediaCoreError,
    ProtectedMediaPacketizer, ProtectedMediaTrySendOutcome, protect_shared_h264_frame,
    try_send_prepared_frame,
};
use crate::transport::SendFrameReport;
use crate::udp::{DatagramError, UdpMediaSocket};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedUnicastSenderConfig {
    destination: SocketAddr,
    presentation_id: u64,
    stream_id: u32,
    epoch: GroupMediaEpoch,
}

impl ProtectedUnicastSenderConfig {
    pub fn new(
        destination: SocketAddr,
        presentation_id: u64,
        stream_id: u32,
        epoch: GroupMediaEpoch,
    ) -> Result<Self, ProtectedUnicastSendError> {
        if destination.port() == 0 {
            return Err(ProtectedUnicastSendError::InvalidPort);
        }
        if invalid_unicast_destination(destination.ip()) {
            return Err(ProtectedUnicastSendError::InvalidDestination);
        }
        if presentation_id == 0 {
            return Err(ProtectedUnicastSendError::InvalidPresentationId);
        }
        if stream_id == 0 {
            return Err(ProtectedUnicastSendError::InvalidStreamId);
        }

        Ok(Self {
            destination,
            presentation_id,
            stream_id,
            epoch,
        })
    }

    #[must_use]
    pub const fn destination(self) -> SocketAddr {
        self.destination
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
    pub const fn local_bind(self) -> SocketAddr {
        match self.destination {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        }
    }

    fn protected_binding(self) -> ProtectedMediaBinding {
        ProtectedMediaBinding::new(self.presentation_id, self.stream_id, self.epoch)
    }
}

fn invalid_unicast_destination(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_unspecified() || address.is_multicast() || address == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(address) => address.is_unspecified() || address.is_multicast(),
    }
}

#[derive(Debug)]
pub enum ProtectedUnicastSendError {
    InvalidDestination,
    InvalidPort,
    InvalidPresentationId,
    InvalidStreamId,
    ProtocolVersionOutOfRange,
    FrameBindingMismatch,
    UnsupportedCodec,
    Security(GroupMediaError),
    Coordinator(GroupMediaCoordinatorError),
    Packetize(PacketizeError),
    Datagram(DatagramError),
    ShortDatagramWrite,
}

impl fmt::Display for ProtectedUnicastSendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDestination => {
                formatter.write_str("protected unicast destination must be a unicast IP address")
            }
            Self::InvalidPort => {
                formatter.write_str("protected unicast destination port must be non-zero")
            }
            Self::InvalidPresentationId => {
                formatter.write_str("protected unicast presentation id must be non-zero")
            }
            Self::InvalidStreamId => {
                formatter.write_str("protected unicast stream id must be non-zero")
            }
            Self::ProtocolVersionOutOfRange => {
                formatter.write_str("protocol version does not fit the media header")
            }
            Self::FrameBindingMismatch => {
                formatter.write_str("sealed group-media frame does not match unicast sender")
            }
            Self::UnsupportedCodec => {
                formatter.write_str("protected presentation unicast sender requires H.264")
            }
            Self::Security(error) => write!(formatter, "group-media binding: {error}"),
            Self::Coordinator(error) => write!(formatter, "group-media coordinator: {error}"),
            Self::Packetize(error) => {
                write!(
                    formatter,
                    "protected unicast packetization failed: {error:?}"
                )
            }
            Self::Datagram(error) => {
                write!(formatter, "protected unicast UDP send failed: {error}")
            }
            Self::ShortDatagramWrite => formatter
                .write_str("protected unicast UDP write did not send the complete datagram"),
        }
    }
}

impl std::error::Error for ProtectedUnicastSendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Datagram(error) => Some(error),
            Self::Security(error) => Some(error),
            Self::Coordinator(error) => Some(error),
            Self::InvalidDestination
            | Self::InvalidPort
            | Self::InvalidPresentationId
            | Self::InvalidStreamId
            | Self::ProtocolVersionOutOfRange
            | Self::FrameBindingMismatch
            | Self::UnsupportedCodec
            | Self::Packetize(_)
            | Self::ShortDatagramWrite => None,
        }
    }
}

impl From<ProtectedMediaCoreError> for ProtectedUnicastSendError {
    fn from(value: ProtectedMediaCoreError) -> Self {
        match value {
            ProtectedMediaCoreError::ProtocolVersionOutOfRange => Self::ProtocolVersionOutOfRange,
            ProtectedMediaCoreError::FrameBindingMismatch => Self::FrameBindingMismatch,
            ProtectedMediaCoreError::UnsupportedCodec => Self::UnsupportedCodec,
            ProtectedMediaCoreError::Security(error) => Self::Security(error),
            ProtectedMediaCoreError::Coordinator(error) => Self::Coordinator(error),
            ProtectedMediaCoreError::Packetize(error) => Self::Packetize(error),
            ProtectedMediaCoreError::Datagram(error) => Self::Datagram(error),
            ProtectedMediaCoreError::ShortDatagramWrite => Self::ShortDatagramWrite,
        }
    }
}

impl From<DatagramError> for ProtectedUnicastSendError {
    fn from(value: DatagramError) -> Self {
        Self::Datagram(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedUnicastBackpressureDrop {
    pub frame_id: u64,
    pub packets_sent: usize,
    pub packets_total: usize,
}

impl From<ProtectedMediaBackpressureDrop> for ProtectedUnicastBackpressureDrop {
    fn from(value: ProtectedMediaBackpressureDrop) -> Self {
        Self {
            frame_id: value.frame_id,
            packets_sent: value.packets_sent,
            packets_total: value.packets_total,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectedUnicastTrySendOutcome {
    Sent(SendFrameReport),
    DroppedBackpressure(ProtectedUnicastBackpressureDrop),
}

impl From<ProtectedMediaTrySendOutcome> for ProtectedUnicastTrySendOutcome {
    fn from(value: ProtectedMediaTrySendOutcome) -> Self {
        match value {
            ProtectedMediaTrySendOutcome::Sent(report) => Self::Sent(report),
            ProtectedMediaTrySendOutcome::DroppedBackpressure(drop) => {
                Self::DroppedBackpressure(drop.into())
            }
        }
    }
}

/// Fail-fast protected UDP-unicast sender for one explicit presentation outlier.
///
/// The destination must be derived by the caller from the authenticated receiver peer plus the
/// validated port-only fallback offer. This type owns no receiver identity, authorization state,
/// fallback policy or retransmission cache.
#[derive(Debug)]
pub struct ProtectedUnicastFrameSender {
    socket: UdpMediaSocket,
    config: ProtectedUnicastSenderConfig,
    packetizer: ProtectedMediaPacketizer,
}

impl ProtectedUnicastFrameSender {
    pub fn bind_nonblocking(
        config: ProtectedUnicastSenderConfig,
    ) -> Result<Self, ProtectedUnicastSendError> {
        let socket = UdpMediaSocket::bind(config.local_bind())?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            config,
            packetizer: ProtectedMediaPacketizer::new(config.protected_binding()),
        })
    }

    pub fn try_send_shared_h264_frame(
        &mut self,
        coordinator: &mut GroupMediaCoordinator,
        authorization: &AuthorizationStore,
        frame: &SharedEncodedFrame,
    ) -> Result<ProtectedUnicastTrySendOutcome, ProtectedUnicastSendError> {
        let sealed = protect_shared_h264_frame(
            self.config.protected_binding(),
            coordinator,
            authorization,
            frame,
        )?;
        self.try_send_frame(&sealed)
    }

    pub fn try_send_frame(
        &mut self,
        frame: &SealedGroupMediaFrame,
    ) -> Result<ProtectedUnicastTrySendOutcome, ProtectedUnicastSendError> {
        let prepared = self.packetizer.packetize(frame)?;
        try_send_prepared_frame(frame, &prepared, |packet| {
            self.socket
                .send_packet_to(packet, self.config.destination())
        })
        .map(Into::into)
        .map_err(Into::into)
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ProtectedUnicastSendError> {
        self.socket.local_addr().map_err(Into::into)
    }

    #[must_use]
    pub const fn destination(&self) -> SocketAddr {
        self.config.destination()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::Duration;

    use classmesh_security::group_media::{
        GroupMediaFrameBinding, GroupMediaKeyMaterial, GroupMediaSender,
    };

    use super::*;

    fn epoch(value: u32) -> GroupMediaEpoch {
        GroupMediaEpoch::new(value).expect("non-zero epoch")
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    fn config(destination: SocketAddr, epoch: GroupMediaEpoch) -> ProtectedUnicastSenderConfig {
        ProtectedUnicastSenderConfig::new(destination, 700, 800, epoch)
            .expect("valid unicast sender config")
    }

    fn sealed_frame(
        presentation_id: u64,
        stream_id: u32,
        epoch: GroupMediaEpoch,
        frame_id: u64,
        bytes: usize,
    ) -> SealedGroupMediaFrame {
        let material = GroupMediaKeyMaterial::generate().expect("test key");
        let mut sender = GroupMediaSender::new(epoch, &material).expect("test sender");
        let binding = GroupMediaFrameBinding::new(
            presentation_id,
            stream_id,
            epoch,
            frame_id,
            frame_id.saturating_mul(33_333),
            frame_id == 1,
        )
        .expect("valid binding");
        sender
            .seal_bound_frame(&vec![0x5a; bytes], binding)
            .expect("sealed frame")
    }

    #[test]
    fn config_rejects_non_unicast_destination_and_invalid_binding() {
        for destination in [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 50_000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 50_000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)), 50_000),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 50_000),
            SocketAddr::new(
                IpAddr::V6("ff02::1".parse::<Ipv6Addr>().expect("multicast IPv6")),
                50_000,
            ),
        ] {
            assert!(matches!(
                ProtectedUnicastSenderConfig::new(destination, 700, 800, epoch(1)),
                Err(ProtectedUnicastSendError::InvalidDestination)
            ));
        }

        assert!(matches!(
            ProtectedUnicastSenderConfig::new(loopback(0), 700, 800, epoch(1)),
            Err(ProtectedUnicastSendError::InvalidPort)
        ));
        assert!(matches!(
            ProtectedUnicastSenderConfig::new(loopback(50_000), 0, 800, epoch(1)),
            Err(ProtectedUnicastSendError::InvalidPresentationId)
        ));
        assert!(matches!(
            ProtectedUnicastSenderConfig::new(loopback(50_000), 700, 0, epoch(1)),
            Err(ProtectedUnicastSendError::InvalidStreamId)
        ));
    }

    #[test]
    fn binding_mismatch_fails_before_any_datagram_is_sent() {
        let receiver = UdpMediaSocket::bind(loopback(0)).expect("receiver binds");
        let destination = receiver.local_addr().expect("receiver address");
        let active_epoch = epoch(2);
        let mut sender =
            ProtectedUnicastFrameSender::bind_nonblocking(config(destination, active_epoch))
                .expect("sender binds");

        let wrong = sealed_frame(701, 800, active_epoch, 1, 128);
        assert!(matches!(
            sender.try_send_frame(&wrong),
            Err(ProtectedUnicastSendError::FrameBindingMismatch)
        ));
    }

    #[test]
    fn loopback_sender_delivers_protected_frame_without_retransmit_cache() {
        let receiver = UdpMediaSocket::bind(loopback(0)).expect("receiver binds");
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("receiver timeout");
        let destination = receiver.local_addr().expect("receiver address");
        let active_epoch = epoch(3);
        let mut sender =
            ProtectedUnicastFrameSender::bind_nonblocking(config(destination, active_epoch))
                .expect("sender binds");

        let sealed = sealed_frame(700, 800, active_epoch, 1, 4_000);
        let outcome = sender.try_send_frame(&sealed).expect("frame sends");
        let ProtectedUnicastTrySendOutcome::Sent(report) = outcome else {
            panic!("loopback send should fit without backpressure");
        };
        assert!(report.packets > 1);

        for _ in 0..report.packets {
            let (packet, _) = receiver.receive_packet().expect("packet receives");
            assert_eq!(packet.header.stream_id, 800);
            assert_eq!(packet.header.frame_id, 1);
        }
    }
}
