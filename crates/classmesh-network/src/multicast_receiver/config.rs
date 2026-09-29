use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::multicast::{MulticastMembership, MulticastProbeOutcome};
use crate::udp::DatagramError;

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
