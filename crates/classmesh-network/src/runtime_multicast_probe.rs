use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use classmesh_protocol::PROTOCOL_VERSION;
use classmesh_protocol::media::{MediaFlags, MediaPacketHeader};

use crate::multicast::{
    MulticastContractError, MulticastMembership, MulticastProbeObservation, MulticastProbeOutcome,
    evaluate_multicast_probe,
};
use crate::udp::{DatagramError, UdpMediaSocket};
use crate::MediaPacket;

const RUNTIME_PROBE_GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 67, 77);
const RUNTIME_PROBE_TAG: &[u8; 8] = b"CMRTPR01";
const RUNTIME_PROBE_TOKEN_BYTES: usize = 16;
const RUNTIME_PROBE_STREAM_ID: u32 = 0xffff_ff02;
const RUNTIME_PROBE_READ_SLICE: Duration = Duration::from_millis(50);
pub const DEFAULT_RUNTIME_MULTICAST_PROBE_TIMEOUT: Duration = Duration::from_millis(500);
pub const MIN_RUNTIME_MULTICAST_PROBE_TIMEOUT: Duration = Duration::from_millis(100);
pub const MAX_RUNTIME_MULTICAST_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum RuntimeMulticastProbeError {
    InvalidInterface(MulticastContractError),
    InvalidTimeout,
    TokenGeneration,
    Socket(DatagramError),
    ProtocolVersionOutOfRange,
}

impl fmt::Display for RuntimeMulticastProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInterface(error) => {
                write!(formatter, "invalid multicast probe interface: {error:?}")
            }
            Self::InvalidTimeout => formatter.write_str("multicast probe timeout is out of bounds"),
            Self::TokenGeneration => {
                formatter.write_str("secure multicast probe token generation failed")
            }
            Self::Socket(error) => write!(formatter, "multicast probe socket failed: {error}"),
            Self::ProtocolVersionOutOfRange => {
                formatter.write_str("protocol version does not fit multicast probe header")
            }
        }
    }
}

impl std::error::Error for RuntimeMulticastProbeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Socket(error) => Some(error),
            Self::InvalidInterface(_)
            | Self::InvalidTimeout
            | Self::TokenGeneration
            | Self::ProtocolVersionOutOfRange => None,
        }
    }
}

impl From<DatagramError> for RuntimeMulticastProbeError {
    fn from(value: DatagramError) -> Self {
        Self::Socket(value)
    }
}

/// Performs a bounded host-local multicast stack probe on one explicitly selected IPv4 interface.
///
/// This is runtime capability evidence only. It proves that this process can join an
/// administratively-scoped IPv4 group, observe an exact self-looped probe datagram on the selected
/// interface, and leave the group cleanly. It does not prove that classroom switching/IGMP paths
/// work between two machines and therefore never satisfies the Phase 7D physical gate.
pub fn probe_local_multicast_interface(
    interface: Ipv4Addr,
) -> Result<MulticastProbeOutcome, RuntimeMulticastProbeError> {
    probe_local_multicast_interface_with_timeout(interface, DEFAULT_RUNTIME_MULTICAST_PROBE_TIMEOUT)
}

pub fn probe_local_multicast_interface_with_timeout(
    interface: Ipv4Addr,
    timeout: Duration,
) -> Result<MulticastProbeOutcome, RuntimeMulticastProbeError> {
    if !(MIN_RUNTIME_MULTICAST_PROBE_TIMEOUT..=MAX_RUNTIME_MULTICAST_PROBE_TIMEOUT)
        .contains(&timeout)
    {
        return Err(RuntimeMulticastProbeError::InvalidTimeout);
    }

    let membership = MulticastMembership::new(RUNTIME_PROBE_GROUP, interface)
        .map_err(RuntimeMulticastProbeError::InvalidInterface)?;
    let receiver = UdpMediaSocket::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        0,
    )))?;
    receiver.set_read_timeout(Some(RUNTIME_PROBE_READ_SLICE))?;
    let receiver_port = receiver.local_addr()?.port();

    if receiver
        .join_multicast_v4(membership.group(), membership.interface())
        .is_err()
    {
        return Ok(MulticastProbeOutcome::Unavailable(
            crate::multicast::MulticastProbeFailure::JoinFailed,
        ));
    }

    let mut token = [0_u8; RUNTIME_PROBE_TOKEN_BYTES];
    if getrandom::fill(&mut token).is_err() {
        let _ = receiver.leave_multicast_v4(membership.group(), membership.interface());
        return Err(RuntimeMulticastProbeError::TokenGeneration);
    }

    let observed = send_and_observe(
        &receiver,
        membership,
        receiver_port,
        token,
        timeout,
    );
    let left_cleanly = receiver
        .leave_multicast_v4(membership.group(), membership.interface())
        .is_ok();

    Ok(evaluate_multicast_probe(MulticastProbeObservation {
        joined: true,
        probe_datagram_observed: observed,
        left_cleanly,
    }))
}

fn send_and_observe(
    receiver: &UdpMediaSocket,
    membership: MulticastMembership,
    receiver_port: u16,
    token: [u8; RUNTIME_PROBE_TOKEN_BYTES],
    timeout: Duration,
) -> bool {
    let sender = match UdpMediaSocket::bind(SocketAddr::V4(SocketAddrV4::new(
        membership.interface(),
        0,
    ))) {
        Ok(sender) => sender,
        Err(_) => return false,
    };
    if sender
        .set_write_timeout(Some(RUNTIME_PROBE_READ_SLICE))
        .and_then(|_| sender.set_multicast_interface_v4(membership.interface()))
        .and_then(|_| sender.set_multicast_loop_v4(true))
        .and_then(|_| sender.set_multicast_ttl_v4(1))
        .is_err()
    {
        return false;
    }

    let packet = match runtime_probe_packet(token) {
        Ok(packet) => packet,
        Err(_) => return false,
    };
    let destination = SocketAddr::V4(SocketAddrV4::new(membership.group(), receiver_port));
    if sender.send_packet_to(&packet, destination).is_err() {
        return false;
    }

    let deadline = match Instant::now().checked_add(timeout) {
        Some(deadline) => deadline,
        None => return false,
    };
    while Instant::now() < deadline {
        match receiver.receive_packet() {
            Ok((packet, source))
                if source.ip() == IpAddr::V4(membership.interface())
                    && runtime_probe_packet_matches(&packet, token) =>
            {
                return true;
            }
            Ok(_) => {}
            Err(DatagramError::Io(error))
                if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
            Err(_) => {}
        }
    }
    false
}

fn runtime_probe_packet(
    token: [u8; RUNTIME_PROBE_TOKEN_BYTES],
) -> Result<MediaPacket, RuntimeMulticastProbeError> {
    let protocol_major = u8::try_from(PROTOCOL_VERSION.major)
        .map_err(|_| RuntimeMulticastProbeError::ProtocolVersionOutOfRange)?;
    let protocol_minor = u8::try_from(PROTOCOL_VERSION.minor)
        .map_err(|_| RuntimeMulticastProbeError::ProtocolVersionOutOfRange)?;
    let mut payload = Vec::with_capacity(RUNTIME_PROBE_TAG.len() + RUNTIME_PROBE_TOKEN_BYTES);
    payload.extend_from_slice(RUNTIME_PROBE_TAG);
    payload.extend_from_slice(&token);

    Ok(MediaPacket {
        header: MediaPacketHeader {
            protocol_major,
            protocol_minor,
            flags: MediaFlags::FRAME_START | MediaFlags::FRAME_END,
            stream_id: RUNTIME_PROBE_STREAM_ID,
            frame_id: 1,
            sequence: 1,
            packet_index: 0,
            packet_count: 1,
            timestamp_us: 0,
            payload_len: u16::try_from(payload.len()).expect("runtime probe payload is bounded"),
        },
        payload,
    })
}

fn runtime_probe_packet_matches(
    packet: &MediaPacket,
    token: [u8; RUNTIME_PROBE_TOKEN_BYTES],
) -> bool {
    let Ok(protocol_major) = u8::try_from(PROTOCOL_VERSION.major) else {
        return false;
    };
    let Ok(protocol_minor) = u8::try_from(PROTOCOL_VERSION.minor) else {
        return false;
    };
    packet.header.protocol_major == protocol_major
        && packet.header.protocol_minor == protocol_minor
        && packet.header.stream_id == RUNTIME_PROBE_STREAM_ID
        && packet.header.packet_index == 0
        && packet.header.packet_count == 1
        && packet.payload.len() == RUNTIME_PROBE_TAG.len() + RUNTIME_PROBE_TOKEN_BYTES
        && packet.payload.starts_with(RUNTIME_PROBE_TAG)
        && packet.payload[RUNTIME_PROBE_TAG.len()..] == token
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_probe_packet_requires_exact_version_stream_tag_and_token() {
        let token = [0x5a; RUNTIME_PROBE_TOKEN_BYTES];
        let packet = runtime_probe_packet(token).expect("probe packet");
        assert!(runtime_probe_packet_matches(&packet, token));

        let mut wrong_stream = packet.clone();
        wrong_stream.header.stream_id = 7;
        assert!(!runtime_probe_packet_matches(&wrong_stream, token));

        let mut wrong_payload = packet.clone();
        wrong_payload.payload[0] ^= 1;
        assert!(!runtime_probe_packet_matches(&wrong_payload, token));
        assert!(!runtime_probe_packet_matches(
            &packet,
            [0xa5; RUNTIME_PROBE_TOKEN_BYTES]
        ));
    }

    #[test]
    fn runtime_probe_rejects_invalid_interface_before_socket_io() {
        for interface in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(239, 1, 2, 3),
        ] {
            assert!(matches!(
                probe_local_multicast_interface_with_timeout(
                    interface,
                    DEFAULT_RUNTIME_MULTICAST_PROBE_TIMEOUT,
                ),
                Err(RuntimeMulticastProbeError::InvalidInterface(_))
            ));
        }
    }

    #[test]
    fn runtime_probe_timeout_is_bounded_before_socket_io() {
        let interface = Ipv4Addr::new(192, 0, 2, 10);
        assert!(matches!(
            probe_local_multicast_interface_with_timeout(
                interface,
                MIN_RUNTIME_MULTICAST_PROBE_TIMEOUT - Duration::from_millis(1),
            ),
            Err(RuntimeMulticastProbeError::InvalidTimeout)
        ));
        assert!(matches!(
            probe_local_multicast_interface_with_timeout(
                interface,
                MAX_RUNTIME_MULTICAST_PROBE_TIMEOUT + Duration::from_millis(1),
            ),
            Err(RuntimeMulticastProbeError::InvalidTimeout)
        ));
    }
}
