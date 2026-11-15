use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use socket2::SockRef;

use classmesh_protocol::media::{
    MAX_PACKET_PAYLOAD, MEDIA_HEADER_LEN, MediaHeaderError, MediaPacketHeader,
};

use crate::MediaPacket;

pub const MAX_MEDIA_DATAGRAM: usize = MEDIA_HEADER_LEN + MAX_PACKET_PAYLOAD;

#[derive(Debug)]
pub enum DatagramError {
    Io(io::Error),
    Header(MediaHeaderError),
    PayloadLengthMismatch,
    DatagramTooLarge,
}

impl fmt::Display for DatagramError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "UDP media I/O error: {error}"),
            Self::Header(error) => write!(formatter, "invalid media packet header: {error:?}"),
            Self::PayloadLengthMismatch => {
                formatter.write_str("media packet payload length mismatch")
            }
            Self::DatagramTooLarge => {
                formatter.write_str("media UDP datagram exceeds ClassMesh MTU")
            }
        }
    }
}

impl std::error::Error for DatagramError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Header(_) | Self::PayloadLengthMismatch | Self::DatagramTooLarge => None,
        }
    }
}

impl From<io::Error> for DatagramError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<MediaHeaderError> for DatagramError {
    fn from(value: MediaHeaderError) -> Self {
        Self::Header(value)
    }
}

pub fn encode_datagram(packet: &MediaPacket) -> Result<Vec<u8>, DatagramError> {
    if packet.payload.len() != usize::from(packet.header.payload_len) {
        return Err(DatagramError::PayloadLengthMismatch);
    }
    if packet.payload.len() > MAX_PACKET_PAYLOAD {
        return Err(DatagramError::DatagramTooLarge);
    }
    let header = packet.header.encode()?;
    let mut output = Vec::with_capacity(MEDIA_HEADER_LEN + packet.payload.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(&packet.payload);
    Ok(output)
}

pub fn decode_datagram(data: &[u8]) -> Result<MediaPacket, DatagramError> {
    if data.len() < MEDIA_HEADER_LEN {
        return Err(MediaHeaderError::Truncated.into());
    }
    if data.len() > MAX_MEDIA_DATAGRAM {
        return Err(DatagramError::DatagramTooLarge);
    }
    let header = MediaPacketHeader::decode(&data[..MEDIA_HEADER_LEN])?;
    let payload = &data[MEDIA_HEADER_LEN..];
    if payload.len() != usize::from(header.payload_len) {
        return Err(DatagramError::PayloadLengthMismatch);
    }
    Ok(MediaPacket {
        header,
        payload: payload.to_vec(),
    })
}

/// Thin UDP socket wrapper. Congestion/adaptation policy intentionally lives above this type.
#[derive(Debug)]
pub struct UdpMediaSocket {
    socket: UdpSocket,
}

impl UdpMediaSocket {
    pub fn bind(address: SocketAddr) -> Result<Self, DatagramError> {
        let socket = UdpSocket::bind(address)?;
        Ok(Self { socket })
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), DatagramError> {
        self.socket.set_read_timeout(timeout)?;
        Ok(())
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<(), DatagramError> {
        self.socket.set_write_timeout(timeout)?;
        Ok(())
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), DatagramError> {
        self.socket.set_nonblocking(nonblocking)?;
        Ok(())
    }

    pub fn set_multicast_ttl_v4(&self, ttl: u32) -> Result<(), DatagramError> {
        self.socket.set_multicast_ttl_v4(ttl)?;
        Ok(())
    }

    pub fn set_multicast_loop_v4(&self, enabled: bool) -> Result<(), DatagramError> {
        self.socket.set_multicast_loop_v4(enabled)?;
        Ok(())
    }

    pub fn set_multicast_interface_v4(&self, interface: Ipv4Addr) -> Result<(), DatagramError> {
        SockRef::from(&self.socket).set_multicast_if_v4(&interface)?;
        Ok(())
    }

    pub fn join_multicast_v4(
        &self,
        group: Ipv4Addr,
        interface: Ipv4Addr,
    ) -> Result<(), DatagramError> {
        self.socket.join_multicast_v4(&group, &interface)?;
        Ok(())
    }

    pub fn leave_multicast_v4(
        &self,
        group: Ipv4Addr,
        interface: Ipv4Addr,
    ) -> Result<(), DatagramError> {
        self.socket.leave_multicast_v4(&group, &interface)?;
        Ok(())
    }

    pub fn send_packet_to(
        &self,
        packet: &MediaPacket,
        destination: SocketAddr,
    ) -> Result<usize, DatagramError> {
        let datagram = encode_datagram(packet)?;
        Ok(self.socket.send_to(&datagram, destination)?)
    }

    pub fn receive_packet(&self) -> Result<(MediaPacket, SocketAddr), DatagramError> {
        // A receive buffer at the protocol limit can make a truncated UDP
        // datagram indistinguishable from a valid maximum-size datagram.
        let mut buffer = [0_u8; MAX_MEDIA_DATAGRAM + 1];
        let (read, source) = self.socket.recv_from(&mut buffer).map_err(receive_error)?;
        Ok((decode_datagram(&buffer[..read])?, source))
    }

    pub fn local_addr(&self) -> Result<SocketAddr, DatagramError> {
        Ok(self.socket.local_addr()?)
    }
}

fn receive_error(error: io::Error) -> DatagramError {
    #[cfg(windows)]
    {
        // Winsock consumes the oversized datagram and reports WSAEMSGSIZE
        // instead of returning its truncated prefix from recvfrom.
        const WSAEMSGSIZE: i32 = 10040;
        if error.raw_os_error() == Some(WSAEMSGSIZE) {
            return DatagramError::DatagramTooLarge;
        }
    }
    DatagramError::Io(error)
}

#[must_use]
pub const fn is_ipv4_multicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_multicast(),
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use classmesh_protocol::media::MediaFlags;

    use super::*;
    use crate::receiver::{ReceiverEvent, ReceiverPolicy};
    use crate::transport::UdpFrameReceiver;

    fn packet() -> MediaPacket {
        MediaPacket {
            header: MediaPacketHeader {
                protocol_major: 0,
                protocol_minor: 1,
                flags: MediaFlags::FRAME_START | MediaFlags::FRAME_END,
                stream_id: 9,
                frame_id: 4,
                sequence: 8,
                packet_index: 0,
                packet_count: 1,
                timestamp_us: 55,
                payload_len: 4,
            },
            payload: vec![1, 2, 3, 4],
        }
    }

    #[test]
    fn datagram_round_trip_preserves_header_and_payload() {
        let original = packet();
        let encoded = encode_datagram(&original).expect("packet should encode");
        assert!(encoded.len() <= MAX_MEDIA_DATAGRAM);
        let decoded = decode_datagram(&encoded).expect("packet should decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn oversized_datagrams_are_rejected_without_losing_the_next_valid_packet() {
        let receiver = UdpMediaSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let destination = receiver.local_addr().unwrap();
        let mut frame = packet();
        frame.payload.resize(MAX_PACKET_PAYLOAD, 0x5a);
        frame.header.payload_len = u16::try_from(frame.payload.len()).unwrap();
        let valid = encode_datagram(&frame).unwrap();
        assert_eq!(valid.len(), MAX_MEDIA_DATAGRAM);

        let oversized = [1, 128].map(|extra| {
            let mut datagram = valid.clone();
            datagram.resize(valid.len() + extra, 0);
            sender.send_to(&datagram, destination).unwrap();
            receiver.receive_packet()
        });
        sender.send_to(&valid, destination).unwrap();
        assert_eq!(receiver.receive_packet().unwrap().0, frame);
        assert!(
            oversized
                .iter()
                .all(|result| matches!(result, Err(DatagramError::DatagramTooLarge))),
            "both datagrams must be classified as malformed: {:?}",
            oversized.map(|result| result.map(|(packet, _)| packet.payload.len()))
        );
    }

    #[test]
    fn fresh_fragments_survive_a_receive_wait_longer_than_the_expiry() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let observer = socket.try_clone().unwrap();
        let mut receiver =
            UdpFrameReceiver::new(UdpMediaSocket { socket }, ReceiverPolicy::default());
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let destination = receiver.local_addr().unwrap();
        let sender = UdpMediaSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut fragment = packet();
        fragment.header.flags = MediaFlags::FRAME_START;
        fragment.header.packet_count = 2;
        sender.send_packet_to(&fragment, destination).unwrap();

        // Use the real socket's queue to distinguish pre-read and post-read
        // times without relying on thread scheduling or a wall-clock delay.
        let mut buffer = [0_u8; MAX_MEDIA_DATAGRAM];
        observer.peek_from(&mut buffer).unwrap();
        let first = receiver
            .receive_once_with_clock(|| {
                observer.set_nonblocking(true).unwrap();
                let pending = observer.peek_from(&mut buffer);
                observer.set_nonblocking(false).unwrap();
                match pending {
                    Ok(_) => 0,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => 100_000,
                    Err(error) => panic!("socket peek failed: {error}"),
                }
            })
            .unwrap();
        assert!(first.events.is_empty());
        let events = receiver.tick(100_001);
        assert!(events.is_empty(), "fresh pending frame expired: {events:?}");

        fragment.header.flags = MediaFlags::FRAME_END;
        fragment.header.packet_index = 1;
        fragment.header.sequence += 1;
        sender.send_packet_to(&fragment, destination).unwrap();
        let completed = receiver.receive_once_with_clock(|| 100_002).unwrap();
        assert!(matches!(
            &completed.events[..],
            [ReceiverEvent::FrameReady(frame)] if frame.data == [1, 2, 3, 4, 1, 2, 3, 4]
        ));
    }

    #[test]
    fn payload_length_mismatch_is_rejected() {
        let mut invalid = packet();
        invalid.header.payload_len = 3;
        assert!(matches!(
            encode_datagram(&invalid),
            Err(DatagramError::PayloadLengthMismatch)
        ));
    }

    #[test]
    fn datagram_error_is_usable_as_standard_error() {
        let error = DatagramError::PayloadLengthMismatch;
        assert!(error.to_string().contains("payload length"));
    }

    #[test]
    fn classroom_multicast_range_is_detected() {
        assert!(is_ipv4_multicast(IpAddr::V4(Ipv4Addr::new(
            239, 10, 20, 30
        ))));
        assert!(!is_ipv4_multicast(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 20
        ))));
    }
}
