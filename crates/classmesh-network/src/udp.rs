use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

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
        let mut buffer = [0_u8; MAX_MEDIA_DATAGRAM];
        let (read, source) = self.socket.recv_from(&mut buffer)?;
        Ok((decode_datagram(&buffer[..read])?, source))
    }

    pub fn local_addr(&self) -> Result<SocketAddr, DatagramError> {
        Ok(self.socket.local_addr()?)
    }
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
    fn payload_length_mismatch_is_rejected() {
        let mut invalid = packet();
        invalid.header.payload_len = 3;
        assert!(matches!(
            encode_datagram(&invalid),
            Err(DatagramError::PayloadLengthMismatch)
        ));
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
