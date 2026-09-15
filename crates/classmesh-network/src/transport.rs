use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use classmesh_protocol::PROTOCOL_VERSION;
use classmesh_video::distributor::SharedEncodedFrame;
use classmesh_video::Codec;

use crate::receiver::{ReceiverEvent, ReceiverPolicy, ReceiverWindow};
use crate::reliability::{RetransmitCache, SequenceObservation, SequenceTracker};
use crate::udp::{DatagramError, UdpMediaSocket};
use crate::{PacketizeError, PacketizeMeta, packetize_frame};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSenderConfig {
    pub stream_id: u32,
    pub destination: SocketAddr,
    pub retransmit_max_packets: usize,
    pub retransmit_max_age_us: u64,
}

impl UdpSenderConfig {
    #[must_use]
    pub const fn presentation(stream_id: u32, destination: SocketAddr) -> Self {
        Self {
            stream_id,
            destination,
            retransmit_max_packets: 2_048,
            retransmit_max_age_us: 250_000,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpSenderStats {
    pub frames_sent: u64,
    pub packets_sent: u64,
    pub payload_bytes_sent: u64,
    pub retransmit_packets_sent: u64,
    pub retransmit_cache_misses: u64,
}

#[derive(Debug)]
pub enum UdpSendError {
    Datagram(DatagramError),
    Packetize(PacketizeError),
    UnsupportedCodec,
    ProtocolVersionOutOfRange,
}

impl From<DatagramError> for UdpSendError {
    fn from(value: DatagramError) -> Self {
        Self::Datagram(value)
    }
}

impl From<PacketizeError> for UdpSendError {
    fn from(value: PacketizeError) -> Self {
        Self::Packetize(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendFrameReport {
    pub frame_id: u64,
    pub packets: usize,
    pub payload_bytes: usize,
    pub first_sequence: u32,
    pub next_sequence: u32,
}

/// Packetizes one already-encoded ClassMesh frame and sends it over UDP without retaining an
/// unbounded media queue. Recent packets are kept only inside a short retransmission cache for NACK
/// recovery; media older than that window is intentionally allowed to expire.
#[derive(Debug)]
pub struct UdpFrameSender {
    socket: UdpMediaSocket,
    config: UdpSenderConfig,
    next_sequence: u32,
    retransmit: RetransmitCache,
    stats: UdpSenderStats,
}

impl UdpFrameSender {
    pub fn bind(local: SocketAddr, config: UdpSenderConfig) -> Result<Self, UdpSendError> {
        let socket = UdpMediaSocket::bind(local)?;
        Ok(Self::new(socket, config))
    }

    #[must_use]
    pub fn new(socket: UdpMediaSocket, config: UdpSenderConfig) -> Self {
        Self {
            socket,
            config,
            next_sequence: 0,
            retransmit: RetransmitCache::new(
                config.retransmit_max_packets,
                config.retransmit_max_age_us,
            ),
            stats: UdpSenderStats::default(),
        }
    }

    pub fn send_frame(
        &mut self,
        now_us: u64,
        frame: &SharedEncodedFrame,
    ) -> Result<SendFrameReport, UdpSendError> {
        if frame.codec != Codec::H264 {
            return Err(UdpSendError::UnsupportedCodec);
        }
        let major = u8::try_from(PROTOCOL_VERSION.major)
            .map_err(|_| UdpSendError::ProtocolVersionOutOfRange)?;
        let minor = u8::try_from(PROTOCOL_VERSION.minor)
            .map_err(|_| UdpSendError::ProtocolVersionOutOfRange)?;
        let first_sequence = self.next_sequence;
        let packets = packetize_frame(
            &frame.data,
            PacketizeMeta {
                protocol_major: major,
                protocol_minor: minor,
                stream_id: self.config.stream_id,
                frame_id: frame.meta.frame_id,
                first_sequence,
                timestamp_us: frame.meta.timestamp_us,
                keyframe: frame.meta.keyframe,
            },
        )?;
        let payload_bytes = frame.data.len();

        for packet in &packets {
            self.socket.send_packet_to(packet, self.config.destination)?;
            self.retransmit.insert(now_us, packet.clone());
        }

        self.next_sequence = self
            .next_sequence
            .wrapping_add(u32::try_from(packets.len()).unwrap_or(u32::MAX));
        self.stats.frames_sent = self.stats.frames_sent.saturating_add(1);
        self.stats.packets_sent = self
            .stats
            .packets_sent
            .saturating_add(u64::try_from(packets.len()).unwrap_or(u64::MAX));
        self.stats.payload_bytes_sent = self
            .stats
            .payload_bytes_sent
            .saturating_add(u64::try_from(payload_bytes).unwrap_or(u64::MAX));

        Ok(SendFrameReport {
            frame_id: frame.meta.frame_id,
            packets: packets.len(),
            payload_bytes,
            first_sequence,
            next_sequence: self.next_sequence,
        })
    }

    /// Retransmits only packets that are still inside the bounded live-media cache.
    ///
    /// Missing cache entries are not fatal; the receiver should eventually request a keyframe
    /// rather than forcing old video to remain buffered indefinitely.
    pub fn retransmit_missing(
        &mut self,
        now_us: u64,
        frame_id: u64,
        missing_packet_indices: &[u16],
    ) -> Result<usize, UdpSendError> {
        self.retransmit.prune(now_us);
        let mut sent = 0_usize;
        for &packet_index in missing_packet_indices {
            let Some(packet) = self.retransmit.find(frame_id, packet_index) else {
                self.stats.retransmit_cache_misses =
                    self.stats.retransmit_cache_misses.saturating_add(1);
                continue;
            };
            self.socket.send_packet_to(packet, self.config.destination)?;
            sent = sent.saturating_add(1);
            self.stats.retransmit_packets_sent =
                self.stats.retransmit_packets_sent.saturating_add(1);
        }
        Ok(sent)
    }

    #[must_use]
    pub const fn stats(&self) -> UdpSenderStats {
        self.stats
    }

    pub fn local_addr(&self) -> Result<SocketAddr, UdpSendError> {
        Ok(self.socket.local_addr()?)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpReceiverStats {
    pub datagrams_received: u64,
    pub frames_completed: u64,
    pub sequence_gaps_observed: u64,
    pub reordered_or_duplicate: u64,
}

#[derive(Debug)]
pub struct UdpReceiveBatch {
    pub source: SocketAddr,
    pub sequence: SequenceObservation,
    pub events: Vec<ReceiverEvent>,
}

/// Receives one ClassMesh UDP media datagram at a time and feeds the bounded receiver window.
#[derive(Debug)]
pub struct UdpFrameReceiver {
    socket: UdpMediaSocket,
    window: ReceiverWindow,
    sequence: SequenceTracker,
    stats: UdpReceiverStats,
}

impl UdpFrameReceiver {
    pub fn bind(local: SocketAddr, policy: ReceiverPolicy) -> Result<Self, DatagramError> {
        let socket = UdpMediaSocket::bind(local)?;
        Ok(Self::new(socket, policy))
    }

    #[must_use]
    pub fn new(socket: UdpMediaSocket, policy: ReceiverPolicy) -> Self {
        Self {
            socket,
            window: ReceiverWindow::new(policy),
            sequence: SequenceTracker::default(),
            stats: UdpReceiverStats::default(),
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), DatagramError> {
        self.socket.set_read_timeout(timeout)
    }

    pub fn receive_once(&mut self, now_us: u64) -> Result<UdpReceiveBatch, DatagramError> {
        let (packet, source) = self.socket.receive_packet()?;
        let observation = self.sequence.observe(packet.header.sequence);
        self.stats.datagrams_received = self.stats.datagrams_received.saturating_add(1);
        match observation {
            SequenceObservation::Gap { .. } => {
                self.stats.sequence_gaps_observed =
                    self.stats.sequence_gaps_observed.saturating_add(1);
            }
            SequenceObservation::ReorderedOrDuplicate => {
                self.stats.reordered_or_duplicate =
                    self.stats.reordered_or_duplicate.saturating_add(1);
            }
            SequenceObservation::First | SequenceObservation::InOrder => {}
        }

        let events = self
            .window
            .push(now_us, &packet)
            .map_err(|error| DatagramError::Io(io::Error::new(io::ErrorKind::InvalidData, format!("frame assembly failed: {error:?}"))))?;
        self.stats.frames_completed = self.stats.frames_completed.saturating_add(
            u64::try_from(
                events
                    .iter()
                    .filter(|event| matches!(event, ReceiverEvent::FrameReady(_)))
                    .count(),
            )
            .unwrap_or(u64::MAX),
        );
        Ok(UdpReceiveBatch {
            source,
            sequence: observation,
            events,
        })
    }

    #[must_use]
    pub fn tick(&mut self, now_us: u64) -> Vec<ReceiverEvent> {
        self.window.tick(now_us)
    }

    #[must_use]
    pub const fn stats(&self) -> UdpReceiverStats {
        self.stats
    }

    pub fn local_addr(&self) -> Result<SocketAddr, DatagramError> {
        self.socket.local_addr()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use classmesh_video::distributor::SharedEncodedFrame;
    use classmesh_video::{Codec, EncodedFrameMeta};

    use super::*;

    fn loopback_any() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn frame(id: u64, bytes: usize) -> SharedEncodedFrame {
        SharedEncodedFrame::new(
            EncodedFrameMeta {
                frame_id: id,
                timestamp_us: id.saturating_mul(33_333),
                keyframe: id == 1,
            },
            Codec::H264,
            (0_u8..=250).cycle().take(bytes).collect(),
        )
    }

    #[test]
    fn loopback_sender_receiver_delivers_encoded_frame() {
        let mut receiver = UdpFrameReceiver::bind(loopback_any(), ReceiverPolicy::default())
            .expect("receiver binds");
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("timeout config");
        let destination = receiver.local_addr().expect("receiver address");
        let mut sender = UdpFrameSender::bind(
            loopback_any(),
            UdpSenderConfig::presentation(55, destination),
        )
        .expect("sender binds");
        let original = frame(1, 4_000);
        let report = sender.send_frame(10_000, &original).expect("frame sends");
        assert!(report.packets > 1);

        let mut completed = None;
        for index in 0..report.packets {
            let batch = receiver
                .receive_once(10_000 + u64::try_from(index).unwrap_or(0))
                .expect("datagram receives");
            for event in batch.events {
                if let ReceiverEvent::FrameReady(frame) = event {
                    completed = Some(frame);
                }
            }
        }

        let completed = completed.expect("frame must complete");
        assert_eq!(completed.frame_id, original.meta.frame_id);
        assert_eq!(completed.timestamp_us, original.meta.timestamp_us);
        assert_eq!(completed.data.as_slice(), original.data.as_ref());
        assert_eq!(sender.stats().frames_sent, 1);
        assert_eq!(receiver.stats().frames_completed, 1);
    }

    #[test]
    fn retransmit_cache_is_used_only_while_media_is_fresh() {
        let receiver = UdpFrameReceiver::bind(loopback_any(), ReceiverPolicy::default())
            .expect("receiver binds");
        let destination = receiver.local_addr().expect("receiver address");
        let mut config = UdpSenderConfig::presentation(8, destination);
        config.retransmit_max_age_us = 100;
        let mut sender = UdpFrameSender::bind(loopback_any(), config).expect("sender binds");
        let report = sender.send_frame(0, &frame(4, 2_000)).expect("frame sends");
        assert!(report.packets >= 2);

        let resent = sender
            .retransmit_missing(50, 4, &[0])
            .expect("fresh packet retransmits");
        assert_eq!(resent, 1);

        let expired = sender
            .retransmit_missing(1_000, 4, &[0])
            .expect("expired packet is a cache miss, not a transport failure");
        assert_eq!(expired, 0);
        assert_eq!(sender.stats().retransmit_cache_misses, 1);
    }
}
