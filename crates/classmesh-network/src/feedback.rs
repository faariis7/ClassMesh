use std::fmt;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use classmesh_protocol::feedback::{
    FEEDBACK_HEADER_LEN, FeedbackCodecError, FeedbackMessage, MAX_NACK_PACKET_INDICES,
};

use crate::receiver::ReceiverEvent;
use crate::transport::{UdpFrameSender, UdpSendError};

pub type MediaFeedback = FeedbackMessage;

const MAX_FEEDBACK_DATAGRAM: usize = FEEDBACK_HEADER_LEN + MAX_NACK_PACKET_INDICES * 2;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FeedbackOutcome {
    pub retransmitted_packets: usize,
    pub keyframe_requested: bool,
}

#[must_use]
pub fn from_receiver_events(events: &[ReceiverEvent]) -> Vec<MediaFeedback> {
    events
        .iter()
        .filter_map(|event| match event {
            ReceiverEvent::NeedNack {
                stream_id,
                frame_id,
                missing_packet_indices,
            } => Some(MediaFeedback::Nack {
                stream_id: *stream_id,
                frame_id: *frame_id,
                missing_packet_indices: missing_packet_indices.clone(),
            }),
            ReceiverEvent::NeedKeyframe {
                stream_id,
                after_frame_id,
            } => Some(MediaFeedback::RequestKeyframe {
                stream_id: *stream_id,
                after_frame_id: *after_frame_id,
            }),
            ReceiverEvent::FrameReady(_) | ReceiverEvent::DroppedStaleFrame { .. } => None,
        })
        .collect()
}

/// Applies transport feedback that can be handled locally by the sender.
///
/// NACKs are satisfied only from the short live retransmit cache. A keyframe request is surfaced to
/// the caller so the reliable control/encoder path can coalesce it with requests from other
/// receivers instead of directly coupling the UDP transport to a particular encoder backend.
pub fn apply_sender_feedback(
    sender: &mut UdpFrameSender,
    now_us: u64,
    feedback: &MediaFeedback,
) -> Result<FeedbackOutcome, UdpSendError> {
    match feedback {
        MediaFeedback::Nack {
            frame_id,
            missing_packet_indices,
            ..
        } => Ok(FeedbackOutcome {
            retransmitted_packets: sender.retransmit_missing(
                now_us,
                *frame_id,
                missing_packet_indices,
            )?,
            keyframe_requested: false,
        }),
        MediaFeedback::RequestKeyframe { .. } => Ok(FeedbackOutcome {
            retransmitted_packets: 0,
            keyframe_requested: true,
        }),
    }
}

/// Phase-4 diagnostic feedback sender.
///
/// This UDP side channel exists only to close the one-to-one media recovery loop before the Phase-5
/// authenticated QUIC control plane is available. The payload is transport-neutral and can later be
/// carried unchanged by the reliable control session.
#[derive(Debug)]
pub struct UdpFeedbackSender {
    socket: UdpSocket,
    destination: SocketAddr,
}

impl UdpFeedbackSender {
    pub fn bind(local: SocketAddr, destination: SocketAddr) -> Result<Self, FeedbackTransportError> {
        let socket = UdpSocket::bind(local)?;
        Ok(Self {
            socket,
            destination,
        })
    }

    #[must_use]
    pub const fn destination(&self) -> SocketAddr {
        self.destination
    }

    pub fn local_addr(&self) -> Result<SocketAddr, FeedbackTransportError> {
        Ok(self.socket.local_addr()?)
    }

    pub fn send(&self, feedback: &MediaFeedback) -> Result<usize, FeedbackTransportError> {
        let encoded = feedback.encode()?;
        Ok(self.socket.send_to(&encoded, self.destination)?)
    }
}

/// Phase-4 diagnostic feedback receiver.
#[derive(Debug)]
pub struct UdpFeedbackReceiver {
    socket: UdpSocket,
}

impl UdpFeedbackReceiver {
    pub fn bind(local: SocketAddr) -> Result<Self, FeedbackTransportError> {
        Ok(Self {
            socket: UdpSocket::bind(local)?,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, FeedbackTransportError> {
        Ok(self.socket.local_addr()?)
    }

    pub fn set_read_timeout(
        &self,
        timeout: Option<Duration>,
    ) -> Result<(), FeedbackTransportError> {
        Ok(self.socket.set_read_timeout(timeout)?)
    }

    pub fn set_nonblocking(&self, enabled: bool) -> Result<(), FeedbackTransportError> {
        Ok(self.socket.set_nonblocking(enabled)?)
    }

    pub fn receive_one(&self) -> Result<(MediaFeedback, SocketAddr), FeedbackTransportError> {
        let mut buffer = [0_u8; MAX_FEEDBACK_DATAGRAM];
        let (len, peer) = self.socket.recv_from(&mut buffer)?;
        Ok((MediaFeedback::decode(&buffer[..len])?, peer))
    }
}

#[derive(Debug)]
pub enum FeedbackTransportError {
    Io(io::Error),
    Codec(FeedbackCodecError),
}

impl fmt::Display for FeedbackTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "feedback socket error: {error}"),
            Self::Codec(error) => write!(formatter, "feedback protocol error: {error}"),
        }
    }
}

impl std::error::Error for FeedbackTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Codec(error) => Some(error),
        }
    }
}

impl From<io::Error> for FeedbackTransportError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<FeedbackCodecError> for FeedbackTransportError {
    fn from(value: FeedbackCodecError) -> Self {
        Self::Codec(value)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

    use classmesh_video::distributor::SharedEncodedFrame;
    use classmesh_video::{Codec, EncodedFrameMeta};

    use super::*;
    use crate::receiver::ReceiverEvent;
    use crate::transport::UdpSenderConfig;

    fn loopback_any() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[test]
    fn receiver_events_become_control_feedback_only_when_needed() {
        let events = vec![
            ReceiverEvent::NeedNack {
                stream_id: 3,
                frame_id: 10,
                missing_packet_indices: vec![1, 4],
            },
            ReceiverEvent::DroppedStaleFrame {
                stream_id: 3,
                frame_id: 10,
            },
            ReceiverEvent::NeedKeyframe {
                stream_id: 3,
                after_frame_id: 10,
            },
        ];
        assert_eq!(
            from_receiver_events(&events),
            vec![
                MediaFeedback::Nack {
                    stream_id: 3,
                    frame_id: 10,
                    missing_packet_indices: vec![1, 4],
                },
                MediaFeedback::RequestKeyframe {
                    stream_id: 3,
                    after_frame_id: 10,
                },
            ]
        );
    }

    #[test]
    fn nack_retransmits_from_live_cache_and_keyframe_is_surfaced() {
        let sink = UdpSocket::bind(loopback_any()).expect("feedback test sink binds");
        let destination = sink.local_addr().expect("feedback test sink address");
        let mut sender = UdpFrameSender::bind(
            loopback_any(),
            UdpSenderConfig::presentation(3, destination),
        )
        .expect("sender binds");
        let frame = SharedEncodedFrame::new(
            EncodedFrameMeta {
                frame_id: 10,
                timestamp_us: 1_000,
                keyframe: false,
            },
            Codec::H264,
            vec![7_u8; 2_000],
        );
        sender.send_frame(0, &frame).expect("frame sends");

        let nack = apply_sender_feedback(
            &mut sender,
            1,
            &MediaFeedback::Nack {
                stream_id: 3,
                frame_id: 10,
                missing_packet_indices: vec![0],
            },
        )
        .expect("nack applies");
        assert_eq!(nack.retransmitted_packets, 1);
        assert!(!nack.keyframe_requested);

        let keyframe = apply_sender_feedback(
            &mut sender,
            2,
            &MediaFeedback::RequestKeyframe {
                stream_id: 3,
                after_frame_id: 10,
            },
        )
        .expect("keyframe feedback applies");
        assert!(keyframe.keyframe_requested);
        assert_eq!(keyframe.retransmitted_packets, 0);
    }

    #[test]
    fn feedback_datagram_round_trips_over_loopback() {
        let receiver = UdpFeedbackReceiver::bind(loopback_any()).expect("feedback receiver binds");
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("feedback timeout config succeeds");
        let sender = UdpFeedbackSender::bind(
            loopback_any(),
            receiver.local_addr().expect("feedback receiver address"),
        )
        .expect("feedback sender binds");
        let feedback = MediaFeedback::RequestKeyframe {
            stream_id: 3,
            after_frame_id: 99,
        };

        sender.send(&feedback).expect("feedback sends");
        let (received, _) = receiver.receive_one().expect("feedback receives");
        assert_eq!(received, feedback);
    }
}
