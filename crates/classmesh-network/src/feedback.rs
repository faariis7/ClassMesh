use crate::receiver::ReceiverEvent;
use crate::transport::{UdpFrameSender, UdpSendError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaFeedback {
    Nack {
        stream_id: u32,
        frame_id: u64,
        missing_packet_indices: Vec<u16>,
    },
    RequestKeyframe {
        stream_id: u32,
        after_frame_id: u64,
    },
}

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
}
