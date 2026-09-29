use std::fmt;
use std::net::{IpAddr, SocketAddr};

use classmesh_protocol::PROTOCOL_VERSION;
use classmesh_protocol::feedback::{FeedbackMessage, MAX_NACK_PACKET_INDICES};
use classmesh_protocol::media::{MAX_PACKET_PAYLOAD, MediaFlags};
use classmesh_security::group_media::MAX_GROUP_MEDIA_SEALED_BYTES;

use crate::receiver::{ReceiverEvent, ReceiverPolicy, ReceiverWindow};
use crate::{AssembleError, AssembledFrame, MediaPacket};

use super::config::{ProtectedMulticastReceiveError, ProtectedMulticastReceiverConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticastPacketDropReason {
    UnexpectedSource,
    UnexpectedProtocolVersion,
    WrongStream,
    FrameTooLarge,
    RetransmitUnsupported,
    FecUnsupported,
    Assembly(AssembleError),
}

#[derive(PartialEq, Eq)]
pub struct ReceivedGroupMediaCiphertext {
    stream_id: u32,
    frame_id: u64,
    timestamp_us: u64,
    keyframe: bool,
    ciphertext: Vec<u8>,
}

impl fmt::Debug for ReceivedGroupMediaCiphertext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceivedGroupMediaCiphertext")
            .field("stream_id", &self.stream_id)
            .field("frame_id", &self.frame_id)
            .field("timestamp_us", &self.timestamp_us)
            .field("keyframe", &self.keyframe)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
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

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProtectedMulticastReceiveBatch {
    pub frames: Vec<ReceivedGroupMediaCiphertext>,
    pub feedback: Vec<FeedbackMessage>,
    pub dropped_stale_frames: usize,
    pub dropped_invalid_frames: usize,
}

impl ProtectedMulticastReceiveBatch {
    pub(super) fn from_receiver_events(events: Vec<ReceiverEvent>) -> Self {
        let mut frames = Vec::new();
        let mut feedback = Vec::new();
        let mut dropped_stale_frames = 0_usize;
        let mut dropped_invalid_frames = 0_usize;

        for event in events {
            match event {
                ReceiverEvent::FrameReady(frame) => {
                    if frame.data.len() <= MAX_GROUP_MEDIA_SEALED_BYTES {
                        frames.push(ReceivedGroupMediaCiphertext::from_assembled(frame));
                    } else {
                        dropped_invalid_frames = dropped_invalid_frames.saturating_add(1);
                    }
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
            dropped_invalid_frames,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
            && self.feedback.is_empty()
            && self.dropped_stale_frames == 0
            && self.dropped_invalid_frames == 0
    }
}

#[derive(Debug, PartialEq, Eq)]
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
            return ProtectedMulticastReceiveOutcome::Dropped(
                MulticastPacketDropReason::WrongStream,
            );
        }
        let max_packets =
            MAX_GROUP_MEDIA_SEALED_BYTES.div_ceil(MAX_PACKET_PAYLOAD);
        if usize::from(packet.header.packet_count) > max_packets {
            return ProtectedMulticastReceiveOutcome::Dropped(
                MulticastPacketDropReason::FrameTooLarge,
            );
        }
        if packet.header.flags.contains(MediaFlags::RETRANSMIT) {
            return ProtectedMulticastReceiveOutcome::Dropped(
                MulticastPacketDropReason::RetransmitUnsupported,
            );
        }
        if packet.header.flags.contains(MediaFlags::FEC) {
            return ProtectedMulticastReceiveOutcome::Dropped(
                MulticastPacketDropReason::FecUnsupported,
            );
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
