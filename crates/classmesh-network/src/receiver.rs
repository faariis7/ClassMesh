use std::collections::BTreeMap;

use crate::{AssembleError, AssembledFrame, FrameAssembler, MediaPacket};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverPolicy {
    pub max_inflight_frames: usize,
    pub nack_after_us: u64,
    pub drop_after_us: u64,
}

impl Default for ReceiverPolicy {
    fn default() -> Self {
        Self {
            max_inflight_frames: 3,
            nack_after_us: 20_000,
            drop_after_us: 80_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiverEvent {
    FrameReady(AssembledFrame),
    NeedNack {
        stream_id: u32,
        frame_id: u64,
        missing_packet_indices: Vec<u16>,
    },
    NeedKeyframe {
        stream_id: u32,
        after_frame_id: u64,
    },
    DroppedStaleFrame {
        stream_id: u32,
        frame_id: u64,
    },
}

#[derive(Debug)]
struct InflightFrame {
    first_seen_us: u64,
    last_nack_us: Option<u64>,
    assembler: FrameAssembler,
}

#[derive(Debug)]
pub struct ReceiverWindow {
    policy: ReceiverPolicy,
    inflight: BTreeMap<u64, InflightFrame>,
    latest_complete_frame: Option<u64>,
    dropped_frames: u64,
}

impl ReceiverWindow {
    /// # Panics
    /// Panics when `max_inflight_frames` is zero or NACK delay is not below the stale deadline.
    #[must_use]
    pub fn new(policy: ReceiverPolicy) -> Self {
        assert!(
            policy.max_inflight_frames > 0,
            "receiver must allow at least one frame"
        );
        assert!(
            policy.nack_after_us < policy.drop_after_us,
            "NACK deadline must precede drop deadline"
        );
        Self {
            policy,
            inflight: BTreeMap::new(),
            latest_complete_frame: None,
            dropped_frames: 0,
        }
    }

    pub fn push(
        &mut self,
        now_us: u64,
        packet: &MediaPacket,
    ) -> Result<Vec<ReceiverEvent>, AssembleError> {
        let mut events = self.expire(now_us);
        let frame_id = packet.header.frame_id;

        if self
            .latest_complete_frame
            .is_some_and(|latest| frame_id <= latest)
        {
            return Ok(events);
        }

        if !self.inflight.contains_key(&frame_id) {
            while self.inflight.len() >= self.policy.max_inflight_frames {
                if let Some((&oldest_id, _)) = self.inflight.first_key_value() {
                    let stream_id = self
                        .inflight
                        .get(&oldest_id)
                        .map(|frame| frame.assembler.stream_id_for_receiver())
                        .unwrap_or(packet.header.stream_id);
                    self.inflight.remove(&oldest_id);
                    self.dropped_frames = self.dropped_frames.saturating_add(1);
                    events.push(ReceiverEvent::DroppedStaleFrame {
                        stream_id,
                        frame_id: oldest_id,
                    });
                } else {
                    break;
                }
            }
            self.inflight.insert(
                frame_id,
                InflightFrame {
                    first_seen_us: now_us,
                    last_nack_us: None,
                    assembler: FrameAssembler::from_first(packet),
                },
            );
        }

        let complete = {
            let frame = self
                .inflight
                .get_mut(&frame_id)
                .expect("frame inserted or already existed");
            frame.assembler.push(packet)?;
            frame.assembler.is_complete()
        };

        if complete {
            let frame = self
                .inflight
                .remove(&frame_id)
                .expect("completed frame must exist")
                .assembler
                .finish()
                .expect("completed assembler must finish");
            self.latest_complete_frame = Some(frame_id);
            self.inflight.retain(|candidate, _| *candidate > frame_id);
            events.push(ReceiverEvent::FrameReady(frame));
        }

        Ok(events)
    }

    pub fn tick(&mut self, now_us: u64) -> Vec<ReceiverEvent> {
        self.expire(now_us)
    }

    fn expire(&mut self, now_us: u64) -> Vec<ReceiverEvent> {
        let mut events = Vec::new();
        let mut remove = Vec::new();
        let mut request_keyframe = None;

        for (&frame_id, frame) in &mut self.inflight {
            let age = now_us.saturating_sub(frame.first_seen_us);
            let stream_id = frame.assembler.stream_id_for_receiver();
            if age >= self.policy.drop_after_us {
                remove.push(frame_id);
                request_keyframe = Some((stream_id, frame_id));
                continue;
            }

            if age >= self.policy.nack_after_us
                && frame
                    .last_nack_us
                    .is_none_or(|last| now_us.saturating_sub(last) >= self.policy.nack_after_us)
            {
                let missing = frame.assembler.missing_packet_indices();
                if !missing.is_empty() {
                    frame.last_nack_us = Some(now_us);
                    events.push(ReceiverEvent::NeedNack {
                        stream_id,
                        frame_id,
                        missing_packet_indices: missing,
                    });
                }
            }
        }

        for frame_id in remove {
            if let Some(frame) = self.inflight.remove(&frame_id) {
                self.dropped_frames = self.dropped_frames.saturating_add(1);
                events.push(ReceiverEvent::DroppedStaleFrame {
                    stream_id: frame.assembler.stream_id_for_receiver(),
                    frame_id,
                });
            }
        }

        if let Some((stream_id, frame_id)) = request_keyframe {
            events.push(ReceiverEvent::NeedKeyframe {
                stream_id,
                after_frame_id: frame_id,
            });
        }

        events
    }

    #[must_use]
    pub const fn dropped_frames(&self) -> u64 {
        self.dropped_frames
    }
}

#[cfg(test)]
mod tests {
    use classmesh_protocol::media::MAX_PACKET_PAYLOAD;

    use super::*;
    use crate::{PacketizeMeta, packetize_frame};

    fn packets(frame_id: u64) -> Vec<MediaPacket> {
        packetize_frame(
            &vec![7_u8; MAX_PACKET_PAYLOAD * 2 + 10],
            PacketizeMeta {
                protocol_major: 0,
                protocol_minor: 1,
                stream_id: 3,
                frame_id,
                first_sequence: 1,
                timestamp_us: frame_id * 1_000,
                keyframe: frame_id == 1,
            },
        )
        .expect("test frame should packetize")
    }

    #[test]
    fn incomplete_frame_generates_nack_then_keyframe_recovery() {
        let mut window = ReceiverWindow::new(ReceiverPolicy::default());
        let frame = packets(1);
        window.push(0, &frame[0]).expect("packet accepted");
        window.push(1_000, &frame[2]).expect("packet accepted");

        let nack = window.tick(25_000);
        assert!(matches!(
            &nack[0],
            ReceiverEvent::NeedNack {
                frame_id: 1,
                missing_packet_indices,
                ..
            } if missing_packet_indices == &vec![1]
        ));

        let expired = window.tick(100_000);
        assert!(expired.iter().any(|event| matches!(
            event,
            ReceiverEvent::NeedKeyframe {
                after_frame_id: 1,
                ..
            }
        )));
        assert_eq!(window.dropped_frames(), 1);
    }

    #[test]
    fn completed_frame_is_delivered_despite_reordering() {
        let mut window = ReceiverWindow::new(ReceiverPolicy::default());
        let frame = packets(2);
        let mut ready = Vec::new();
        for packet in frame.iter().rev() {
            ready.extend(window.push(5_000, packet).expect("packet accepted"));
        }
        assert!(ready.iter().any(|event| matches!(
            event,
            ReceiverEvent::FrameReady(frame) if frame.frame_id == 2
        )));
    }
}
