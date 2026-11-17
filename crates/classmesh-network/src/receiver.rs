use std::collections::{BTreeMap, VecDeque};

use crate::multicast_diagnostics::{DeliveryStage, DeliveryTrace};
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
    order_by_completion: bool,
    recently_discarded: VecDeque<u64>,
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
            order_by_completion: true,
            recently_discarded: VecDeque::new(),
            dropped_frames: 0,
        }
    }

    /// Protected transport only assembles candidates. The key owner decides
    /// which completed frame IDs may advance presentation order.
    pub(crate) fn for_unverified_frames(policy: ReceiverPolicy) -> Self {
        Self {
            order_by_completion: false,
            ..Self::new(policy)
        }
    }

    pub fn push(
        &mut self,
        now_us: u64,
        packet: &MediaPacket,
    ) -> Result<Vec<ReceiverEvent>, AssembleError> {
        self.push_observed(now_us, packet, None)
    }

    pub(crate) fn push_observed(
        &mut self,
        now_us: u64,
        packet: &MediaPacket,
        mut trace: Option<&mut DeliveryTrace>,
    ) -> Result<Vec<ReceiverEvent>, AssembleError> {
        let mut events = self.expire(now_us, trace.as_deref_mut());
        let frame_id = packet.header.frame_id;

        if self
            .latest_complete_frame
            .is_some_and(|latest| frame_id <= latest)
            || self.recently_discarded.contains(&frame_id)
        {
            return Ok(events);
        }

        if !self.inflight.contains_key(&frame_id) {
            if self.inflight.len() == self.policy.max_inflight_frames {
                let (oldest_id, oldest) = self.inflight.pop_first().expect("full receive window");
                self.remember_discarded(oldest_id);
                if let Some(trace) = trace {
                    trace.record(DeliveryStage::FrameWindowEvicted, Some(oldest_id), None);
                }
                self.report_drop(
                    oldest.assembler.stream_id_for_receiver(),
                    oldest_id,
                    &mut events,
                );
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
            if self.order_by_completion {
                self.note_complete(frame_id, &mut events);
            }
            events.push(ReceiverEvent::FrameReady(frame));
        }

        Ok(events)
    }

    fn note_complete(&mut self, frame_id: u64, events: &mut Vec<ReceiverEvent>) {
        self.latest_complete_frame = Some(frame_id);
        self.recently_discarded
            .retain(|candidate| *candidate > frame_id);
        while self
            .inflight
            .first_key_value()
            .is_some_and(|(&id, _)| id < frame_id)
        {
            let (id, partial) = self.inflight.pop_first().expect("oldest frame is present");
            self.report_drop(partial.assembler.stream_id_for_receiver(), id, events);
        }
    }

    pub(crate) fn has_pending_frames(&self) -> bool {
        !self.inflight.is_empty()
    }

    pub fn tick(&mut self, now_us: u64) -> Vec<ReceiverEvent> {
        self.expire(now_us, None)
    }

    pub(crate) fn expire(
        &mut self,
        now_us: u64,
        mut trace: Option<&mut DeliveryTrace>,
    ) -> Vec<ReceiverEvent> {
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
                self.remember_discarded(frame_id);
                if let Some(trace) = trace.as_deref_mut() {
                    trace.record(DeliveryStage::FrameExpired, Some(frame_id), None);
                }
                self.report_drop(
                    frame.assembler.stream_id_for_receiver(),
                    frame_id,
                    &mut events,
                );
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

    fn remember_discarded(&mut self, frame_id: u64) {
        // Discarded, unauthenticated IDs must not advance the stream watermark.
        // Keep only one receive window of exact IDs until completed frames
        // supersede them. An isolated high ID cannot suppress lower frames.
        if self.recently_discarded.len() == self.policy.max_inflight_frames {
            self.recently_discarded.pop_front();
        }
        self.recently_discarded.push_back(frame_id);
    }

    fn report_drop(&mut self, stream_id: u32, frame_id: u64, events: &mut Vec<ReceiverEvent>) {
        self.dropped_frames = self.dropped_frames.saturating_add(1);
        events.push(ReceiverEvent::DroppedStaleFrame {
            stream_id,
            frame_id,
        });
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
    fn observed_drops_distinguish_expiry_and_window_eviction() {
        let policy = ReceiverPolicy::default();
        let mut window = ReceiverWindow::for_unverified_frames(policy);
        let mut trace = DeliveryTrace::new();
        for frame_id in 1..=4 {
            window
                .push_observed(0, &packets(frame_id)[0], Some(&mut trace))
                .unwrap();
        }
        window.expire(policy.drop_after_us - 1, Some(&mut trace));
        assert_eq!(trace.count(DeliveryStage::FrameExpired), 0);
        window.expire(policy.drop_after_us, Some(&mut trace));
        assert_eq!(
            trace
                .events()
                .iter()
                .map(|event| (event.stage, event.frame_id))
                .collect::<Vec<_>>(),
            vec![
                (DeliveryStage::FrameWindowEvicted, Some(1)),
                (DeliveryStage::FrameExpired, Some(2)),
                (DeliveryStage::FrameExpired, Some(3)),
                (DeliveryStage::FrameExpired, Some(4)),
            ]
        );
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

    #[test]
    fn sustained_partial_frames_keep_the_receive_window_bounded() {
        let policy = ReceiverPolicy::default();
        let mut window = ReceiverWindow::new(policy);
        for id in 1..=4_096 {
            let events = window.push(0, &packets(id)[0]).unwrap();
            assert!(window.inflight.len() <= policy.max_inflight_frames);
            assert!(window.recently_discarded.len() <= policy.max_inflight_frames);
            assert!(
                !events
                    .iter()
                    .any(|event| matches!(event, ReceiverEvent::FrameReady(_)))
            );
        }
        assert_eq!(window.inflight.len(), policy.max_inflight_frames);
        assert_eq!(window.dropped_frames(), 4_093);
        window.tick(policy.drop_after_us);
        assert!(window.inflight.is_empty());
        assert_eq!(window.dropped_frames(), 4_096);
    }

    #[test]
    fn unverified_completion_preserves_an_older_partial_and_its_deadline() {
        let policy = ReceiverPolicy::default();
        let mut window = ReceiverWindow::for_unverified_frames(policy);
        let lower = packets(8);
        assert!(window.push(0, &lower[0]).unwrap().is_empty());
        assert!(window.push(1, &lower[0]).unwrap().is_empty());

        let mut events = Vec::new();
        for fragment in &packets(1_000_000) {
            events.extend(window.push(2, fragment).unwrap());
        }
        assert!(matches!(
            events.as_slice(),
            [ReceiverEvent::FrameReady(frame)] if frame.frame_id == 1_000_000
        ));
        assert!(
            window
                .push(policy.drop_after_us - 1, &lower[2])
                .unwrap()
                .iter()
                .any(|event| { matches!(event, ReceiverEvent::NeedNack { frame_id: 8, .. }) })
        );
        let events = window.push(policy.drop_after_us, &lower[1]).unwrap();
        assert!(matches!(
            events.as_slice(),
            [
                ReceiverEvent::DroppedStaleFrame { frame_id: 8, .. },
                ReceiverEvent::NeedKeyframe {
                    after_frame_id: 8,
                    ..
                }
            ]
        ));
        assert_eq!(window.dropped_frames(), 1);
    }

    #[test]
    fn duplicate_fragments_do_not_restart_a_recently_expired_frame() {
        let policy = ReceiverPolicy::default();
        let mut window = ReceiverWindow::new(policy);
        let expired = packets(8);
        assert!(window.push(0, &expired[0]).unwrap().is_empty());
        assert!(window.tick(policy.drop_after_us).iter().any(|event| {
            matches!(event, ReceiverEvent::DroppedStaleFrame { frame_id: 8, .. })
        }));
        for fragment in &expired {
            assert!(
                window
                    .push(policy.drop_after_us + 1, fragment)
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(window.inflight.is_empty());

        // The expired ID alone must not advance the delivery watermark. A
        // different frame can still finish in its own receive window.
        assert!(packets(7).iter().any(|fragment| {
            window.push(policy.drop_after_us + 2, fragment).unwrap().iter().any(|event| {
                matches!(event, ReceiverEvent::FrameReady(frame) if frame.frame_id == 7)
            })
        }));
    }

    #[test]
    fn completing_a_newer_frame_reports_discarded_partial_frames_once() {
        let mut window = ReceiverWindow::new(ReceiverPolicy::default());
        assert!(window.push(0, &packets(1)[0]).unwrap().is_empty());
        let mut events = Vec::new();
        for fragment in &packets(2) {
            events.extend(window.push(1, fragment).unwrap());
        }
        assert!(matches!(
            &events[..],
            [
                ReceiverEvent::DroppedStaleFrame { stream_id: 3, frame_id: 1 },
                ReceiverEvent::FrameReady(frame)
            ] if frame.frame_id == 2
        ));
        assert_eq!(window.dropped_frames(), 1);
        assert!(
            window
                .tick(ReceiverPolicy::default().drop_after_us + 1)
                .is_empty()
        );
    }

    #[test]
    fn late_fragments_cannot_complete_an_expired_assembly_or_replace_a_newer_frame() {
        let policy = ReceiverPolicy::default();
        let mut window = ReceiverWindow::new(policy);
        let old = packets(1);
        for fragment in &old[..2] {
            assert!(window.push(0, fragment).unwrap().is_empty());
        }
        let events = window.push(policy.drop_after_us, &old[2]).unwrap();
        assert!(matches!(
            &events[..],
            [
                ReceiverEvent::DroppedStaleFrame { frame_id: 1, .. },
                ReceiverEvent::NeedKeyframe { .. }
            ]
        ));
        for fragment in &packets(2) {
            let events = window.push(policy.drop_after_us + 1, fragment).unwrap();
            assert_eq!(
                events.iter().any(
                    |event| matches!(event, ReceiverEvent::FrameReady(frame) if frame.frame_id == 2)
                ),
                fragment.header.packet_index == 2
            );
        }
        for fragment in &old {
            assert!(
                window
                    .push(policy.drop_after_us + 2, fragment)
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(window.inflight.is_empty());
    }
}
