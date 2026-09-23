use std::collections::BTreeMap;
use std::sync::Arc;

use crate::{Codec, EncodedFrameMeta};

pub const DEFAULT_MAX_SINKS: usize = 64;
pub const DEFAULT_MAX_QUEUE_DEPTH: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributorError {
    InvalidMaxSinks,
    InvalidMaxQueueDepth,
    InvalidQueueCapacity,
    QueueCapacityExceeded,
    DuplicateSink,
    SinkLimitReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SinkId(pub u64);

#[derive(Debug, Clone)]
pub struct SharedEncodedFrame {
    pub meta: EncodedFrameMeta,
    pub codec: Codec,
    pub data: Arc<[u8]>,
}

impl SharedEncodedFrame {
    #[must_use]
    pub fn new(meta: EncodedFrameMeta, codec: Codec, data: Vec<u8>) -> Self {
        Self {
            meta,
            codec,
            data: Arc::from(data),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SinkMode {
    Multicast,
    Unicast,
    SfuUplink,
    Recording,
}

#[derive(Debug)]
struct SinkQueue {
    mode: SinkMode,
    frames: BTreeMap<u64, SharedEncodedFrame>,
    capacity: usize,
    dropped: u64,
}

impl SinkQueue {
    fn new(mode: SinkMode, capacity: usize) -> Self {
        Self {
            mode,
            frames: BTreeMap::new(),
            capacity,
            dropped: 0,
        }
    }

    fn push(&mut self, frame: SharedEncodedFrame) {
        while self.frames.len() >= self.capacity {
            if let Some((&oldest, _)) = self.frames.first_key_value() {
                self.frames.remove(&oldest);
                self.dropped = self.dropped.saturating_add(1);
            } else {
                break;
            }
        }
        self.frames.insert(frame.meta.frame_id, frame);
    }

    fn pop_latest(&mut self) -> Option<SharedEncodedFrame> {
        let (&latest, _) = self.frames.last_key_value()?;
        let dropped_before_latest = self.frames.len().saturating_sub(1);
        self.dropped = self
            .dropped
            .saturating_add(u64::try_from(dropped_before_latest).unwrap_or(u64::MAX));
        let latest_frame = self.frames.remove(&latest);
        self.frames.clear();
        latest_frame
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkStats {
    pub mode: SinkMode,
    pub queued: usize,
    pub dropped: u64,
}

/// Fan-out queue that shares the same encoded frame allocation across sinks.
///
/// This enforces the "encode once, distribute many" invariant at the encoded-frame boundary.
/// Individual sinks own bounded queues so a slow receiver/transport cannot hold back the encoder or
/// other healthy sinks.
#[derive(Debug)]
pub struct FrameDistributor {
    sinks: BTreeMap<SinkId, SinkQueue>,
    max_sinks: usize,
    max_queue_depth: usize,
}

impl Default for FrameDistributor {
    fn default() -> Self {
        Self {
            sinks: BTreeMap::new(),
            max_sinks: DEFAULT_MAX_SINKS,
            max_queue_depth: DEFAULT_MAX_QUEUE_DEPTH,
        }
    }
}

impl FrameDistributor {
    pub fn with_limits(max_sinks: usize, max_queue_depth: usize) -> Result<Self, DistributorError> {
        if max_sinks == 0 {
            return Err(DistributorError::InvalidMaxSinks);
        }
        if max_queue_depth == 0 {
            return Err(DistributorError::InvalidMaxQueueDepth);
        }
        Ok(Self {
            sinks: BTreeMap::new(),
            max_sinks,
            max_queue_depth,
        })
    }

    pub fn add_sink(
        &mut self,
        id: SinkId,
        mode: SinkMode,
        capacity: usize,
    ) -> Result<(), DistributorError> {
        if capacity == 0 {
            return Err(DistributorError::InvalidQueueCapacity);
        }
        if capacity > self.max_queue_depth {
            return Err(DistributorError::QueueCapacityExceeded);
        }
        if self.sinks.contains_key(&id) {
            return Err(DistributorError::DuplicateSink);
        }
        if self.sinks.len() >= self.max_sinks {
            return Err(DistributorError::SinkLimitReached);
        }
        self.sinks.insert(id, SinkQueue::new(mode, capacity));
        Ok(())
    }

    pub fn remove_sink(&mut self, id: SinkId) -> bool {
        self.sinks.remove(&id).is_some()
    }

    /// Shares one `Arc<[u8]>` allocation across every sink queue.
    pub fn publish(&mut self, frame: SharedEncodedFrame) {
        for sink in self.sinks.values_mut() {
            sink.push(frame.clone());
        }
    }

    pub fn pop_latest(&mut self, id: SinkId) -> Option<SharedEncodedFrame> {
        self.sinks.get_mut(&id)?.pop_latest()
    }

    #[must_use]
    pub fn stats(&self, id: SinkId) -> Option<SinkStats> {
        let sink = self.sinks.get(&id)?;
        Some(SinkStats {
            mode: sink.mode,
            queued: sink.frames.len(),
            dropped: sink.dropped,
        })
    }

    #[must_use]
    pub fn sink_count(&self) -> usize {
        self.sinks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(id: u64) -> SharedEncodedFrame {
        SharedEncodedFrame::new(
            EncodedFrameMeta {
                frame_id: id,
                timestamp_us: id * 1_000,
                keyframe: id == 1,
            },
            Codec::H264,
            vec![u8::try_from(id).unwrap_or(0); 16],
        )
    }

    #[test]
    fn one_allocation_is_shared_across_many_sinks() {
        let mut distributor = FrameDistributor::default();
        distributor
            .add_sink(SinkId(1), SinkMode::Multicast, 2)
            .expect("sink 1");
        distributor
            .add_sink(SinkId(2), SinkMode::Unicast, 2)
            .expect("sink 2");
        let original = frame(1);
        let pointer = Arc::as_ptr(&original.data);
        distributor.publish(original);
        let a = distributor
            .pop_latest(SinkId(1))
            .expect("sink 1 gets frame");
        let b = distributor
            .pop_latest(SinkId(2))
            .expect("sink 2 gets frame");
        assert_eq!(Arc::as_ptr(&a.data), pointer);
        assert_eq!(Arc::as_ptr(&b.data), pointer);
    }

    #[test]
    fn classroom_scale_shares_one_encoded_allocation() {
        let mut distributor = FrameDistributor::default();
        let original = frame(1);
        let pointer = Arc::as_ptr(&original.data);

        for id in 1..=20 {
            distributor
                .add_sink(SinkId(id), SinkMode::Unicast, 2)
                .expect("classroom sink should fit default bound");
        }
        distributor.publish(original);

        for id in 1..=20 {
            let delivered = distributor
                .pop_latest(SinkId(id))
                .expect("each sink gets the shared frame");
            assert_eq!(Arc::as_ptr(&delivered.data), pointer);
        }
        assert_eq!(distributor.sink_count(), 20);
    }

    #[test]
    fn distributor_rejects_unbounded_membership_and_queue_depth() {
        assert!(matches!(
            FrameDistributor::with_limits(0, 2),
            Err(DistributorError::InvalidMaxSinks)
        ));
        assert!(matches!(
            FrameDistributor::with_limits(2, 0),
            Err(DistributorError::InvalidMaxQueueDepth)
        ));

        let mut distributor = FrameDistributor::with_limits(2, 3).expect("valid limits");
        assert_eq!(
            distributor.add_sink(SinkId(1), SinkMode::Unicast, 0),
            Err(DistributorError::InvalidQueueCapacity)
        );
        assert_eq!(
            distributor.add_sink(SinkId(1), SinkMode::Unicast, 4),
            Err(DistributorError::QueueCapacityExceeded)
        );
        distributor
            .add_sink(SinkId(1), SinkMode::Unicast, 2)
            .expect("first sink");
        assert_eq!(
            distributor.add_sink(SinkId(1), SinkMode::Multicast, 2),
            Err(DistributorError::DuplicateSink)
        );
        distributor
            .add_sink(SinkId(2), SinkMode::Multicast, 3)
            .expect("second sink");
        assert_eq!(
            distributor.add_sink(SinkId(3), SinkMode::Unicast, 1),
            Err(DistributorError::SinkLimitReached)
        );
        assert_eq!(distributor.sink_count(), 2);
    }

    #[test]
    fn slow_sink_drops_old_frames_without_affecting_other_sink() {
        let mut distributor = FrameDistributor::default();
        distributor
            .add_sink(SinkId(1), SinkMode::Multicast, 2)
            .expect("sink 1");
        distributor
            .add_sink(SinkId(2), SinkMode::Unicast, 2)
            .expect("sink 2");

        distributor.publish(frame(1));
        let _ = distributor.pop_latest(SinkId(1));
        distributor.publish(frame(2));
        let _ = distributor.pop_latest(SinkId(1));
        distributor.publish(frame(3));
        let _ = distributor.pop_latest(SinkId(1));

        let latest_slow = distributor
            .pop_latest(SinkId(2))
            .expect("slow sink has latest");
        assert_eq!(latest_slow.meta.frame_id, 3);
        assert!(distributor.stats(SinkId(2)).expect("stats").dropped >= 2);
        assert_eq!(distributor.stats(SinkId(1)).expect("stats").dropped, 0);
    }
}
