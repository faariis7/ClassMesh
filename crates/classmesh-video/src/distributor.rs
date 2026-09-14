use std::collections::BTreeMap;
use std::sync::Arc;

use crate::{Codec, EncodedFrameMeta};

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
        assert!(capacity > 0, "sink queue capacity must be non-zero");
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
#[derive(Debug, Default)]
pub struct FrameDistributor {
    sinks: BTreeMap<SinkId, SinkQueue>,
}

impl FrameDistributor {
    pub fn add_sink(&mut self, id: SinkId, mode: SinkMode, capacity: usize) {
        self.sinks.insert(id, SinkQueue::new(mode, capacity));
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
        distributor.add_sink(SinkId(1), SinkMode::Multicast, 2);
        distributor.add_sink(SinkId(2), SinkMode::Unicast, 2);
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
    fn slow_sink_drops_old_frames_without_affecting_other_sink() {
        let mut distributor = FrameDistributor::default();
        distributor.add_sink(SinkId(1), SinkMode::Multicast, 2);
        distributor.add_sink(SinkId(2), SinkMode::Unicast, 2);

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
