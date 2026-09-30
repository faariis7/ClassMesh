use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use crate::distributor::{
    DistributorError, FrameDistributor, SharedEncodedFrame, SinkId, SinkMode, SinkStats,
};

#[derive(Debug)]
struct ConcurrentDistributorInner {
    distributor: Mutex<FrameDistributor>,
    changed: Condvar,
}

/// Thread-safe ownership boundary for one encode-once `FrameDistributor`.
///
/// Publishing and queue mutation hold the mutex only for bounded in-memory work. Consumers receive
/// an owned `SharedEncodedFrame` before this API returns, so transport or disk I/O happens after the
/// distributor lock has been released.
#[derive(Debug, Clone)]
pub struct ConcurrentFrameDistributor {
    inner: Arc<ConcurrentDistributorInner>,
}

impl Default for ConcurrentFrameDistributor {
    fn default() -> Self {
        Self::from_distributor(FrameDistributor::default())
    }
}

impl ConcurrentFrameDistributor {
    #[must_use]
    pub fn from_distributor(distributor: FrameDistributor) -> Self {
        Self {
            inner: Arc::new(ConcurrentDistributorInner {
                distributor: Mutex::new(distributor),
                changed: Condvar::new(),
            }),
        }
    }

    pub fn with_limits(
        max_sinks: usize,
        max_queue_depth: usize,
    ) -> Result<Self, DistributorError> {
        FrameDistributor::with_limits(max_sinks, max_queue_depth).map(Self::from_distributor)
    }

    pub fn add_sink(
        &self,
        id: SinkId,
        mode: SinkMode,
        capacity: usize,
    ) -> Result<(), DistributorError> {
        self.lock().add_sink(id, mode, capacity)
    }

    pub fn remove_sink(&self, id: SinkId) -> bool {
        let removed = self.lock().remove_sink(id);
        if removed {
            self.inner.changed.notify_all();
        }
        removed
    }

    pub fn publish(&self, frame: SharedEncodedFrame) {
        self.lock().publish(frame);
        self.inner.changed.notify_all();
    }

    pub fn pop_latest(&self, id: SinkId) -> Option<SharedEncodedFrame> {
        self.lock().pop_latest(id)
    }

    /// Waits for a sink to receive a frame, then returns only its newest queued frame.
    ///
    /// The returned frame owns an `Arc<[u8]>`; the internal distributor mutex is released before
    /// the caller can perform any potentially blocking transport work.
    pub fn wait_latest(
        &self,
        id: SinkId,
        timeout: Duration,
    ) -> Option<SharedEncodedFrame> {
        let mut distributor = self.lock();
        if let Some(frame) = distributor.pop_latest(id) {
            return Some(frame);
        }

        let waited = self.inner.changed.wait_timeout_while(
            distributor,
            timeout,
            |state| {
                state
                    .stats(id)
                    .is_some_and(|stats| stats.queued == 0)
            },
        );
        let (mut distributor, _) = match waited {
            Ok(value) => value,
            Err(poisoned) => poisoned.into_inner(),
        };
        distributor.pop_latest(id)
    }

    #[must_use]
    pub fn stats(&self, id: SinkId) -> Option<SinkStats> {
        self.lock().stats(id)
    }

    #[must_use]
    pub fn sink_count(&self) -> usize {
        self.lock().sink_count()
    }

    fn lock(&self) -> MutexGuard<'_, FrameDistributor> {
        self.inner
            .distributor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::thread;

    use crate::{Codec, EncodedFrameMeta};

    use super::*;

    fn frame(id: u64) -> SharedEncodedFrame {
        SharedEncodedFrame::new(
            EncodedFrameMeta {
                frame_id: id,
                timestamp_us: id.saturating_mul(1_000),
                keyframe: id == 1,
            },
            Codec::H264,
            vec![u8::try_from(id).unwrap_or(0); 16],
        )
    }

    #[test]
    fn shared_wrapper_preserves_latest_only_arc_semantics() {
        let distributor = ConcurrentFrameDistributor::default();
        distributor
            .add_sink(SinkId(1), SinkMode::Multicast, 2)
            .expect("sink");

        distributor.publish(frame(1));
        distributor.publish(frame(2));
        let latest = frame(3);
        let pointer = Arc::as_ptr(&latest.data);
        distributor.publish(latest);

        let before = distributor.stats(SinkId(1)).expect("stats");
        assert_eq!(before.queued, 2);
        assert_eq!(before.dropped, 1);

        let received = distributor
            .pop_latest(SinkId(1))
            .expect("latest frame");
        assert_eq!(received.meta.frame_id, 3);
        assert_eq!(Arc::as_ptr(&received.data), pointer);

        let after = distributor.stats(SinkId(1)).expect("stats");
        assert_eq!(after.queued, 0);
        assert_eq!(after.dropped, 2);
    }

    #[test]
    fn waiting_consumer_wakes_for_published_frame() {
        let distributor = ConcurrentFrameDistributor::default();
        distributor
            .add_sink(SinkId(7), SinkMode::Multicast, 2)
            .expect("sink");

        let consumer = distributor.clone();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread = thread::spawn(move || {
            ready_tx.send(()).expect("ready");
            consumer
                .wait_latest(SinkId(7), Duration::from_secs(1))
                .map(|frame| frame.meta.frame_id)
        });

        ready_rx.recv().expect("consumer ready");
        distributor.publish(frame(42));

        assert_eq!(thread.join().expect("consumer thread"), Some(42));
    }

    #[test]
    fn missing_or_idle_sink_waits_fail_closed_without_creating_state() {
        let distributor = ConcurrentFrameDistributor::default();
        assert!(
            distributor
                .wait_latest(SinkId(99), Duration::from_millis(1))
                .is_none()
        );
        assert_eq!(distributor.sink_count(), 0);

        distributor
            .add_sink(SinkId(1), SinkMode::Multicast, 1)
            .expect("sink");
        assert!(
            distributor
                .wait_latest(SinkId(1), Duration::from_millis(1))
                .is_none()
        );
        assert_eq!(distributor.stats(SinkId(1)).expect("stats").queued, 0);
    }

    #[test]
    fn wrapper_reuses_existing_distributor_bounds_and_cleanup() {
        let distributor = ConcurrentFrameDistributor::with_limits(1, 2).expect("limits");
        distributor
            .add_sink(SinkId(1), SinkMode::Multicast, 2)
            .expect("sink");
        assert_eq!(
            distributor.add_sink(SinkId(2), SinkMode::Unicast, 1),
            Err(DistributorError::SinkLimitReached)
        );
        assert!(distributor.remove_sink(SinkId(1)));
        assert_eq!(distributor.sink_count(), 0);
    }
}
