use std::collections::VecDeque;

/// A strictly bounded queue for live media where freshness is more valuable than completeness.
///
/// When the queue is full, pushing a new item evicts the oldest item. This is the intended
/// behavior for capture/encode/transport handoffs: ClassMesh must drop stale media rather than
/// accumulate end-to-end latency.
#[derive(Debug)]
pub struct LatestQueue<T> {
    items: VecDeque<T>,
    capacity: usize,
    dropped: u64,
}

impl<T> LatestQueue<T> {
    /// Creates a queue with a non-zero capacity.
    ///
    /// # Panics
    /// Panics when `capacity` is zero because an always-empty media queue is almost certainly a
    /// configuration bug.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "queue capacity must be greater than zero");
        Self {
            items: VecDeque::with_capacity(capacity),
            capacity,
            dropped: 0,
        }
    }

    /// Pushes an item and returns the evicted oldest item when the queue was already full.
    pub fn push(&mut self, item: T) -> Option<T> {
        let evicted = if self.items.len() == self.capacity {
            self.dropped = self.dropped.saturating_add(1);
            self.items.pop_front()
        } else {
            None
        };
        self.items.push_back(item);
        evicted
    }

    pub fn pop(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    /// Removes every queued item except the newest one.
    ///
    /// Returns the number of items discarded. Receivers can use this after a stall to immediately
    /// catch up to live media instead of draining obsolete frames.
    pub fn retain_latest(&mut self) -> usize {
        let remove_count = self.items.len().saturating_sub(1);
        for _ in 0..remove_count {
            let _ = self.items.pop_front();
        }
        self.dropped = self
            .dropped
            .saturating_add(u64::try_from(remove_count).unwrap_or(u64::MAX));
        remove_count
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::LatestQueue;

    #[test]
    fn full_queue_evicts_oldest_frame() {
        let mut queue = LatestQueue::new(2);
        assert_eq!(queue.push(10), None);
        assert_eq!(queue.push(11), None);
        assert_eq!(queue.push(12), Some(10));
        assert_eq!(queue.pop(), Some(11));
        assert_eq!(queue.pop(), Some(12));
        assert_eq!(queue.dropped(), 1);
    }

    #[test]
    fn retain_latest_catches_up_after_stall() {
        let mut queue = LatestQueue::new(4);
        for value in 1..=4 {
            let _ = queue.push(value);
        }
        assert_eq!(queue.retain_latest(), 3);
        assert_eq!(queue.pop(), Some(4));
        assert_eq!(queue.dropped(), 3);
    }

    #[test]
    #[should_panic(expected = "queue capacity must be greater than zero")]
    fn zero_capacity_is_rejected() {
        let _ = LatestQueue::<u8>::new(0);
    }
}
