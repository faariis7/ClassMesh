use std::collections::VecDeque;

/// Small ownership pool used for GPU surfaces that may remain in-flight inside an asynchronous
/// hardware encoder.
///
/// The pool never blocks. If every surface is in-flight, capture/presentation code must prefer
/// freshness and drop/defer the current frame rather than allocate an unbounded queue.
#[derive(Debug)]
pub struct SurfacePool<T> {
    free: VecDeque<T>,
    capacity: usize,
}

impl<T> SurfacePool<T> {
    /// Builds a bounded pool from preallocated surfaces.
    ///
    /// # Panics
    /// Panics when `items` is empty; a zero-surface pool cannot make progress.
    #[must_use]
    pub fn from_items(items: Vec<T>) -> Self {
        assert!(!items.is_empty(), "surface pool must not be empty");
        let capacity = items.len();
        Self {
            free: items.into(),
            capacity,
        }
    }

    /// Moves one free surface to the caller. `None` means every surface is currently in-flight.
    pub fn try_acquire(&mut self) -> Option<T> {
        self.free.pop_front()
    }

    /// Returns a surface after the encoder has finished with it.
    ///
    /// If the pool is already full, the caller receives the surface back instead of silently
    /// growing the pool or dropping an owned GPU resource.
    pub fn release(&mut self, surface: T) -> Result<(), T> {
        if self.free.len() >= self.capacity {
            return Err(surface);
        }
        self.free.push_back(surface);
        Ok(())
    }

    #[must_use]
    pub fn available(&self) -> usize {
        self.free.len()
    }

    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.capacity.saturating_sub(self.free.len())
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_never_grows_past_preallocated_capacity() {
        let mut pool = SurfacePool::from_items(vec![1_u8, 2, 3]);
        assert_eq!(pool.capacity(), 3);
        assert_eq!(pool.available(), 3);

        let a = pool.try_acquire().expect("first surface");
        let b = pool.try_acquire().expect("second surface");
        let c = pool.try_acquire().expect("third surface");
        assert_eq!(pool.in_flight(), 3);
        assert!(pool.try_acquire().is_none());

        pool.release(a).expect("return first");
        pool.release(b).expect("return second");
        pool.release(c).expect("return third");
        assert_eq!(pool.available(), 3);
        assert_eq!(pool.in_flight(), 0);
        assert_eq!(pool.release(99), Err(99));
    }

    #[test]
    fn returned_surfaces_become_available_without_allocation() {
        let mut pool = SurfacePool::from_items(vec![10_u8, 20]);
        let first = pool.try_acquire().expect("surface");
        assert_eq!(first, 10);
        pool.release(first).expect("return surface");
        assert_eq!(pool.available(), 2);
        assert_eq!(pool.try_acquire(), Some(20));
        assert_eq!(pool.try_acquire(), Some(10));
    }
}
