//! Monotonic idle recovery for a live Service-owned file pull.
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FilePullIdleLease {
    last_progress: Instant,
}

impl FilePullIdleLease {
    pub(crate) fn new(now: Instant) -> Self {
        Self { last_progress: now }
    }

    pub(crate) fn refresh(&mut self, now: Instant) {
        if now > self.last_progress {
            self.last_progress = now;
        }
    }

    pub(crate) fn expired(&self, now: Instant, limit: Duration) -> bool {
        now.saturating_duration_since(self.last_progress) >= limit
    }
}
#[cfg(test)]
mod tests {
    use super::FilePullIdleLease;
    use std::time::{Duration, Instant};

    const IDLE_LIMIT: Duration = Duration::from_secs(60);

    #[test]
    fn idle_pull_expires_on_boundary_without_network_progress() {
        let started = Instant::now();
        let lease = FilePullIdleLease::new(started);
        assert!(!lease.expired(started + IDLE_LIMIT - Duration::from_nanos(1), IDLE_LIMIT));
        assert!(lease.expired(started + IDLE_LIMIT, IDLE_LIMIT));
    }

    #[test]
    fn accepted_progress_refreshes_the_idle_window() {
        let started = Instant::now();
        let mut lease = FilePullIdleLease::new(started);
        lease.refresh(started + Duration::from_secs(30));
        assert!(!lease.expired(started + Duration::from_secs(89), IDLE_LIMIT));
        assert!(lease.expired(started + Duration::from_secs(90), IDLE_LIMIT));
    }

    #[test]
    fn earlier_clock_sample_cannot_roll_back_a_valid_progress_time() {
        let started = Instant::now();
        let mut lease = FilePullIdleLease::new(started);
        lease.refresh(started + Duration::from_secs(30));
        lease.refresh(started + Duration::from_secs(20));
        assert!(!lease.expired(started + Duration::from_secs(89), IDLE_LIMIT));
        assert!(lease.expired(started + Duration::from_secs(90), IDLE_LIMIT));
    }
}
