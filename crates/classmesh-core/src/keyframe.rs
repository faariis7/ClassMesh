#![forbid(unsafe_code)]

/// Coalesces receiver keyframe requests so one unhealthy client cannot force the encoder to emit an
/// unbounded IDR storm. Time is supplied by the caller in a monotonic microsecond domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyframeRequestCoordinator {
    min_interval_us: u64,
    last_granted_us: Option<u64>,
    granted_requests: u64,
    suppressed_requests: u64,
}

impl KeyframeRequestCoordinator {
    #[must_use]
    pub const fn new(min_interval_us: u64) -> Self {
        Self {
            min_interval_us,
            last_granted_us: None,
            granted_requests: 0,
            suppressed_requests: 0,
        }
    }

    /// Returns `true` when the caller should ask the encoder for a keyframe now.
    ///
    /// The first request is granted immediately. Subsequent requests inside the configured interval
    /// are coalesced. A request exactly at the boundary is granted.
    pub fn request(&mut self, now_us: u64) -> bool {
        let allowed = self.last_granted_us.is_none_or(|last| {
            now_us.saturating_sub(last) >= self.min_interval_us
        });
        if allowed {
            self.last_granted_us = Some(now_us);
            self.granted_requests = self.granted_requests.saturating_add(1);
            true
        } else {
            self.suppressed_requests = self.suppressed_requests.saturating_add(1);
            false
        }
    }

    #[must_use]
    pub const fn granted_requests(&self) -> u64 {
        self.granted_requests
    }

    #[must_use]
    pub const fn suppressed_requests(&self) -> u64 {
        self.suppressed_requests
    }

    #[must_use]
    pub const fn min_interval_us(&self) -> u64 {
        self.min_interval_us
    }
}

impl Default for KeyframeRequestCoordinator {
    fn default() -> Self {
        Self::new(250_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_request_is_immediate_and_duplicates_are_coalesced() {
        let mut coordinator = KeyframeRequestCoordinator::new(250_000);
        assert!(coordinator.request(1_000_000));
        assert!(!coordinator.request(1_050_000));
        assert!(!coordinator.request(1_249_999));
        assert_eq!(coordinator.granted_requests(), 1);
        assert_eq!(coordinator.suppressed_requests(), 2);
    }

    #[test]
    fn boundary_and_later_requests_are_granted() {
        let mut coordinator = KeyframeRequestCoordinator::new(250_000);
        assert!(coordinator.request(10));
        assert!(coordinator.request(250_010));
        assert!(coordinator.request(700_000));
        assert_eq!(coordinator.granted_requests(), 3);
        assert_eq!(coordinator.suppressed_requests(), 0);
    }

    #[test]
    fn backwards_clock_input_does_not_bypass_throttle() {
        let mut coordinator = KeyframeRequestCoordinator::new(100);
        assert!(coordinator.request(1_000));
        assert!(!coordinator.request(900));
        assert_eq!(coordinator.suppressed_requests(), 1);
    }
}
