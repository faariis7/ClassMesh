//! Portable policy for the native Windows first-run H.264 encoder benchmark.

/// Bounded first-run probe: transient MF encoder request failures may recover,
/// but must not trigger unbounded calls on the capture thread.
#[derive(Debug, Default)]
pub(crate) struct KeyframeRequestRetry {
    attempts: u8,
    next_submission: usize,
    succeeded: bool,
}

impl KeyframeRequestRetry {
    const FIRST_SUBMISSION: usize = 30;
    const RETRY_INTERVAL_SUBMISSIONS: usize = 5;
    const MAX_ATTEMPTS: u8 = 3;

    pub(crate) fn should_attempt(&self, submitted: usize, non_keyframe_observed: bool) -> bool {
        non_keyframe_observed
            && !self.succeeded
            && self.attempts < Self::MAX_ATTEMPTS
            && submitted >= Self::FIRST_SUBMISSION
            && submitted >= self.next_submission
    }

    pub(crate) fn record_attempt(&mut self, submitted: usize, succeeded: bool) {
        self.attempts = self.attempts.saturating_add(1);
        self.next_submission = submitted.saturating_add(Self::RETRY_INTERVAL_SUBMISSIONS);
        self.succeeded |= succeeded;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_encoder_keyframe_request_failure_retries_after_bounded_submissions() {
        let mut retry = KeyframeRequestRetry::default();
        assert!(!retry.should_attempt(29, true));
        assert!(!retry.should_attempt(30, false));
        assert!(retry.should_attempt(30, true));
        retry.record_attempt(30, false);
        assert!(!retry.should_attempt(34, true));
        assert!(retry.should_attempt(35, true));
        retry.record_attempt(35, true);
        assert!(!retry.should_attempt(60, true));
    }

    #[test]
    fn persistently_rejected_encoder_keyframe_request_stops_after_three_attempts() {
        let mut retry = KeyframeRequestRetry::default();
        for submission in [30, 35, 40] {
            assert!(retry.should_attempt(submission, true));
            retry.record_attempt(submission, false);
        }
        assert!(!retry.should_attempt(45, true));
        assert!(!retry.should_attempt(119, true));
    }
}
