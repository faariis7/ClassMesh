//! Per-key-epoch retry state for authenticated Worker media recovery requests.
use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;
use std::time::{Duration, Instant};

/// Bounded per-session retry when the decoder is still waiting for a keyframe.
/// The Teacher-side recovery coordinator independently limits global IDR rate.
const KEYFRAME_RETRY_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Default)]
pub struct PresentationKeyframeRetry {
    last_sent: Option<(PresentationKeyInstallBinding, Instant)>,
}

impl PresentationKeyframeRetry {
    #[must_use]
    pub fn should_request(&self, binding: PresentationKeyInstallBinding, now: Instant) -> bool {
        match self.last_sent {
            None => true,
            Some((previous, _)) if previous != binding => true,
            Some((_, last)) => now
                .checked_duration_since(last)
                .is_some_and(|elapsed| elapsed >= KEYFRAME_RETRY_INTERVAL),
        }
    }

    pub fn record_sent(&mut self, binding: PresentationKeyInstallBinding, now: Instant) {
        self.last_sent = Some((binding, now));
    }

    pub fn reset(&mut self) {
        self.last_sent = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding(epoch: u32) -> PresentationKeyInstallBinding {
        PresentationKeyInstallBinding {
            control_session_id: 5,
            request_id: 8,
            presentation_id: 11,
            stream_id: 7,
            epoch,
        }
    }

    #[test]
    fn dropped_keyframe_request_can_retry_after_bounded_delay() {
        let start = Instant::now();
        let mut gate = PresentationKeyframeRetry::default();
        assert!(gate.should_request(binding(1), start));
        gate.record_sent(binding(1), start);
        assert!(!gate.should_request(binding(1), start + Duration::from_millis(100)));
        assert!(!gate.should_request(binding(1), start + Duration::from_millis(1999)));
        assert!(gate.should_request(binding(1), start + Duration::from_secs(2)));
        gate.record_sent(binding(1), start + Duration::from_secs(2));
        assert!(!gate.should_request(binding(1), start + Duration::from_secs(3)));
        assert!(gate.should_request(binding(1), start + Duration::from_secs(4)));
    }

    #[test]
    fn keyframe_ack_and_new_key_epoch_rearm_without_leaking_old_pending_state() {
        let start = Instant::now();
        let mut gate = PresentationKeyframeRetry::default();
        gate.record_sent(binding(1), start);
        assert!(gate.should_request(binding(2), start + Duration::from_millis(1)));
        gate.record_sent(binding(2), start + Duration::from_millis(1));
        gate.reset();
        assert!(gate.should_request(binding(2), start + Duration::from_millis(2)));
    }

    #[test]
    fn backwards_timestamp_never_accelerates_retry() {
        let start = Instant::now();
        let mut gate = PresentationKeyframeRetry::default();
        gate.record_sent(binding(1), start + Duration::from_secs(10));
        assert!(!gate.should_request(binding(1), start));
        assert!(!gate.should_request(binding(1), start + Duration::from_secs(11)));
    }
}
