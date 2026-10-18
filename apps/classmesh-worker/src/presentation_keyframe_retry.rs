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

/// A per-active-presentation silence clock. It never authorizes a request:
/// callers must separately enforce exact receiver/key binding and retry rate.
/// Track *authenticated* frames only; candidate ciphertext is untrusted.
#[derive(Debug, Default)]
pub struct PresentationKeyframeSilence {
    binding: Option<PresentationKeyInstallBinding>,
    last_authenticated_at: Option<Instant>,
    last_authenticated_frame_id: u64,
}

impl PresentationKeyframeSilence {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn note_authenticated_frame(
        &mut self,
        binding: PresentationKeyInstallBinding,
        frame_id: u64,
        now: Instant,
    ) {
        if self.binding != Some(binding) {
            self.binding = Some(binding);
            self.last_authenticated_at = Some(now);
            self.last_authenticated_frame_id = frame_id;
        } else if self.last_authenticated_at.is_none_or(|last| now >= last) {
            self.last_authenticated_at = Some(now);
            self.last_authenticated_frame_id = frame_id;
        }
    }

    /// Returns the last authenticated frame ID, or 0 before any authenticated
    /// frame, only if a live decoder is still waiting for its first valid IDR.
    /// First invocation arms the inactivity clock, avoiding immediate request
    /// storms when starting a fresh receiver with no video yet.
    pub fn due(
        &mut self,
        binding: PresentationKeyInstallBinding,
        now: Instant,
        waiting_for_keyframe: bool,
    ) -> Option<u64> {
        if self.binding != Some(binding) {
            self.binding = Some(binding);
            self.last_authenticated_at = Some(now);
            self.last_authenticated_frame_id = 0;
            return None;
        }
        if !waiting_for_keyframe {
            return None;
        }
        let last = self.last_authenticated_at?;
        (now.checked_duration_since(last)? >= KEYFRAME_RETRY_INTERVAL)
            .then_some(self.last_authenticated_frame_id)
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
    fn quiet_active_decoder_requests_first_idr_after_initial_grace() {
        let start = Instant::now();
        let mut watch = PresentationKeyframeSilence::default();
        assert_eq!(watch.due(binding(1), start, true), None);
        assert_eq!(
            watch.due(binding(1), start + Duration::from_millis(1999), true),
            None
        );
        assert_eq!(
            watch.due(binding(1), start + Duration::from_secs(2), true),
            Some(0)
        );
        // The separate retry limiter controls the rate of subsequent sends.
        assert_eq!(
            watch.due(binding(1), start + Duration::from_secs(3), false),
            None
        );
    }

    #[test]
    fn last_authenticated_frame_delays_silence_and_pins_request_cursor() {
        let start = Instant::now();
        let mut watch = PresentationKeyframeSilence::default();
        assert_eq!(watch.due(binding(1), start, true), None);
        watch.note_authenticated_frame(binding(1), 42, start + Duration::from_secs(1));
        assert_eq!(
            watch.due(binding(1), start + Duration::from_secs(2), true),
            None
        );
        assert_eq!(
            watch.due(binding(1), start + Duration::from_secs(3), true),
            Some(42)
        );
        // A later authentic frame resets the clock and provides a newer cursor.
        watch.note_authenticated_frame(binding(1), 43, start + Duration::from_secs(4));
        assert_eq!(
            watch.due(binding(1), start + Duration::from_secs(5), true),
            None
        );
        assert_eq!(
            watch.due(binding(1), start + Duration::from_secs(6), true),
            Some(43)
        );
    }

    #[test]
    fn silence_watch_does_not_mix_keys_or_reset_across_expired_sessions() {
        let start = Instant::now();
        let mut watch = PresentationKeyframeSilence::default();
        watch.note_authenticated_frame(binding(1), 99, start);
        assert_eq!(
            watch.due(binding(2), start + Duration::from_secs(20), true),
            None
        );
        assert_eq!(
            watch.due(binding(2), start + Duration::from_secs(22), true),
            Some(0)
        );
        watch.reset();
        assert_eq!(
            watch.due(binding(2), start + Duration::from_secs(50), true),
            None
        );
    }

    #[test]
    fn silence_watch_suppresses_healthy_or_regressed_timestamps() {
        let start = Instant::now();
        let mut watch = PresentationKeyframeSilence::default();
        watch.note_authenticated_frame(binding(1), 17, start + Duration::from_secs(10));
        assert_eq!(watch.due(binding(1), start, true), None);
        assert_eq!(
            watch.due(binding(1), start + Duration::from_secs(20), false),
            None
        );
        // Refuse an old observation attempting to replace current cursor.
        watch.note_authenticated_frame(binding(1), 1, start);
        assert_eq!(
            watch.due(binding(1), start + Duration::from_secs(12), true),
            Some(17)
        );
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
