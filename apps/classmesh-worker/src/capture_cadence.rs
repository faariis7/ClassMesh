//! Bounded capture submission cadence for the real Windows GPU encoder.

#[derive(Debug, Default)]
pub struct CaptureCadence {
    next_due_us: Option<u64>,
    last_seen_us: Option<u64>,
}

impl CaptureCadence {
    /// Only the first frame at or beyond the next target deadline is submitted.
    pub fn should_submit(&mut self, timestamp_us: u64, interval_us: u64) -> bool {
        if interval_us == 0 {
            return false;
        }
        // Desktop Duplication normally supplies monotonic timestamps. If a
        // recovered capture backend restarts its clock, re-arm instead of
        // suppressing the stream until the old timestamp is reached again.
        if self.last_seen_us.is_some_and(|last| timestamp_us < last) {
            self.next_due_us = None;
        }
        self.last_seen_us = Some(timestamp_us);

        match self.next_due_us {
            Some(next_due) if timestamp_us < next_due => false,
            Some(next_due) => {
                // Advance the *original* deadline, not the accepted frame's
                // timestamp. A slightly faster source must not force every
                // second frame to be dropped. Skip missed slots after a gap
                // rather than emitting a catch-up burst.
                let elapsed = timestamp_us - next_due;
                let slots = (elapsed / interval_us).saturating_add(1);
                self.next_due_us = Some(next_due.saturating_add(slots.saturating_mul(interval_us)));
                true
            }
            None => {
                self.next_due_us = Some(timestamp_us.saturating_add(interval_us));
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slightly_faster_capture_does_not_halve_a_thirty_fps_target() {
        // A 30.03 fps source is slightly faster than the 30 fps encoder target.
        // Re-anchoring each deadline to the last accepted frame can erroneously
        // discard every other frame, yielding ~15 fps.
        let mut cadence = CaptureCadence::default();
        let submitted = (0..300_u64)
            .filter(|frame| cadence.should_submit(frame * 33_300, 33_333))
            .count();
        assert!(
            (290..=300).contains(&submitted),
            "submitted {submitted}/300 frames"
        );
    }

    #[test]
    fn a_restarted_capture_clock_rearms_the_live_encoder_cadence() {
        let mut cadence = CaptureCadence::default();
        assert!(cadence.should_submit(5_000_000, 33_333));
        assert!(!cadence.should_submit(5_000_100, 33_333));
        assert!(cadence.should_submit(0, 33_333));
        assert!(!cadence.should_submit(10_000, 33_333));
        assert!(cadence.should_submit(33_333, 33_333));
    }

    #[test]
    fn invalid_zero_interval_never_submits() {
        let mut cadence = CaptureCadence::default();
        assert!(!cadence.should_submit(0, 0));
        assert!(cadence.should_submit(0, 33_333));
    }

    #[test]
    fn large_capture_gap_never_creates_a_catch_up_burst() {
        let mut cadence = CaptureCadence::default();
        assert!(cadence.should_submit(0, 33_333));
        assert!(cadence.should_submit(10_000_000, 33_333));
        assert!(!cadence.should_submit(10_000_100, 33_333));
    }
}
