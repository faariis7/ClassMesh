//! Shared admission budget for completed, but unauthenticated, UDP media.
//! Count-bounded channels alone would permit 64 * 8 MiB of ciphertext.
//! Keep the event count for normal bursts and cap queued ciphertext bytes.
use std::sync::atomic::{AtomicUsize, Ordering};

use classmesh_network::multicast_receiver::ProtectedMulticastReceiveOutcome;

/// Separate from the at-most-three in-flight reassemblies and Worker decoder.
pub const MAX_QUEUED_CIPHERTEXT_BYTES: usize = 96 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct UnverifiedQueueBudget {
    bytes: AtomicUsize,
}

impl UnverifiedQueueBudget {
    #[must_use]
    pub fn try_reserve(&self, incoming: usize) -> bool {
        if incoming == 0 {
            return true;
        }
        let mut current = self.bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = current
                .checked_add(incoming)
                .filter(|&next| next <= MAX_QUEUED_CIPHERTEXT_BYTES)
            else {
                return false;
            };
            match self.bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    pub fn release(&self, consumed: usize) {
        if consumed != 0 {
            let previous = self.bytes.fetch_sub(consumed, Ordering::AcqRel);
            debug_assert!(
                previous >= consumed,
                "unverified queue byte accounting underflow"
            );
        }
    }

    #[must_use]
    pub fn queued(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }
}

/// All multicast and unicast protected receive outcomes share this enum.
#[must_use]
pub fn candidate_bytes(outcome: &ProtectedMulticastReceiveOutcome) -> usize {
    match outcome {
        ProtectedMulticastReceiveOutcome::Events(batch) => batch
            .frames
            .iter()
            .map(|frame| frame.ciphertext().len())
            .sum(),
        ProtectedMulticastReceiveOutcome::Dropped(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_unverified_candidates_cannot_fill_an_unbounded_event_queue() {
        let budget = UnverifiedQueueBudget::default();
        let maximum = classmesh_security::group_media::MAX_GROUP_MEDIA_SEALED_BYTES;
        let accepted = MAX_QUEUED_CIPHERTEXT_BYTES / maximum;
        for _ in 0..accepted {
            assert!(budget.try_reserve(maximum));
        }
        assert!(!budget.try_reserve(maximum));
        assert!(budget.queued() <= MAX_QUEUED_CIPHERTEXT_BYTES);
        budget.release(maximum);
        assert!(budget.try_reserve(maximum));
    }

    #[test]
    fn small_frames_keep_the_normal_sixty_four_event_burst_and_release_budget() {
        let budget = UnverifiedQueueBudget::default();
        for _ in 0..64 {
            assert!(budget.try_reserve(4096));
        }
        assert_eq!(budget.queued(), 64 * 4096);
        for _ in 0..64 {
            budget.release(4096);
        }
        assert_eq!(budget.queued(), 0);
        assert!(!budget.try_reserve(usize::MAX));
    }
}
