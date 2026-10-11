//! Single-flight, text-free correlation for authorized clipboard read results.
//!
//! This module is not authorization and does not route clipboard text. A caller must
//! first pass the authenticated control guard, capability and ReadClipboard checks,
//! then bind the accepted read to the specific active interactive Worker. Do not
//! accept any Worker response without an exact successful completion here.

/// Maximum elapsed monotonic milliseconds before a read result must be rejected.
pub const CLIPBOARD_READ_TIMEOUT_MS: u64 = 5_000;

/// Identity of the *currently active* interactive Worker incarnation.
/// A process/session ID alone is insufficient after Worker restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipboardWorkerBinding {
    pub process_id: u32,
    pub session_id: u32,
    pub generation: u64,
}

/// A non-sensitive correlation record. This is not a permission/dispatch token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipboardReadBinding {
    pub control_session_id: u64,
    pub request_id: u64,
    pub worker: ClipboardWorkerBinding,
}

impl ClipboardReadBinding {
    fn is_valid(self) -> bool {
        self.control_session_id != 0
            && self.request_id != 0
            && self.worker.process_id != 0
            && self.worker.session_id != 0
            && self.worker.generation != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardCorrelationError {
    InvalidBinding,
    ClockOverflow,
    Busy,
    Missing,
    Mismatch,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingRead {
    binding: ClipboardReadBinding,
    expires_at_ms: u64,
}

/// Bounded at one pending read across the Service, so slow Workers cannot create
/// an unbounded pending queue. Caller supplies a monotonic millisecond clock.
#[derive(Debug, Default)]
pub struct ClipboardReadCorrelation {
    pending: Option<PendingRead>,
}

impl ClipboardReadCorrelation {
    /// Register only *after* authenticated privileged dispatch accepted the read.
    /// Expired entries are cleared on each registration to avoid sticky busy state.
    pub fn register(
        &mut self,
        binding: ClipboardReadBinding,
        now_ms: u64,
    ) -> Result<(), ClipboardCorrelationError> {
        if !binding.is_valid() {
            return Err(ClipboardCorrelationError::InvalidBinding);
        }
        let expires_at_ms = now_ms
            .checked_add(CLIPBOARD_READ_TIMEOUT_MS)
            .ok_or(ClipboardCorrelationError::ClockOverflow)?;
        self.expire(now_ms);
        if self.pending.is_some() {
            return Err(ClipboardCorrelationError::Busy);
        }
        self.pending = Some(PendingRead {
            binding,
            expires_at_ms,
        });
        Ok(())
    }

    /// Accept an exact Worker-bound response at most once. An expired entry is
    /// discarded even if the attempted response has mismatched identifiers.
    pub fn complete(
        &mut self,
        received: ClipboardReadBinding,
        now_ms: u64,
    ) -> Result<(), ClipboardCorrelationError> {
        let Some(pending) = self.pending else {
            return Err(ClipboardCorrelationError::Missing);
        };
        if now_ms >= pending.expires_at_ms {
            self.pending = None;
            return Err(ClipboardCorrelationError::Expired);
        }
        if pending.binding != received {
            return Err(ClipboardCorrelationError::Mismatch);
        }
        self.pending = None;
        Ok(())
    }

    /// Discard the read on disconnect, permission/session revocation or cleanup.
    pub fn cancel_session(&mut self, control_session_id: u64) -> bool {
        if self
            .pending
            .is_some_and(|pending| pending.binding.control_session_id == control_session_id)
        {
            self.pending = None;
            true
        } else {
            false
        }
    }

    /// Reject in-flight responses from any replaced Worker incarnation.
    pub fn invalidate_worker_change(&mut self, current: ClipboardWorkerBinding) -> bool {
        if self
            .pending
            .is_some_and(|pending| pending.binding.worker != current)
        {
            self.pending = None;
            true
        } else {
            false
        }
    }

    /// Caller must sweep with its monotonic clock, including when no new traffic arrives.
    pub fn expire(&mut self, now_ms: u64) -> bool {
        if self
            .pending
            .is_some_and(|pending| now_ms >= pending.expires_at_ms)
        {
            self.pending = None;
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn worker() -> ClipboardWorkerBinding {
        ClipboardWorkerBinding {
            process_id: 42,
            session_id: 7,
            generation: 3,
        }
    }

    fn binding() -> ClipboardReadBinding {
        ClipboardReadBinding {
            control_session_id: 77,
            request_id: 12,
            worker: worker(),
        }
    }

    #[test]
    fn correlation_consumes_only_one_matching_result() {
        let mut pending = ClipboardReadCorrelation::default();
        pending.register(binding(), 100).expect("valid read");
        assert_eq!(pending.complete(binding(), 4_999), Ok(()));
        assert_eq!(
            pending.complete(binding(), 4_999),
            Err(ClipboardCorrelationError::Missing)
        );
        assert!(!pending.is_pending());
    }

    #[test]
    fn single_flight_prevents_cross_session_busy_registration() {
        let mut pending = ClipboardReadCorrelation::default();
        pending.register(binding(), 100).expect("first read");
        let other = ClipboardReadBinding {
            control_session_id: 88,
            ..binding()
        };
        assert_eq!(
            pending.register(other, 100),
            Err(ClipboardCorrelationError::Busy)
        );
        assert!(pending.is_pending());
        assert_eq!(pending.complete(binding(), 101), Ok(()));
        assert_eq!(pending.register(other, 101), Ok(()));
    }

    #[test]
    fn zero_ids_and_worker_generation_are_rejected_before_registration() {
        let variants = [
            ClipboardReadBinding {
                control_session_id: 0,
                ..binding()
            },
            ClipboardReadBinding {
                request_id: 0,
                ..binding()
            },
            ClipboardReadBinding {
                worker: ClipboardWorkerBinding {
                    process_id: 0,
                    ..worker()
                },
                ..binding()
            },
            ClipboardReadBinding {
                worker: ClipboardWorkerBinding {
                    session_id: 0,
                    ..worker()
                },
                ..binding()
            },
            ClipboardReadBinding {
                worker: ClipboardWorkerBinding {
                    generation: 0,
                    ..worker()
                },
                ..binding()
            },
        ];
        let mut pending = ClipboardReadCorrelation::default();
        for invalid in variants {
            assert_eq!(
                pending.register(invalid, 100),
                Err(ClipboardCorrelationError::InvalidBinding)
            );
            assert!(!pending.is_pending());
        }
    }

    #[test]
    fn incorrect_session_request_or_worker_cannot_consume_pending_read() {
        let mut pending = ClipboardReadCorrelation::default();
        pending.register(binding(), 10).expect("valid");
        let incorrect = [
            ClipboardReadBinding {
                control_session_id: 9,
                ..binding()
            },
            ClipboardReadBinding {
                request_id: 13,
                ..binding()
            },
            ClipboardReadBinding {
                worker: ClipboardWorkerBinding {
                    process_id: 5,
                    ..worker()
                },
                ..binding()
            },
            ClipboardReadBinding {
                worker: ClipboardWorkerBinding {
                    session_id: 5,
                    ..worker()
                },
                ..binding()
            },
            ClipboardReadBinding {
                worker: ClipboardWorkerBinding {
                    generation: 4,
                    ..worker()
                },
                ..binding()
            },
        ];
        for other in incorrect {
            assert_eq!(
                pending.complete(other, 11),
                Err(ClipboardCorrelationError::Mismatch)
            );
            assert!(pending.is_pending());
        }
        assert_eq!(pending.complete(binding(), 11), Ok(()));
    }

    #[test]
    fn deadline_is_five_seconds_and_strict_at_boundary() {
        let mut pending = ClipboardReadCorrelation::default();
        pending.register(binding(), 100).expect("valid");
        assert_eq!(pending.complete(binding(), 5_099), Ok(()));

        pending.register(binding(), 100).expect("fresh");
        assert_eq!(
            pending.complete(binding(), 5_100),
            Err(ClipboardCorrelationError::Expired)
        );
        assert!(!pending.is_pending());
        assert_eq!(
            pending.complete(binding(), 5_100),
            Err(ClipboardCorrelationError::Missing)
        );
    }

    #[test]
    fn expiration_precedes_mismatch_and_unblocks_following_request() {
        let mut pending = ClipboardReadCorrelation::default();
        pending.register(binding(), 0).expect("valid");
        let wrong = ClipboardReadBinding {
            request_id: 999,
            ..binding()
        };
        assert_eq!(
            pending.complete(wrong, 5_000),
            Err(ClipboardCorrelationError::Expired)
        );
        assert_eq!(pending.register(wrong, 5_001), Ok(()));
        assert!(!pending.expire(10_000));
        assert!(pending.expire(10_001));
        assert!(!pending.is_pending());
    }

    #[test]
    fn clock_overflow_fails_closed() {
        let mut pending = ClipboardReadCorrelation::default();
        assert_eq!(
            pending.register(binding(), u64::MAX - 4_000),
            Err(ClipboardCorrelationError::ClockOverflow)
        );
        assert!(!pending.is_pending());
    }

    #[test]
    fn session_cancellation_is_exact_and_one_shot() {
        let mut pending = ClipboardReadCorrelation::default();
        pending.register(binding(), 0).expect("valid");
        assert!(!pending.cancel_session(88));
        assert!(pending.is_pending());
        assert!(pending.cancel_session(77));
        assert!(!pending.cancel_session(77));
        assert_eq!(
            pending.complete(binding(), 1),
            Err(ClipboardCorrelationError::Missing)
        );
    }

    #[test]
    fn new_worker_or_generation_invalidates_stale_pending_read() {
        let mut pending = ClipboardReadCorrelation::default();
        pending.register(binding(), 0).expect("valid");
        assert!(!pending.invalidate_worker_change(worker()));
        assert!(pending.is_pending());
        let replacement = ClipboardWorkerBinding {
            generation: 4,
            ..worker()
        };
        assert!(pending.invalidate_worker_change(replacement));
        assert!(!pending.is_pending());
        assert_eq!(
            pending.complete(binding(), 1),
            Err(ClipboardCorrelationError::Missing)
        );
    }

    #[test]
    fn explicit_expiration_clears_only_at_deadline() {
        let mut pending = ClipboardReadCorrelation::default();
        pending.register(binding(), 123).expect("valid");
        assert!(!pending.expire(5_122));
        assert!(pending.is_pending());
        assert!(pending.expire(5_123));
        assert!(!pending.expire(5_123));
    }
}
