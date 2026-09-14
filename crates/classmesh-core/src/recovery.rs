#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryReason {
    AccessLost,
    DeviceRemoved,
    DeviceReset,
    DisplayChanged,
    MonitorHotPlug,
    SessionChanged,
    SecureDesktop,
    EncoderFailure,
    DecoderFailure,
    NetworkFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    Idle,
    Starting,
    Healthy,
    Suspended,
    Recovering { attempt: u8, reason: RecoveryReason },
    Failed { reason: RecoveryReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryPolicy {
    pub max_attempts: u8,
    pub base_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 8,
            base_backoff_ms: 100,
            max_backoff_ms: 5_000,
        }
    }
}

impl RecoveryPolicy {
    #[must_use]
    pub fn backoff_ms(self, attempt: u8) -> u64 {
        let exponent = u32::from(attempt.saturating_sub(1)).min(16);
        self.base_backoff_ms
            .saturating_mul(1_u64 << exponent)
            .min(self.max_backoff_ms)
    }
}

#[derive(Debug)]
pub struct RecoveryController {
    state: RecoveryState,
    policy: RecoveryPolicy,
}

impl RecoveryController {
    #[must_use]
    pub const fn new(policy: RecoveryPolicy) -> Self {
        Self {
            state: RecoveryState::Idle,
            policy,
        }
    }

    #[must_use]
    pub const fn state(&self) -> RecoveryState {
        self.state
    }

    pub fn mark_starting(&mut self) {
        self.state = RecoveryState::Starting;
    }

    pub fn mark_healthy(&mut self) {
        self.state = RecoveryState::Healthy;
    }

    pub fn suspend(&mut self) {
        self.state = RecoveryState::Suspended;
    }

    /// Starts a new recovery sequence and returns the delay before the first retry.
    pub fn begin(&mut self, reason: RecoveryReason) -> u64 {
        self.state = RecoveryState::Recovering { attempt: 1, reason };
        self.policy.backoff_ms(1)
    }

    /// Records a failed recovery attempt.
    ///
    /// Returns the delay before another attempt, or `None` after the policy limit is reached.
    pub fn retry_failed(&mut self) -> Option<u64> {
        let RecoveryState::Recovering { attempt, reason } = self.state else {
            return None;
        };

        if attempt >= self.policy.max_attempts {
            self.state = RecoveryState::Failed { reason };
            return None;
        }

        let next_attempt = attempt.saturating_add(1);
        self.state = RecoveryState::Recovering {
            attempt: next_attempt,
            reason,
        };
        Some(self.policy.backoff_ms(next_attempt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_uses_bounded_exponential_backoff() {
        let policy = RecoveryPolicy {
            max_attempts: 4,
            base_backoff_ms: 100,
            max_backoff_ms: 250,
        };
        assert_eq!(policy.backoff_ms(1), 100);
        assert_eq!(policy.backoff_ms(2), 200);
        assert_eq!(policy.backoff_ms(3), 250);
        assert_eq!(policy.backoff_ms(9), 250);
    }

    #[test]
    fn controller_eventually_enters_failed_state() {
        let mut controller = RecoveryController::new(RecoveryPolicy {
            max_attempts: 2,
            base_backoff_ms: 1,
            max_backoff_ms: 2,
        });
        assert_eq!(controller.begin(RecoveryReason::AccessLost), 1);
        assert_eq!(controller.retry_failed(), Some(2));
        assert_eq!(controller.retry_failed(), None);
        assert_eq!(
            controller.state(),
            RecoveryState::Failed {
                reason: RecoveryReason::AccessLost
            }
        );
    }

    #[test]
    fn successful_recovery_resets_state() {
        let mut controller = RecoveryController::new(RecoveryPolicy::default());
        let _ = controller.begin(RecoveryReason::DisplayChanged);
        controller.mark_healthy();
        assert_eq!(controller.state(), RecoveryState::Healthy);
    }
}
