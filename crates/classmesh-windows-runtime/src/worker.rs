use crate::SessionId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerProcess {
    pub session: SessionId,
    pub process_id: u32,
    pub launched_at_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerRestartPolicy {
    pub base_backoff_us: u64,
    pub max_backoff_us: u64,
    pub reset_after_healthy_us: u64,
    pub max_consecutive_failures: u8,
}

impl Default for WorkerRestartPolicy {
    fn default() -> Self {
        Self {
            base_backoff_us: 250_000,
            max_backoff_us: 10_000_000,
            reset_after_healthy_us: 60_000_000,
            max_consecutive_failures: 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerRestartDecision {
    RelaunchAfter { session: SessionId, delay_us: u64 },
    GiveUp { session: SessionId },
    Ignore,
}

#[derive(Debug)]
pub struct WorkerWatchdog {
    policy: WorkerRestartPolicy,
    process: Option<WorkerProcess>,
    consecutive_failures: u8,
}

impl WorkerWatchdog {
    #[must_use]
    pub const fn new(policy: WorkerRestartPolicy) -> Self {
        Self {
            policy,
            process: None,
            consecutive_failures: 0,
        }
    }

    pub fn launched(&mut self, process: WorkerProcess) {
        self.process = Some(process);
    }

    #[must_use]
    pub const fn process(&self) -> Option<WorkerProcess> {
        self.process
    }

    pub fn stopped_intentionally(&mut self, session: SessionId) {
        if self
            .process
            .is_some_and(|process| process.session == session)
        {
            self.process = None;
            self.consecutive_failures = 0;
        }
    }

    pub fn launch_failed(&mut self, session: SessionId) -> WorkerRestartDecision {
        self.process = None;
        self.next_failure_decision(session)
    }

    pub fn exited_unexpectedly(
        &mut self,
        now_us: u64,
        session: SessionId,
        process_id: u32,
    ) -> WorkerRestartDecision {
        let Some(process) = self.process else {
            return WorkerRestartDecision::Ignore;
        };
        if process.session != session || process.process_id != process_id {
            return WorkerRestartDecision::Ignore;
        }

        self.process = None;
        if now_us.saturating_sub(process.launched_at_us) >= self.policy.reset_after_healthy_us {
            self.consecutive_failures = 0;
        }
        self.next_failure_decision(session)
    }

    #[must_use]
    pub const fn consecutive_failures(&self) -> u8 {
        self.consecutive_failures
    }

    fn next_failure_decision(&mut self, session: SessionId) -> WorkerRestartDecision {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);

        if self.consecutive_failures > self.policy.max_consecutive_failures {
            return WorkerRestartDecision::GiveUp { session };
        }

        let exponent = u32::from(self.consecutive_failures.saturating_sub(1)).min(16);
        let delay_us = self
            .policy
            .base_backoff_us
            .saturating_mul(1_u64 << exponent)
            .min(self.policy.max_backoff_us);
        WorkerRestartDecision::RelaunchAfter { session, delay_us }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rapid_crashes_back_off_and_eventually_stop_restarting() {
        let mut watchdog = WorkerWatchdog::new(WorkerRestartPolicy {
            base_backoff_us: 100,
            max_backoff_us: 500,
            reset_after_healthy_us: 10_000,
            max_consecutive_failures: 2,
        });
        let session = SessionId(4);

        watchdog.launched(WorkerProcess {
            session,
            process_id: 10,
            launched_at_us: 0,
        });
        assert_eq!(
            watchdog.exited_unexpectedly(1, session, 10),
            WorkerRestartDecision::RelaunchAfter {
                session,
                delay_us: 100
            }
        );

        watchdog.launched(WorkerProcess {
            session,
            process_id: 11,
            launched_at_us: 2,
        });
        assert_eq!(
            watchdog.exited_unexpectedly(3, session, 11),
            WorkerRestartDecision::RelaunchAfter {
                session,
                delay_us: 200
            }
        );

        watchdog.launched(WorkerProcess {
            session,
            process_id: 12,
            launched_at_us: 4,
        });
        assert_eq!(
            watchdog.exited_unexpectedly(5, session, 12),
            WorkerRestartDecision::GiveUp { session }
        );
    }

    #[test]
    fn launch_failures_use_same_bounded_backoff() {
        let mut watchdog = WorkerWatchdog::new(WorkerRestartPolicy {
            base_backoff_us: 100,
            max_backoff_us: 500,
            reset_after_healthy_us: 10_000,
            max_consecutive_failures: 2,
        });
        let session = SessionId(8);
        assert_eq!(
            watchdog.launch_failed(session),
            WorkerRestartDecision::RelaunchAfter {
                session,
                delay_us: 100
            }
        );
        assert_eq!(
            watchdog.launch_failed(session),
            WorkerRestartDecision::RelaunchAfter {
                session,
                delay_us: 200
            }
        );
        assert_eq!(
            watchdog.launch_failed(session),
            WorkerRestartDecision::GiveUp { session }
        );
    }

    #[test]
    fn healthy_runtime_resets_crash_streak() {
        let mut watchdog = WorkerWatchdog::new(WorkerRestartPolicy {
            base_backoff_us: 100,
            max_backoff_us: 1_000,
            reset_after_healthy_us: 1_000,
            max_consecutive_failures: 5,
        });
        let session = SessionId(1);
        watchdog.launched(WorkerProcess {
            session,
            process_id: 1,
            launched_at_us: 0,
        });
        let _ = watchdog.exited_unexpectedly(10, session, 1);
        watchdog.launched(WorkerProcess {
            session,
            process_id: 2,
            launched_at_us: 20,
        });
        assert_eq!(
            watchdog.exited_unexpectedly(2_000, session, 2),
            WorkerRestartDecision::RelaunchAfter {
                session,
                delay_us: 100
            }
        );
        assert_eq!(watchdog.consecutive_failures(), 1);
    }
}
