pub const DEFAULT_MONITORING_HEARTBEAT_US: u64 = 2_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitoringChangeHint {
    pub region_metadata_bytes: u32,
}

impl MonitoringChangeHint {
    #[must_use]
    pub const fn has_region_change(self) -> bool {
        self.region_metadata_bytes > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringEmissionReason {
    Initial,
    RegionChange,
    Heartbeat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitoringEmissionDecision {
    pub emit: bool,
    pub reason: Option<MonitoringEmissionReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringEmissionError {
    InvalidHeartbeatInterval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitoringEmissionPolicy {
    heartbeat_interval_us: u64,
    last_emitted_us: Option<u64>,
}

impl Default for MonitoringEmissionPolicy {
    fn default() -> Self {
        Self {
            heartbeat_interval_us: DEFAULT_MONITORING_HEARTBEAT_US,
            last_emitted_us: None,
        }
    }
}

impl MonitoringEmissionPolicy {
    pub fn new(heartbeat_interval_us: u64) -> Result<Self, MonitoringEmissionError> {
        if heartbeat_interval_us == 0 {
            return Err(MonitoringEmissionError::InvalidHeartbeatInterval);
        }
        Ok(Self {
            heartbeat_interval_us,
            last_emitted_us: None,
        })
    }

    #[must_use]
    pub fn observe(
        &mut self,
        now_us: u64,
        change: MonitoringChangeHint,
    ) -> MonitoringEmissionDecision {
        let reason = if self.last_emitted_us.is_none() {
            Some(MonitoringEmissionReason::Initial)
        } else if change.has_region_change() {
            Some(MonitoringEmissionReason::RegionChange)
        } else if self
            .last_emitted_us
            .is_some_and(|last| now_us.saturating_sub(last) >= self.heartbeat_interval_us)
        {
            Some(MonitoringEmissionReason::Heartbeat)
        } else {
            None
        };

        if reason.is_some() {
            self.last_emitted_us = Some(now_us);
        }

        MonitoringEmissionDecision {
            emit: reason.is_some(),
            reason,
        }
    }

    #[must_use]
    pub const fn heartbeat_interval_us(&self) -> u64 {
        self.heartbeat_interval_us
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unchanged() -> MonitoringChangeHint {
        MonitoringChangeHint {
            region_metadata_bytes: 0,
        }
    }

    fn changed() -> MonitoringChangeHint {
        MonitoringChangeHint {
            region_metadata_bytes: 64,
        }
    }

    #[test]
    fn first_sample_emits_even_without_change_metadata() {
        let mut policy = MonitoringEmissionPolicy::default();
        assert_eq!(
            policy.observe(0, unchanged()),
            MonitoringEmissionDecision {
                emit: true,
                reason: Some(MonitoringEmissionReason::Initial),
            }
        );
    }

    #[test]
    fn unchanged_samples_are_suppressed_until_heartbeat() {
        let mut policy = MonitoringEmissionPolicy::new(2_000_000).unwrap();
        assert!(policy.observe(0, unchanged()).emit);
        assert!(!policy.observe(500_000, unchanged()).emit);
        assert!(!policy.observe(1_999_999, unchanged()).emit);
        assert_eq!(
            policy.observe(2_000_000, unchanged()).reason,
            Some(MonitoringEmissionReason::Heartbeat)
        );
    }

    #[test]
    fn region_change_emits_immediately_and_resets_freshness_clock() {
        let mut policy = MonitoringEmissionPolicy::new(2_000_000).unwrap();
        assert!(policy.observe(0, unchanged()).emit);
        assert_eq!(
            policy.observe(500_000, changed()).reason,
            Some(MonitoringEmissionReason::RegionChange)
        );
        assert!(!policy.observe(2_000_000, unchanged()).emit);
        assert_eq!(
            policy.observe(2_500_000, unchanged()).reason,
            Some(MonitoringEmissionReason::Heartbeat)
        );
    }

    #[test]
    fn zero_heartbeat_interval_fails_closed() {
        assert_eq!(
            MonitoringEmissionPolicy::new(0),
            Err(MonitoringEmissionError::InvalidHeartbeatInterval)
        );
    }
}
