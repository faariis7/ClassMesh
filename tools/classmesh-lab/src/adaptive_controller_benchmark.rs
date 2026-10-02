use classmesh_core::adaptation::QualityTier;

pub const ADAPTIVE_SCALE_POINTS: [usize; 4] = [5, 10, 20, 30];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveControllerBenchmarkConfig {
    pub receivers: usize,
    pub rounds: u32,
}

impl Default for AdaptiveControllerBenchmarkConfig {
    fn default() -> Self {
        Self {
            receivers: 30,
            rounds: 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptiveControllerBenchmarkReport {
    pub receivers: usize,
    pub rounds: u32,
    pub healthy_high_after_weak_degrade: usize,
    pub weak_degraded_tier: QualityTier,
    pub weak_recovered_tier: QualityTier,
    pub noisy_receiver_tier_changes: u32,
    pub max_routed_receivers: usize,
    pub unresolved_transport_blocked: bool,
    pub qualified_switch_required_hysteresis: bool,
    pub unresolved_rendition_blocked: bool,
    pub reliable_fallback_eligible_without_default_selection: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdaptiveControllerBenchmarkError {
    UnsupportedReceiverCount(usize),
    InvalidRounds,
    Invariant(&'static str),
}

pub fn run_adaptive_controller_benchmark(
    _config: AdaptiveControllerBenchmarkConfig,
) -> Result<AdaptiveControllerBenchmarkReport, AdaptiveControllerBenchmarkError> {
    todo!("Phase 10G RED: exercise production adaptation contracts")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_scale_points_preserve_per_receiver_isolation() {
        for receivers in ADAPTIVE_SCALE_POINTS {
            let report = run_adaptive_controller_benchmark(AdaptiveControllerBenchmarkConfig {
                receivers,
                rounds: 30,
            })
            .unwrap();
            assert_eq!(report.receivers, receivers);
            assert_eq!(
                report.healthy_high_after_weak_degrade,
                receivers.saturating_sub(1)
            );
            assert_eq!(report.weak_degraded_tier, QualityTier::Emergency);
            assert_eq!(report.weak_recovered_tier, QualityTier::High);
            assert_eq!(report.max_routed_receivers, receivers);
        }
    }

    #[test]
    fn noisy_samples_do_not_flap_tier_without_hysteresis_evidence() {
        let report =
            run_adaptive_controller_benchmark(AdaptiveControllerBenchmarkConfig::default())
                .unwrap();
        assert_eq!(report.noisy_receiver_tier_changes, 0);
    }

    #[test]
    fn unresolved_physical_and_rendition_candidates_remain_blocked() {
        let report =
            run_adaptive_controller_benchmark(AdaptiveControllerBenchmarkConfig::default())
                .unwrap();
        assert!(report.unresolved_transport_blocked);
        assert!(report.unresolved_rendition_blocked);
        assert!(report.qualified_switch_required_hysteresis);
        assert!(report.reliable_fallback_eligible_without_default_selection);
    }

    #[test]
    fn unsupported_scale_and_empty_rounds_fail_closed() {
        assert_eq!(
            run_adaptive_controller_benchmark(AdaptiveControllerBenchmarkConfig {
                receivers: 3,
                rounds: 30,
            }),
            Err(AdaptiveControllerBenchmarkError::UnsupportedReceiverCount(3))
        );
        assert_eq!(
            run_adaptive_controller_benchmark(AdaptiveControllerBenchmarkConfig {
                receivers: 5,
                rounds: 0,
            }),
            Err(AdaptiveControllerBenchmarkError::InvalidRounds)
        );
    }
}
