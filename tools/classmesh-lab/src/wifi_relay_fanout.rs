use crate::wifi_direct_fanout::DirectFanoutBenchmarkConfig;
use crate::wifi_fanout_benchmark::{WifiFanoutBenchmarkPlan, WifiFanoutBenchmarkPlanError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFanoutBenchmarkReport;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayFanoutBenchmarkError {
    Plan(WifiFanoutBenchmarkPlanError),
}

pub fn run_relay_fanout_benchmark(
    _plan: &WifiFanoutBenchmarkPlan,
    _config: DirectFanoutBenchmarkConfig,
) -> Result<RelayFanoutBenchmarkReport, RelayFanoutBenchmarkError> {
    todo!("Phase 8C RED: implement relay fanout benchmark")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi_fanout_benchmark::WIFI_FANOUT_EVIDENCE_VERSION;

    fn plan(receiver_count: usize) -> WifiFanoutBenchmarkPlan {
        WifiFanoutBenchmarkPlan {
            schema_version: WIFI_FANOUT_EVIDENCE_VERSION,
            run_id: "relay-baseline-001".to_owned(),
            strategy_label: "relay".to_owned(),
            receiver_ids: (1..=receiver_count)
                .map(|index| format!("student-{index:02}"))
                .collect(),
            duration_seconds: 60,
            weak_receiver_probe: Some("student-01".to_owned()),
        }
    }

    #[test]
    fn relay_teacher_uplink_is_one_frame_per_published_frame() {
        let config = DirectFanoutBenchmarkConfig {
            frame_count: 30,
            ..DirectFanoutBenchmarkConfig::default()
        };
        let report = run_relay_fanout_benchmark(&plan(5), config).unwrap();
        assert_eq!(report.teacher_frames_to_relay, config.frame_count);
        assert_eq!(
            report.teacher_payload_bytes,
            config.frame_count.saturating_mul(config.payload_bytes as u64)
        );
        assert_eq!(report.relay_frames_published, config.frame_count);
        assert_eq!(report.shared_allocation_mismatches, 0);
    }

    #[test]
    fn weak_receiver_drops_do_not_spill_from_relay_to_healthy_receivers() {
        let config = DirectFanoutBenchmarkConfig::default();
        let report = run_relay_fanout_benchmark(&plan(5), config).unwrap();

        let weak = report.receiver("student-01").unwrap();
        assert!(weak.queue_dropped > 0);
        assert!(weak.max_queued <= config.queue_capacity);

        for healthy in report
            .receivers
            .iter()
            .filter(|receiver| receiver.receiver_id != "student-01")
        {
            assert_eq!(healthy.queue_dropped, 0);
            assert_eq!(healthy.delivered, config.frame_count);
        }
    }

    #[test]
    fn relay_supports_the_same_scale_points_as_direct() {
        for receiver_count in [5, 10, 20, 30] {
            let report = run_relay_fanout_benchmark(
                &plan(receiver_count),
                DirectFanoutBenchmarkConfig {
                    frame_count: 15,
                    ..DirectFanoutBenchmarkConfig::default()
                },
            )
            .unwrap();
            assert_eq!(report.receivers.len(), receiver_count);
            assert_eq!(report.teacher_frames_to_relay, 15);
        }
    }

    #[test]
    fn relay_requires_relay_strategy_and_weak_receiver() {
        let mut wrong = plan(5);
        wrong.strategy_label = "direct-unicast".to_owned();
        assert!(matches!(
            run_relay_fanout_benchmark(&wrong, DirectFanoutBenchmarkConfig::default()),
            Err(RelayFanoutBenchmarkError::WrongStrategyLabel(_))
        ));

        let mut missing = plan(5);
        missing.weak_receiver_probe = None;
        assert!(matches!(
            run_relay_fanout_benchmark(&missing, DirectFanoutBenchmarkConfig::default()),
            Err(RelayFanoutBenchmarkError::MissingWeakReceiver)
        ));
    }
}
