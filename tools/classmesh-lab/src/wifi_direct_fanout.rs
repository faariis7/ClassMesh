use classmesh_video::distributor::DEFAULT_MAX_QUEUE_DEPTH;

use crate::wifi_fanout_benchmark::WifiFanoutBenchmarkPlan;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectFanoutBenchmarkConfig {
    pub frame_count: u64,
    pub payload_bytes: usize,
    pub queue_capacity: usize,
    pub weak_drain_every: u64,
}

impl Default for DirectFanoutBenchmarkConfig {
    fn default() -> Self {
        Self {
            frame_count: 120,
            payload_bytes: 1_200,
            queue_capacity: DEFAULT_MAX_QUEUE_DEPTH.min(4),
            weak_drain_every: 8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wifi_fanout_benchmark::WIFI_FANOUT_EVIDENCE_VERSION;

    fn plan(receiver_count: usize) -> WifiFanoutBenchmarkPlan {
        WifiFanoutBenchmarkPlan {
            schema_version: WIFI_FANOUT_EVIDENCE_VERSION,
            run_id: "direct-baseline-001".to_owned(),
            strategy_label: "direct-unicast".to_owned(),
            receiver_ids: (1..=receiver_count)
                .map(|index| format!("student-{index:02}"))
                .collect(),
            duration_seconds: 60,
            weak_receiver_probe: Some("student-01".to_owned()),
        }
    }

    #[test]
    fn weak_receiver_drops_do_not_spill_into_healthy_receivers() {
        let report =
            run_direct_fanout_benchmark(&plan(5), DirectFanoutBenchmarkConfig::default()).unwrap();

        let weak = report.receiver("student-01").unwrap();
        assert!(weak.queue_dropped > 0);
        assert!(weak.max_queued <= DirectFanoutBenchmarkConfig::default().queue_capacity);

        for healthy in report
            .receivers
            .iter()
            .filter(|receiver| receiver.receiver_id != "student-01")
        {
            assert_eq!(healthy.queue_dropped, 0);
            assert_eq!(healthy.max_queued, 0);
        }
        assert_eq!(report.shared_allocation_mismatches, 0);
    }

    #[test]
    fn all_supported_scale_points_preserve_one_shared_allocation() {
        for receiver_count in [5, 10, 20, 30] {
            let report = run_direct_fanout_benchmark(
                &plan(receiver_count),
                DirectFanoutBenchmarkConfig {
                    frame_count: 30,
                    ..DirectFanoutBenchmarkConfig::default()
                },
            )
            .unwrap();
            assert_eq!(report.shared_allocation_mismatches, 0);
            assert_eq!(report.receivers.len(), receiver_count);
        }
    }

    #[test]
    fn benchmark_requires_the_direct_unicast_label_and_weak_receiver() {
        let mut wrong_strategy = plan(5);
        wrong_strategy.strategy_label = "relay".to_owned();
        assert!(run_direct_fanout_benchmark(
            &wrong_strategy,
            DirectFanoutBenchmarkConfig::default()
        )
        .is_err());

        let mut no_weak_receiver = plan(5);
        no_weak_receiver.weak_receiver_probe = None;
        assert!(run_direct_fanout_benchmark(
            &no_weak_receiver,
            DirectFanoutBenchmarkConfig::default()
        )
        .is_err());
    }
}
