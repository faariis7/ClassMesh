use std::fmt;
use std::sync::Arc;

use classmesh_video::distributor::{
    DEFAULT_MAX_QUEUE_DEPTH, DistributorError, FrameDistributor, SinkId, SinkMode,
};

use crate::wifi_direct_fanout::{
    DirectFanoutBenchmarkConfig, DirectFanoutBenchmarkError, DirectFanoutReceiverReport,
    synthetic_frame, validate_config,
};
use crate::wifi_fanout_benchmark::{WifiFanoutBenchmarkPlan, WifiFanoutBenchmarkPlanError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFanoutBenchmarkReport {
    pub teacher_frames_to_relay: u64,
    pub teacher_payload_bytes: u64,
    pub relay_frames_published: u64,
    pub payload_bytes_per_frame: usize,
    pub shared_allocation_mismatches: u64,
    pub receivers: Vec<DirectFanoutReceiverReport>,
}

impl RelayFanoutBenchmarkReport {
    #[must_use]
    pub fn receiver(&self, receiver_id: &str) -> Option<&DirectFanoutReceiverReport> {
        self.receivers
            .iter()
            .find(|receiver| receiver.receiver_id == receiver_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayFanoutBenchmarkError {
    Plan(WifiFanoutBenchmarkPlanError),
    Config(DirectFanoutBenchmarkError),
    WrongStrategyLabel(String),
    MissingWeakReceiver,
    Distributor(DistributorError),
    MissingSinkStats(String),
}

impl fmt::Display for RelayFanoutBenchmarkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(error) => write!(formatter, "invalid Wi-Fi benchmark plan: {error}"),
            Self::Config(error) => write!(formatter, "invalid relay fanout config: {error}"),
            Self::WrongStrategyLabel(label) => write!(
                formatter,
                "relay fanout benchmark requires strategy_label=relay, got {label:?}"
            ),
            Self::MissingWeakReceiver => {
                formatter.write_str("relay fanout benchmark requires one weak_receiver_probe")
            }
            Self::Distributor(error) => write!(formatter, "relay fanout distributor: {error:?}"),
            Self::MissingSinkStats(receiver_id) => {
                write!(
                    formatter,
                    "missing relay sink stats for receiver {receiver_id:?}"
                )
            }
        }
    }
}

impl std::error::Error for RelayFanoutBenchmarkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(error) => Some(error),
            Self::Config(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WifiFanoutBenchmarkPlanError> for RelayFanoutBenchmarkError {
    fn from(value: WifiFanoutBenchmarkPlanError) -> Self {
        Self::Plan(value)
    }
}

impl From<DistributorError> for RelayFanoutBenchmarkError {
    fn from(value: DistributorError) -> Self {
        Self::Distributor(value)
    }
}

pub fn run_relay_fanout_benchmark(
    plan: &WifiFanoutBenchmarkPlan,
    config: DirectFanoutBenchmarkConfig,
) -> Result<RelayFanoutBenchmarkReport, RelayFanoutBenchmarkError> {
    plan.validate()?;
    if plan.strategy_label != "relay" {
        return Err(RelayFanoutBenchmarkError::WrongStrategyLabel(
            plan.strategy_label.clone(),
        ));
    }
    let weak_receiver = plan
        .weak_receiver_probe
        .as_deref()
        .ok_or(RelayFanoutBenchmarkError::MissingWeakReceiver)?;
    validate_config(config).map_err(RelayFanoutBenchmarkError::Config)?;

    let mut distributor =
        FrameDistributor::with_limits(plan.receiver_ids.len(), DEFAULT_MAX_QUEUE_DEPTH)?;
    let mut sinks = Vec::with_capacity(plan.receiver_ids.len());
    for (index, receiver_id) in plan.receiver_ids.iter().enumerate() {
        let sink_id = SinkId(u64::try_from(index + 1).unwrap_or(u64::MAX));
        distributor.add_sink(sink_id, SinkMode::Unicast, config.queue_capacity)?;
        sinks.push((receiver_id.as_str(), sink_id));
    }

    let mut reports: Vec<DirectFanoutReceiverReport> = plan
        .receiver_ids
        .iter()
        .map(|receiver_id| DirectFanoutReceiverReport {
            receiver_id: receiver_id.clone(),
            delivered: 0,
            queue_dropped: 0,
            max_queued: 0,
            queued_at_end: 0,
        })
        .collect();

    let payload_bytes_u64 = u64::try_from(config.payload_bytes).unwrap_or(u64::MAX);
    let mut teacher_frames_to_relay = 0_u64;
    let mut teacher_payload_bytes = 0_u64;
    let mut relay_frames_published = 0_u64;
    let mut shared_allocation_mismatches = 0_u64;

    for frame_id in 1..=config.frame_count {
        let frame = synthetic_frame(frame_id, config.payload_bytes);
        let teacher_data = Arc::clone(&frame.data);

        teacher_frames_to_relay = teacher_frames_to_relay.saturating_add(1);
        teacher_payload_bytes = teacher_payload_bytes.saturating_add(payload_bytes_u64);

        let relay_data = Arc::clone(&frame.data);
        if !Arc::ptr_eq(&teacher_data, &relay_data) {
            shared_allocation_mismatches = shared_allocation_mismatches.saturating_add(1);
        }
        distributor.publish(frame);
        relay_frames_published = relay_frames_published.saturating_add(1);

        for (index, (_, sink_id)) in sinks.iter().enumerate() {
            let stats = distributor.stats(*sink_id).ok_or_else(|| {
                RelayFanoutBenchmarkError::MissingSinkStats(reports[index].receiver_id.clone())
            })?;
            reports[index].max_queued = reports[index].max_queued.max(stats.queued);
        }

        for (index, (receiver_id, sink_id)) in sinks.iter().enumerate() {
            let should_drain =
                *receiver_id != weak_receiver || frame_id % config.weak_drain_every == 0;
            if !should_drain {
                continue;
            }
            let Some(delivered) = distributor.pop_next_decodable(*sink_id) else {
                continue;
            };
            reports[index].delivered = reports[index].delivered.saturating_add(1);
            if delivered.meta.frame_id == frame_id && !Arc::ptr_eq(&relay_data, &delivered.data) {
                shared_allocation_mismatches = shared_allocation_mismatches.saturating_add(1);
            }
        }
    }

    for (index, (_, sink_id)) in sinks.iter().enumerate() {
        let stats = distributor.stats(*sink_id).ok_or_else(|| {
            RelayFanoutBenchmarkError::MissingSinkStats(reports[index].receiver_id.clone())
        })?;
        reports[index].queue_dropped = stats.dropped;
        reports[index].queued_at_end = stats.queued;
    }

    Ok(RelayFanoutBenchmarkReport {
        teacher_frames_to_relay,
        teacher_payload_bytes,
        relay_frames_published,
        payload_bytes_per_frame: config.payload_bytes,
        shared_allocation_mismatches,
        receivers: reports,
    })
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
            config
                .frame_count
                .saturating_mul(u64::try_from(config.payload_bytes).unwrap())
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
