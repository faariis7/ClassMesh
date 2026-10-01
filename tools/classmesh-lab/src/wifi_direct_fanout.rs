use std::fmt;
use std::sync::Arc;

use classmesh_video::distributor::{
    DEFAULT_MAX_QUEUE_DEPTH, DistributorError, FrameDistributor, SharedEncodedFrame, SinkId,
    SinkMode,
};
use classmesh_video::{Codec, EncodedFrameMeta};

use crate::wifi_fanout_benchmark::{WifiFanoutBenchmarkPlan, WifiFanoutBenchmarkPlanError};

pub const MAX_SYNTHETIC_FRAME_COUNT: u64 = 1_000_000;
pub const MAX_SYNTHETIC_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectFanoutReceiverReport {
    pub receiver_id: String,
    pub delivered: u64,
    pub queue_dropped: u64,
    pub max_queued: usize,
    pub queued_at_end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectFanoutBenchmarkReport {
    pub frames_published: u64,
    pub payload_bytes_per_frame: usize,
    pub shared_allocation_mismatches: u64,
    pub receivers: Vec<DirectFanoutReceiverReport>,
}

impl DirectFanoutBenchmarkReport {
    #[must_use]
    pub fn receiver(&self, receiver_id: &str) -> Option<&DirectFanoutReceiverReport> {
        self.receivers
            .iter()
            .find(|receiver| receiver.receiver_id == receiver_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectFanoutBenchmarkError {
    Plan(WifiFanoutBenchmarkPlanError),
    WrongStrategyLabel(String),
    MissingWeakReceiver,
    InvalidFrameCount(u64),
    InvalidPayloadBytes(usize),
    InvalidQueueCapacity(usize),
    InvalidWeakDrainEvery(u64),
    Distributor(DistributorError),
    MissingSinkStats(String),
}

impl fmt::Display for DirectFanoutBenchmarkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plan(error) => write!(formatter, "invalid Wi-Fi benchmark plan: {error}"),
            Self::WrongStrategyLabel(label) => {
                write!(
                    formatter,
                    "direct fanout benchmark requires strategy_label=direct-unicast, got {label:?}"
                )
            }
            Self::MissingWeakReceiver => {
                formatter.write_str("direct fanout benchmark requires one weak_receiver_probe")
            }
            Self::InvalidFrameCount(count) => write!(
                formatter,
                "invalid synthetic frame count {count}; expected 1..={MAX_SYNTHETIC_FRAME_COUNT}"
            ),
            Self::InvalidPayloadBytes(bytes) => write!(
                formatter,
                "invalid synthetic payload size {bytes}; expected 1..={MAX_SYNTHETIC_PAYLOAD_BYTES}"
            ),
            Self::InvalidQueueCapacity(capacity) => write!(
                formatter,
                "invalid queue capacity {capacity}; expected 1..={DEFAULT_MAX_QUEUE_DEPTH}"
            ),
            Self::InvalidWeakDrainEvery(every) => {
                write!(
                    formatter,
                    "invalid weak receiver drain interval {every}; expected at least 2"
                )
            }
            Self::Distributor(error) => write!(formatter, "fanout distributor: {error:?}"),
            Self::MissingSinkStats(receiver_id) => {
                write!(formatter, "missing sink stats for receiver {receiver_id:?}")
            }
        }
    }
}

impl std::error::Error for DirectFanoutBenchmarkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Plan(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WifiFanoutBenchmarkPlanError> for DirectFanoutBenchmarkError {
    fn from(value: WifiFanoutBenchmarkPlanError) -> Self {
        Self::Plan(value)
    }
}

impl From<DistributorError> for DirectFanoutBenchmarkError {
    fn from(value: DistributorError) -> Self {
        Self::Distributor(value)
    }
}

pub fn run_direct_fanout_benchmark(
    plan: &WifiFanoutBenchmarkPlan,
    config: DirectFanoutBenchmarkConfig,
) -> Result<DirectFanoutBenchmarkReport, DirectFanoutBenchmarkError> {
    plan.validate()?;
    if plan.strategy_label != "direct-unicast" {
        return Err(DirectFanoutBenchmarkError::WrongStrategyLabel(
            plan.strategy_label.clone(),
        ));
    }
    let weak_receiver = plan
        .weak_receiver_probe
        .as_deref()
        .ok_or(DirectFanoutBenchmarkError::MissingWeakReceiver)?;
    validate_config(config)?;

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
    let mut shared_allocation_mismatches = 0_u64;

    for frame_id in 1..=config.frame_count {
        let frame = synthetic_frame(frame_id, config.payload_bytes);
        let published_data = Arc::clone(&frame.data);
        distributor.publish(frame);

        for (index, (_, sink_id)) in sinks.iter().enumerate() {
            let stats = distributor.stats(*sink_id).ok_or_else(|| {
                DirectFanoutBenchmarkError::MissingSinkStats(reports[index].receiver_id.clone())
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
            if delivered.meta.frame_id == frame_id && !Arc::ptr_eq(&published_data, &delivered.data)
            {
                shared_allocation_mismatches = shared_allocation_mismatches.saturating_add(1);
            }
        }
    }

    for (index, (_, sink_id)) in sinks.iter().enumerate() {
        let stats = distributor.stats(*sink_id).ok_or_else(|| {
            DirectFanoutBenchmarkError::MissingSinkStats(reports[index].receiver_id.clone())
        })?;
        reports[index].queue_dropped = stats.dropped;
        reports[index].queued_at_end = stats.queued;
    }

    Ok(DirectFanoutBenchmarkReport {
        frames_published: config.frame_count,
        payload_bytes_per_frame: config.payload_bytes,
        shared_allocation_mismatches,
        receivers: reports,
    })
}

pub(crate) fn validate_config(
    config: DirectFanoutBenchmarkConfig,
) -> Result<(), DirectFanoutBenchmarkError> {
    if config.frame_count == 0 || config.frame_count > MAX_SYNTHETIC_FRAME_COUNT {
        return Err(DirectFanoutBenchmarkError::InvalidFrameCount(
            config.frame_count,
        ));
    }
    if config.payload_bytes == 0 || config.payload_bytes > MAX_SYNTHETIC_PAYLOAD_BYTES {
        return Err(DirectFanoutBenchmarkError::InvalidPayloadBytes(
            config.payload_bytes,
        ));
    }
    if config.queue_capacity == 0 || config.queue_capacity > DEFAULT_MAX_QUEUE_DEPTH {
        return Err(DirectFanoutBenchmarkError::InvalidQueueCapacity(
            config.queue_capacity,
        ));
    }
    if config.weak_drain_every < 2 {
        return Err(DirectFanoutBenchmarkError::InvalidWeakDrainEvery(
            config.weak_drain_every,
        ));
    }
    Ok(())
}

pub(crate) fn synthetic_frame(frame_id: u64, payload_bytes: usize) -> SharedEncodedFrame {
    SharedEncodedFrame::new(
        EncodedFrameMeta {
            frame_id,
            timestamp_us: frame_id.saturating_mul(33_333),
            keyframe: frame_id == 1 || frame_id % 60 == 1,
        },
        Codec::H264,
        vec![u8::try_from(frame_id & 0xff).unwrap_or(0); payload_bytes],
    )
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
        let config = DirectFanoutBenchmarkConfig::default();
        let report = run_direct_fanout_benchmark(&plan(5), config).unwrap();

        let weak = report.receiver("student-01").unwrap();
        assert!(weak.queue_dropped > 0);
        assert!(weak.max_queued <= config.queue_capacity);

        for healthy in report
            .receivers
            .iter()
            .filter(|receiver| receiver.receiver_id != "student-01")
        {
            assert_eq!(healthy.queue_dropped, 0);
            assert_eq!(healthy.max_queued, 1);
            assert_eq!(healthy.queued_at_end, 0);
            assert_eq!(healthy.delivered, config.frame_count);
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
        assert!(matches!(
            run_direct_fanout_benchmark(&wrong_strategy, DirectFanoutBenchmarkConfig::default()),
            Err(DirectFanoutBenchmarkError::WrongStrategyLabel(_))
        ));

        let mut no_weak_receiver = plan(5);
        no_weak_receiver.weak_receiver_probe = None;
        assert!(matches!(
            run_direct_fanout_benchmark(&no_weak_receiver, DirectFanoutBenchmarkConfig::default()),
            Err(DirectFanoutBenchmarkError::MissingWeakReceiver)
        ));
    }

    #[test]
    fn config_bounds_fail_closed() {
        let plan = plan(5);
        assert!(matches!(
            run_direct_fanout_benchmark(
                &plan,
                DirectFanoutBenchmarkConfig {
                    frame_count: 0,
                    ..DirectFanoutBenchmarkConfig::default()
                }
            ),
            Err(DirectFanoutBenchmarkError::InvalidFrameCount(0))
        ));
        assert!(matches!(
            run_direct_fanout_benchmark(
                &plan,
                DirectFanoutBenchmarkConfig {
                    queue_capacity: DEFAULT_MAX_QUEUE_DEPTH + 1,
                    ..DirectFanoutBenchmarkConfig::default()
                }
            ),
            Err(DirectFanoutBenchmarkError::InvalidQueueCapacity(_))
        ));
    }
}
