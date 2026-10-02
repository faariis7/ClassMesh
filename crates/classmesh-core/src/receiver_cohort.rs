use std::collections::BTreeMap;

use crate::adaptation::{AdaptationPolicy, HysteresisConfig, StreamDecision};
use crate::cohort::{CohortKey, CohortRouter, ReceiverId, ReceiverRoute};
use crate::quality_sample::ReceiverQualitySample;
use crate::receiver_quality::{
    ReceiverQualityController, ReceiverQualityObservation, ReceiverQualityPolicy,
    ReceiverQualityPolicyError,
};
use crate::{MediaTransport, StreamKind};

pub const DEFAULT_MAX_COHORT_RECEIVERS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverCohortPlannerConfig {
    pub max_receivers: usize,
}

impl Default for ReceiverCohortPlannerConfig {
    fn default() -> Self {
        Self {
            max_receivers: DEFAULT_MAX_COHORT_RECEIVERS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverCohortPlannerError {
    InvalidMaxReceivers,
    InvalidQualityPolicy(ReceiverQualityPolicyError),
    DuplicateReceiver,
    ReceiverLimitReached,
    UnknownReceiver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverCohortObservation {
    pub quality: ReceiverQualityObservation,
    pub route: ReceiverRoute,
}

#[derive(Debug)]
struct ReceiverState {
    transport: MediaTransport,
    quality: ReceiverQualityController,
}

#[derive(Debug)]
pub struct ReceiverCohortPlanner {
    kind: StreamKind,
    adaptation_policy: AdaptationPolicy,
    hysteresis: HysteresisConfig,
    quality_policy: ReceiverQualityPolicy,
    config: ReceiverCohortPlannerConfig,
    receivers: BTreeMap<ReceiverId, ReceiverState>,
    router: CohortRouter,
}

impl ReceiverCohortPlanner {
    pub fn new(
        kind: StreamKind,
        adaptation_policy: AdaptationPolicy,
        hysteresis: HysteresisConfig,
        quality_policy: ReceiverQualityPolicy,
        config: ReceiverCohortPlannerConfig,
    ) -> Result<Self, ReceiverCohortPlannerError> {
        if config.max_receivers == 0 {
            return Err(ReceiverCohortPlannerError::InvalidMaxReceivers);
        }
        let quality_policy = quality_policy
            .validate()
            .map_err(ReceiverCohortPlannerError::InvalidQualityPolicy)?;

        Ok(Self {
            kind,
            adaptation_policy,
            hysteresis,
            quality_policy,
            config,
            receivers: BTreeMap::new(),
            router: CohortRouter::default(),
        })
    }

    pub fn register(
        &mut self,
        receiver: ReceiverId,
        transport: MediaTransport,
    ) -> Result<(), ReceiverCohortPlannerError> {
        if self.receivers.contains_key(&receiver) {
            return Err(ReceiverCohortPlannerError::DuplicateReceiver);
        }
        if self.receivers.len() >= self.config.max_receivers {
            return Err(ReceiverCohortPlannerError::ReceiverLimitReached);
        }

        let quality = ReceiverQualityController::new(
            self.kind,
            self.adaptation_policy,
            self.hysteresis,
            self.quality_policy,
        )
        .map_err(ReceiverCohortPlannerError::InvalidQualityPolicy)?;
        self.receivers
            .insert(receiver, ReceiverState { transport, quality });
        Ok(())
    }

    pub fn observe(
        &mut self,
        receiver: ReceiverId,
        sample: ReceiverQualitySample,
        now_us: u64,
    ) -> Result<ReceiverCohortObservation, ReceiverCohortPlannerError> {
        let state = self
            .receivers
            .get_mut(&receiver)
            .ok_or(ReceiverCohortPlannerError::UnknownReceiver)?;
        let quality = state.quality.observe(sample, now_us);
        let decision = StreamDecision {
            transport: state.transport,
            profile: quality.decision.profile,
            tier: quality.decision.tier,
        };
        let route = self.router.update(receiver, decision);
        Ok(ReceiverCohortObservation { quality, route })
    }

    pub fn remove(&mut self, receiver: ReceiverId) -> bool {
        let removed = self.receivers.remove(&receiver).is_some();
        let _ = self.router.remove(receiver);
        removed
    }

    #[must_use]
    pub fn route(&self, receiver: ReceiverId) -> Option<CohortKey> {
        self.router.route(receiver)
    }

    #[must_use]
    pub fn members(&self, cohort: CohortKey) -> Vec<ReceiverId> {
        self.router.members(cohort)
    }

    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.receivers.len()
    }

    #[must_use]
    pub fn routed_count(&self) -> usize {
        self.router.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NetworkMetrics;
    use crate::adaptation::QualityTier;
    use crate::cohort::CohortKind;
    use crate::quality_sample::{
        RECEIVER_QUALITY_SAMPLE_VERSION, ReceiverCapabilityHealth, ReceiverQualitySample,
    };
    use crate::receiver_quality::ReceiverQualitySampleStatus;

    fn sample(receiver_sequence: u64, observed_at_us: u64) -> ReceiverQualitySample {
        ReceiverQualitySample {
            schema_version: RECEIVER_QUALITY_SAMPLE_VERSION,
            sample_sequence: receiver_sequence,
            observed_at_us,
            network: NetworkMetrics {
                rtt_ms: 10.0,
                packet_loss: 0.001,
                jitter_ms: 1.0,
                decode_fps: 30.0,
                queue_delay_ms: 3.0,
                estimated_mbps: 100.0,
                multicast_viable: true,
                wireless: false,
            },
            reordered_packet_rate: 0.001,
            decode_delay_ms: 4.0,
            render_delay_ms: 3.0,
            queue_depth: 1,
            queue_drop_rate: 0.0,
            capability: ReceiverCapabilityHealth {
                hardware_decode_available: true,
                profile_supported: true,
                decoder_healthy: true,
                renderer_healthy: true,
            },
        }
    }

    fn planner(max_receivers: usize) -> ReceiverCohortPlanner {
        ReceiverCohortPlanner::new(
            StreamKind::TeacherPresentation,
            AdaptationPolicy::default(),
            HysteresisConfig {
                degrade_samples: 2,
                recover_samples: 3,
                transport_samples: 3,
            },
            ReceiverQualityPolicy::default(),
            ReceiverCohortPlannerConfig { max_receivers },
        )
        .unwrap()
    }

    #[test]
    fn weak_receiver_moves_tier_without_downgrading_healthy_peers() {
        let mut planner = planner(3);
        for id in 1..=3 {
            planner
                .register(ReceiverId(id), MediaTransport::UdpMulticast)
                .unwrap();
            planner
                .observe(ReceiverId(id), sample(1, 1_000_000), 1_000_000)
                .unwrap();
        }

        let high = CohortKey {
            kind: CohortKind::WiredMulticast,
            tier: QualityTier::High,
        };
        assert_eq!(
            planner.members(high),
            vec![ReceiverId(1), ReceiverId(2), ReceiverId(3)]
        );

        let mut weak = sample(2, 1_100_000);
        weak.queue_drop_rate = 0.08;
        assert_eq!(
            planner
                .observe(ReceiverId(3), weak, 1_100_000)
                .unwrap()
                .quality
                .decision
                .tier,
            QualityTier::High
        );

        weak.sample_sequence = 3;
        weak.observed_at_us = 1_200_000;
        let degraded = planner.observe(ReceiverId(3), weak, 1_200_000).unwrap();
        assert_eq!(degraded.quality.decision.tier, QualityTier::Emergency);
        assert_eq!(planner.members(high), vec![ReceiverId(1), ReceiverId(2)]);
        assert_eq!(planner.route(ReceiverId(1)), Some(high));
        assert_eq!(planner.route(ReceiverId(2)), Some(high));
        assert_eq!(
            planner.route(ReceiverId(3)),
            Some(CohortKey {
                kind: CohortKind::WiredMulticast,
                tier: QualityTier::Emergency,
            })
        );
    }

    #[test]
    fn receiver_sequences_and_hysteresis_are_independent() {
        let mut planner = planner(2);
        planner
            .register(ReceiverId(10), MediaTransport::UdpUnicast)
            .unwrap();
        planner
            .register(ReceiverId(11), MediaTransport::UdpUnicast)
            .unwrap();

        let first = planner
            .observe(ReceiverId(10), sample(1, 1_000_000), 1_000_000)
            .unwrap();
        let second = planner
            .observe(ReceiverId(11), sample(1, 1_000_000), 1_000_000)
            .unwrap();
        assert_eq!(first.quality.status, ReceiverQualitySampleStatus::Accepted);
        assert_eq!(second.quality.status, ReceiverQualitySampleStatus::Accepted);

        let replay = planner
            .observe(ReceiverId(10), sample(1, 1_100_000), 1_100_000)
            .unwrap();
        assert_eq!(
            replay.quality.status,
            ReceiverQualitySampleStatus::NonMonotonicSequence
        );

        let healthy_other = planner
            .observe(ReceiverId(11), sample(2, 1_100_000), 1_100_000)
            .unwrap();
        assert_eq!(
            healthy_other.quality.status,
            ReceiverQualitySampleStatus::Accepted
        );
        assert_eq!(healthy_other.quality.decision.tier, QualityTier::High);
    }

    #[test]
    fn transport_is_caller_owned_in_phase_10c() {
        let mut planner = planner(2);
        planner
            .register(ReceiverId(20), MediaTransport::UdpMulticast)
            .unwrap();
        planner
            .register(ReceiverId(21), MediaTransport::QuicDatagram)
            .unwrap();

        planner
            .observe(ReceiverId(20), sample(1, 1_000_000), 1_000_000)
            .unwrap();
        planner
            .observe(ReceiverId(21), sample(1, 1_000_000), 1_000_000)
            .unwrap();

        assert_eq!(
            planner.route(ReceiverId(20)),
            Some(CohortKey {
                kind: CohortKind::WiredMulticast,
                tier: QualityTier::High,
            })
        );
        assert_eq!(
            planner.route(ReceiverId(21)),
            Some(CohortKey {
                kind: CohortKind::DirectUnicast,
                tier: QualityTier::High,
            })
        );
    }

    #[test]
    fn planner_capacity_and_unknown_receiver_fail_closed() {
        let mut planner = planner(1);
        planner
            .register(ReceiverId(1), MediaTransport::UdpUnicast)
            .unwrap();
        assert_eq!(
            planner.register(ReceiverId(2), MediaTransport::UdpUnicast),
            Err(ReceiverCohortPlannerError::ReceiverLimitReached)
        );
        assert_eq!(
            planner.observe(ReceiverId(2), sample(1, 1_000_000), 1_000_000),
            Err(ReceiverCohortPlannerError::UnknownReceiver)
        );
        assert_eq!(planner.receiver_count(), 1);
        assert_eq!(planner.routed_count(), 0);
    }

    #[test]
    fn remove_clears_controller_and_route_state() {
        let mut planner = planner(1);
        let receiver = ReceiverId(7);
        planner
            .register(receiver, MediaTransport::UdpUnicast)
            .unwrap();
        planner
            .observe(receiver, sample(1, 1_000_000), 1_000_000)
            .unwrap();
        assert!(planner.route(receiver).is_some());

        assert!(planner.remove(receiver));
        assert_eq!(planner.route(receiver), None);
        assert_eq!(planner.receiver_count(), 0);
        assert_eq!(planner.routed_count(), 0);
    }
}
