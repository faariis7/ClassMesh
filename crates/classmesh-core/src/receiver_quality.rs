use crate::StreamKind;
use crate::adaptation::{
    AdaptationPolicy, FocusedProfileController, FocusedProfileDecision, HysteresisConfig,
    QualityTier,
};
use crate::quality_sample::{ReceiverQualitySample, ReceiverQualitySampleError};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReceiverQualityPolicy {
    pub max_sample_age_us: u64,
    pub degraded_reordered_packet_rate: f32,
    pub severe_reordered_packet_rate: f32,
    pub degraded_decode_delay_ms: f32,
    pub severe_decode_delay_ms: f32,
    pub degraded_render_delay_ms: f32,
    pub severe_render_delay_ms: f32,
    pub degraded_queue_depth: u32,
    pub severe_queue_depth: u32,
    pub degraded_queue_drop_rate: f32,
    pub severe_queue_drop_rate: f32,
}

impl Default for ReceiverQualityPolicy {
    fn default() -> Self {
        Self {
            max_sample_age_us: 2_000_000,
            degraded_reordered_packet_rate: 0.01,
            severe_reordered_packet_rate: 0.05,
            degraded_decode_delay_ms: 40.0,
            severe_decode_delay_ms: 120.0,
            degraded_render_delay_ms: 40.0,
            severe_render_delay_ms: 120.0,
            degraded_queue_depth: 4,
            severe_queue_depth: 12,
            degraded_queue_drop_rate: 0.01,
            severe_queue_drop_rate: 0.05,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverQualityPolicyError {
    InvalidSampleAge,
    InvalidThresholds,
}

impl ReceiverQualityPolicy {
    pub fn validate(self) -> Result<Self, ReceiverQualityPolicyError> {
        if self.max_sample_age_us == 0 {
            return Err(ReceiverQualityPolicyError::InvalidSampleAge);
        }

        let valid_rates =
            valid_rate_thresholds(
                self.degraded_reordered_packet_rate,
                self.severe_reordered_packet_rate,
            ) && valid_rate_thresholds(self.degraded_queue_drop_rate, self.severe_queue_drop_rate);
        let valid_delays =
            valid_delay_thresholds(self.degraded_decode_delay_ms, self.severe_decode_delay_ms)
                && valid_delay_thresholds(
                    self.degraded_render_delay_ms,
                    self.severe_render_delay_ms,
                );
        let valid_depths = self.degraded_queue_depth <= self.severe_queue_depth;

        if !valid_rates || !valid_delays || !valid_depths {
            return Err(ReceiverQualityPolicyError::InvalidThresholds);
        }

        Ok(self)
    }

    fn health_tier_ceiling(self, sample: ReceiverQualitySample) -> QualityTier {
        let capability = sample.capability;
        if !capability.profile_supported
            || !capability.decoder_healthy
            || !capability.renderer_healthy
        {
            return QualityTier::Emergency;
        }

        if sample.reordered_packet_rate >= self.severe_reordered_packet_rate
            || sample.decode_delay_ms >= self.severe_decode_delay_ms
            || sample.render_delay_ms >= self.severe_render_delay_ms
            || sample.queue_depth >= self.severe_queue_depth
            || sample.queue_drop_rate >= self.severe_queue_drop_rate
        {
            return QualityTier::Emergency;
        }

        if sample.reordered_packet_rate >= self.degraded_reordered_packet_rate
            || sample.decode_delay_ms >= self.degraded_decode_delay_ms
            || sample.render_delay_ms >= self.degraded_render_delay_ms
            || sample.queue_depth >= self.degraded_queue_depth
            || sample.queue_drop_rate >= self.degraded_queue_drop_rate
        {
            return QualityTier::Low;
        }

        if !capability.hardware_decode_available {
            return QualityTier::Medium;
        }

        QualityTier::High
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverQualitySampleStatus {
    Accepted,
    InvalidSample(ReceiverQualitySampleError),
    FutureObservation,
    StaleAge,
    NonMonotonicSequence,
    NonMonotonicObservationTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverQualityObservation {
    pub decision: FocusedProfileDecision,
    pub status: ReceiverQualitySampleStatus,
}

#[derive(Debug)]
pub struct ReceiverQualityController {
    adaptation_policy: AdaptationPolicy,
    quality_policy: ReceiverQualityPolicy,
    profile_controller: FocusedProfileController,
    last_sequence: Option<u64>,
    last_observed_at_us: Option<u64>,
}

impl ReceiverQualityController {
    pub fn new(
        kind: StreamKind,
        adaptation_policy: AdaptationPolicy,
        hysteresis: HysteresisConfig,
        quality_policy: ReceiverQualityPolicy,
    ) -> Result<Self, ReceiverQualityPolicyError> {
        let quality_policy = quality_policy.validate()?;
        Ok(Self {
            adaptation_policy,
            quality_policy,
            profile_controller: FocusedProfileController::new(kind, adaptation_policy, hysteresis),
            last_sequence: None,
            last_observed_at_us: None,
        })
    }

    #[must_use]
    pub const fn current(&self) -> Option<FocusedProfileDecision> {
        self.profile_controller.current()
    }

    #[must_use]
    pub const fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }

    pub fn observe(
        &mut self,
        sample: ReceiverQualitySample,
        now_us: u64,
    ) -> ReceiverQualityObservation {
        let status = self.validate_observation(sample, now_us);
        let candidate = if status == ReceiverQualitySampleStatus::Accepted {
            let network_tier = self.adaptation_policy.quality_tier(sample.network);
            let health_ceiling = self.quality_policy.health_tier_ceiling(sample);
            network_tier.min(health_ceiling)
        } else {
            QualityTier::Emergency
        };

        if status == ReceiverQualitySampleStatus::Accepted {
            self.last_sequence = Some(sample.sample_sequence);
            self.last_observed_at_us = Some(sample.observed_at_us);
        }

        ReceiverQualityObservation {
            decision: self.profile_controller.observe_tier(candidate),
            status,
        }
    }

    fn validate_observation(
        &self,
        sample: ReceiverQualitySample,
        now_us: u64,
    ) -> ReceiverQualitySampleStatus {
        if let Err(error) = sample.validate() {
            return ReceiverQualitySampleStatus::InvalidSample(error);
        }
        if sample.observed_at_us > now_us {
            return ReceiverQualitySampleStatus::FutureObservation;
        }
        if now_us.saturating_sub(sample.observed_at_us) > self.quality_policy.max_sample_age_us {
            return ReceiverQualitySampleStatus::StaleAge;
        }
        if self
            .last_sequence
            .is_some_and(|last| sample.sample_sequence <= last)
        {
            return ReceiverQualitySampleStatus::NonMonotonicSequence;
        }
        if self
            .last_observed_at_us
            .is_some_and(|last| sample.observed_at_us < last)
        {
            return ReceiverQualitySampleStatus::NonMonotonicObservationTime;
        }
        ReceiverQualitySampleStatus::Accepted
    }
}

fn valid_rate_thresholds(degraded: f32, severe: f32) -> bool {
    degraded.is_finite()
        && severe.is_finite()
        && (0.0..=1.0).contains(&degraded)
        && (0.0..=1.0).contains(&severe)
        && degraded <= severe
}

fn valid_delay_thresholds(degraded: f32, severe: f32) -> bool {
    degraded.is_finite() && severe.is_finite() && degraded >= 0.0 && degraded <= severe
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NetworkMetrics;
    use crate::quality_sample::{RECEIVER_QUALITY_SAMPLE_VERSION, ReceiverCapabilityHealth};

    fn healthy_sample(sequence: u64, observed_at_us: u64) -> ReceiverQualitySample {
        ReceiverQualitySample {
            schema_version: RECEIVER_QUALITY_SAMPLE_VERSION,
            sample_sequence: sequence,
            observed_at_us,
            network: NetworkMetrics {
                rtt_ms: 12.0,
                packet_loss: 0.002,
                jitter_ms: 1.0,
                decode_fps: 30.0,
                queue_delay_ms: 4.0,
                estimated_mbps: 80.0,
                multicast_viable: false,
                wireless: false,
            },
            reordered_packet_rate: 0.001,
            decode_delay_ms: 5.0,
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

    fn controller() -> ReceiverQualityController {
        ReceiverQualityController::new(
            StreamKind::Interactive,
            AdaptationPolicy::default(),
            HysteresisConfig {
                degrade_samples: 2,
                recover_samples: 3,
                transport_samples: 1,
            },
            ReceiverQualityPolicy::default(),
        )
        .unwrap()
    }

    #[test]
    fn healthy_sample_starts_at_existing_high_profile() {
        let mut controller = controller();
        let observed = controller.observe(healthy_sample(1, 1_000_000), 1_000_000);
        assert_eq!(observed.status, ReceiverQualitySampleStatus::Accepted);
        assert_eq!(observed.decision.tier, QualityTier::High);
        assert_eq!(controller.last_sequence(), Some(1));
    }

    #[test]
    fn extended_queue_health_degrades_through_existing_hysteresis() {
        let mut controller = controller();
        assert_eq!(
            controller
                .observe(healthy_sample(1, 1_000_000), 1_000_000)
                .decision
                .tier,
            QualityTier::High
        );

        let mut severe = healthy_sample(2, 1_100_000);
        severe.queue_drop_rate = 0.08;
        assert_eq!(
            controller.observe(severe, 1_100_000).decision.tier,
            QualityTier::High
        );

        severe.sample_sequence = 3;
        severe.observed_at_us = 1_200_000;
        let degraded = controller.observe(severe, 1_200_000);
        assert_eq!(degraded.status, ReceiverQualitySampleStatus::Accepted);
        assert_eq!(degraded.decision.tier, QualityTier::Emergency);
        assert!(degraded.decision.changed);
    }

    #[test]
    fn missing_hardware_decode_caps_healthy_receiver_at_medium() {
        let mut controller = controller();
        let mut sample = healthy_sample(1, 1_000_000);
        sample.capability.hardware_decode_available = false;
        let observed = controller.observe(sample, 1_000_000);
        assert_eq!(observed.status, ReceiverQualitySampleStatus::Accepted);
        assert_eq!(observed.decision.tier, QualityTier::Medium);
    }

    #[test]
    fn stale_samples_fail_closed_and_cannot_recover_quality() {
        let mut controller = controller();

        let mut severe = healthy_sample(1, 1_000_000);
        severe.capability.decoder_healthy = false;
        assert_eq!(
            controller.observe(severe, 1_000_000).decision.tier,
            QualityTier::Emergency
        );

        for sequence in 2..=4 {
            let stale = healthy_sample(sequence, 1_100_000);
            let observed = controller.observe(stale, 4_000_001);
            assert_eq!(observed.status, ReceiverQualitySampleStatus::StaleAge);
            assert_eq!(observed.decision.tier, QualityTier::Emergency);
        }
        assert_eq!(controller.last_sequence(), Some(1));
    }

    #[test]
    fn only_accepted_fresh_samples_can_recover_after_hysteresis() {
        let mut controller = controller();

        let mut severe = healthy_sample(1, 1_000_000);
        severe.capability.renderer_healthy = false;
        assert_eq!(
            controller.observe(severe, 1_000_000).decision.tier,
            QualityTier::Emergency
        );

        for sequence in 2..=3 {
            let observed = controller.observe(
                healthy_sample(sequence, 1_000_000 + sequence * 100_000),
                1_500_000,
            );
            assert_eq!(observed.status, ReceiverQualitySampleStatus::Accepted);
            assert_eq!(observed.decision.tier, QualityTier::Emergency);
        }

        let recovered = controller.observe(healthy_sample(4, 1_400_000), 1_500_000);
        assert_eq!(recovered.status, ReceiverQualitySampleStatus::Accepted);
        assert_eq!(recovered.decision.tier, QualityTier::High);
        assert!(recovered.decision.changed);
    }

    #[test]
    fn replayed_or_future_sample_is_fail_closed_without_advancing_sequence() {
        let mut controller = controller();
        let first = controller.observe(healthy_sample(1, 1_000_000), 1_000_000);
        assert_eq!(first.decision.tier, QualityTier::High);

        let replay = controller.observe(healthy_sample(1, 1_100_000), 1_100_000);
        assert_eq!(
            replay.status,
            ReceiverQualitySampleStatus::NonMonotonicSequence
        );
        assert_eq!(controller.last_sequence(), Some(1));

        let future = controller.observe(healthy_sample(2, 2_000_000), 1_900_000);
        assert_eq!(
            future.status,
            ReceiverQualitySampleStatus::FutureObservation
        );
        assert_eq!(controller.last_sequence(), Some(1));
    }

    #[test]
    fn invalid_policy_threshold_order_is_rejected() {
        assert_eq!(
            ReceiverQualityPolicy {
                degraded_queue_drop_rate: 0.2,
                severe_queue_drop_rate: 0.1,
                ..ReceiverQualityPolicy::default()
            }
            .validate(),
            Err(ReceiverQualityPolicyError::InvalidThresholds)
        );
    }
}
