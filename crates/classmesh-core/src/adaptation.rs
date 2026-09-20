use crate::{MediaTransport, NetworkMetrics, StreamKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamProfile {
    pub width: u16,
    pub height: u16,
    pub fps: u8,
    pub bitrate_kbps: u32,
}

impl StreamProfile {
    #[must_use]
    pub const fn new(width: u16, height: u16, fps: u8, bitrate_kbps: u32) -> Self {
        Self {
            width,
            height,
            fps,
            bitrate_kbps,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QualityTier {
    Emergency,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamDecision {
    pub transport: MediaTransport,
    pub profile: StreamProfile,
    pub tier: QualityTier,
}

#[derive(Debug, Clone, Copy)]
pub struct AdaptationPolicy {
    /// Loss below this level is considered healthy enough for the high tier.
    pub healthy_loss: f32,
    /// Loss at or above this level forces emergency quality.
    pub severe_loss: f32,
    pub healthy_rtt_ms: f32,
    pub severe_rtt_ms: f32,
    pub max_queue_delay_ms: f32,
}

impl Default for AdaptationPolicy {
    fn default() -> Self {
        Self {
            healthy_loss: 0.01,
            severe_loss: 0.08,
            healthy_rtt_ms: 40.0,
            severe_rtt_ms: 180.0,
            max_queue_delay_ms: 120.0,
        }
    }
}

impl AdaptationPolicy {
    #[must_use]
    pub fn decide(self, kind: StreamKind, metrics: NetworkMetrics) -> StreamDecision {
        let tier = self.quality_tier(metrics);
        self.decision_for_tier(kind, metrics, tier)
    }

    #[must_use]
    pub fn decision_for_tier(
        self,
        kind: StreamKind,
        metrics: NetworkMetrics,
        tier: QualityTier,
    ) -> StreamDecision {
        let transport = self.transport(kind, metrics, tier);
        StreamDecision {
            transport,
            profile: profile_for(kind, tier),
            tier,
        }
    }

    fn quality_tier(self, metrics: NetworkMetrics) -> QualityTier {
        if !metrics.is_valid()
            || metrics.packet_loss >= self.severe_loss
            || metrics.rtt_ms >= self.severe_rtt_ms
            || metrics.queue_delay_ms >= self.max_queue_delay_ms
        {
            return QualityTier::Emergency;
        }

        if metrics.packet_loss <= self.healthy_loss
            && metrics.rtt_ms <= self.healthy_rtt_ms
            && metrics.queue_delay_ms <= 30.0
        {
            return QualityTier::High;
        }

        if metrics.packet_loss < 0.04 && metrics.rtt_ms < 100.0 {
            QualityTier::Medium
        } else {
            QualityTier::Low
        }
    }

    fn transport(
        self,
        kind: StreamKind,
        metrics: NetworkMetrics,
        tier: QualityTier,
    ) -> MediaTransport {
        if tier == QualityTier::Emergency {
            return MediaTransport::ReliableFallback;
        }

        if kind == StreamKind::TeacherPresentation && !metrics.wireless && metrics.multicast_viable
        {
            return MediaTransport::UdpMulticast;
        }

        if metrics.wireless {
            return MediaTransport::QuicDatagram;
        }

        MediaTransport::UdpUnicast
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HysteresisConfig {
    /// Degrade quickly because queue growth/loss hurts real-time latency.
    pub degrade_samples: u8,
    /// Recover more slowly to avoid oscillating quality after a short good burst.
    pub recover_samples: u8,
    /// Require repeated topology observations before moving between multicast/unicast paths.
    pub transport_samples: u8,
}

impl Default for HysteresisConfig {
    fn default() -> Self {
        Self {
            degrade_samples: 2,
            recover_samples: 5,
            transport_samples: 3,
        }
    }
}

/// Stateful adaptation controller that prevents bitrate/profile/transport flapping.
#[derive(Debug)]
pub struct AdaptiveController {
    kind: StreamKind,
    policy: AdaptationPolicy,
    hysteresis: HysteresisConfig,
    current: Option<StreamDecision>,
    pending_tier: Option<QualityTier>,
    pending_tier_samples: u8,
    pending_transport: Option<MediaTransport>,
    pending_transport_samples: u8,
}

impl AdaptiveController {
    #[must_use]
    pub const fn new(
        kind: StreamKind,
        policy: AdaptationPolicy,
        hysteresis: HysteresisConfig,
    ) -> Self {
        Self {
            kind,
            policy,
            hysteresis,
            current: None,
            pending_tier: None,
            pending_tier_samples: 0,
            pending_transport: None,
            pending_transport_samples: 0,
        }
    }

    #[must_use]
    pub const fn current(&self) -> Option<StreamDecision> {
        self.current
    }

    /// Observes one metrics sample and returns the active decision after hysteresis is applied.
    pub fn observe(&mut self, metrics: NetworkMetrics) -> StreamDecision {
        let candidate = self.policy.decide(self.kind, metrics);
        let Some(current) = self.current else {
            self.current = Some(candidate);
            return candidate;
        };

        let tier = self.apply_tier_hysteresis(current.tier, candidate.tier);
        let base = self.policy.decision_for_tier(self.kind, metrics, tier);
        let transport = self.apply_transport_hysteresis(current.transport, base.transport);
        let next = StreamDecision {
            tier,
            profile: profile_for(self.kind, tier),
            transport,
        };
        self.current = Some(next);
        next
    }

    fn apply_tier_hysteresis(
        &mut self,
        current: QualityTier,
        candidate: QualityTier,
    ) -> QualityTier {
        if candidate == current {
            self.pending_tier = None;
            self.pending_tier_samples = 0;
            return current;
        }

        if self.pending_tier == Some(candidate) {
            self.pending_tier_samples = self.pending_tier_samples.saturating_add(1);
        } else {
            self.pending_tier = Some(candidate);
            self.pending_tier_samples = 1;
        }

        let required = if candidate < current {
            self.hysteresis.degrade_samples.max(1)
        } else {
            self.hysteresis.recover_samples.max(1)
        };
        if self.pending_tier_samples >= required {
            self.pending_tier = None;
            self.pending_tier_samples = 0;
            candidate
        } else {
            current
        }
    }

    fn apply_transport_hysteresis(
        &mut self,
        current: MediaTransport,
        candidate: MediaTransport,
    ) -> MediaTransport {
        if candidate == current {
            self.pending_transport = None;
            self.pending_transport_samples = 0;
            return current;
        }

        // Emergency fallback follows the quality decision immediately once its tier hysteresis has
        // fired; waiting extra topology samples would only prolong an overloaded real-time path.
        if candidate == MediaTransport::ReliableFallback {
            self.pending_transport = None;
            self.pending_transport_samples = 0;
            return candidate;
        }

        if self.pending_transport == Some(candidate) {
            self.pending_transport_samples = self.pending_transport_samples.saturating_add(1);
        } else {
            self.pending_transport = Some(candidate);
            self.pending_transport_samples = 1;
        }

        if self.pending_transport_samples >= self.hysteresis.transport_samples.max(1) {
            self.pending_transport = None;
            self.pending_transport_samples = 0;
            candidate
        } else {
            current
        }
    }
}

#[must_use]
pub const fn profile_for(kind: StreamKind, tier: QualityTier) -> StreamProfile {
    match (kind, tier) {
        (StreamKind::Monitoring, QualityTier::High) => StreamProfile::new(640, 360, 5, 700),
        (StreamKind::Monitoring, QualityTier::Medium) => StreamProfile::new(480, 270, 4, 450),
        (StreamKind::Monitoring, QualityTier::Low) => StreamProfile::new(320, 180, 3, 250),
        (StreamKind::Monitoring, QualityTier::Emergency) => StreamProfile::new(320, 180, 1, 120),
        (StreamKind::Interactive, QualityTier::High) => {
            StreamProfile::new(1920, 1080, 30, 5_000)
        }
        (StreamKind::Interactive, QualityTier::Medium) => {
            StreamProfile::new(1280, 720, 30, 2_500)
        }
        (StreamKind::Interactive, QualityTier::Low) => {
            StreamProfile::new(960, 540, 30, 1_500)
        }
        (StreamKind::Interactive, QualityTier::Emergency) => {
            StreamProfile::new(640, 360, 20, 700)
        }
        (StreamKind::TeacherPresentation, QualityTier::High) => {
            StreamProfile::new(1920, 1080, 30, 5_000)
        }
        (StreamKind::TeacherPresentation, QualityTier::Medium) => {
            StreamProfile::new(1280, 720, 30, 2_500)
        }
        (StreamKind::TeacherPresentation, QualityTier::Low) => {
            StreamProfile::new(1280, 720, 20, 1_500)
        }
        (StreamKind::TeacherPresentation, QualityTier::Emergency) => {
            StreamProfile::new(854, 480, 10, 700)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy(wireless: bool, multicast_viable: bool) -> NetworkMetrics {
        NetworkMetrics {
            rtt_ms: 8.0,
            packet_loss: 0.001,
            jitter_ms: 1.0,
            decode_fps: 30.0,
            queue_delay_ms: 4.0,
            estimated_mbps: 100.0,
            multicast_viable,
            wireless,
        }
    }

    #[test]
    fn wired_presentation_prefers_multicast_when_probe_succeeds() {
        let decision = AdaptationPolicy::default()
            .decide(StreamKind::TeacherPresentation, healthy(false, true));
        assert_eq!(decision.transport, MediaTransport::UdpMulticast);
        assert_eq!(decision.tier, QualityTier::High);
    }

    #[test]
    fn wireless_presentation_avoids_ip_multicast() {
        let decision = AdaptationPolicy::default()
            .decide(StreamKind::TeacherPresentation, healthy(true, true));
        assert_eq!(decision.transport, MediaTransport::QuicDatagram);
    }

    #[test]
    fn severe_loss_degrades_without_marking_device_offline() {
        let mut metrics = healthy(false, true);
        metrics.packet_loss = 0.12;
        let decision = AdaptationPolicy::default().decide(StreamKind::Interactive, metrics);
        assert_eq!(decision.tier, QualityTier::Emergency);
        assert_eq!(decision.transport, MediaTransport::ReliableFallback);
        assert_eq!(decision.profile.fps, 10);
    }

    #[test]
    fn one_bad_sample_does_not_immediately_degrade() {
        let mut controller = AdaptiveController::new(
            StreamKind::TeacherPresentation,
            AdaptationPolicy::default(),
            HysteresisConfig::default(),
        );
        assert_eq!(
            controller.observe(healthy(false, true)).tier,
            QualityTier::High
        );
        let mut bad = healthy(false, true);
        bad.packet_loss = 0.12;
        assert_eq!(controller.observe(bad).tier, QualityTier::High);
        assert_eq!(controller.observe(bad).tier, QualityTier::Emergency);
    }

    #[test]
    fn recovery_requires_more_good_samples_than_degradation() {
        let mut controller = AdaptiveController::new(
            StreamKind::Interactive,
            AdaptationPolicy::default(),
            HysteresisConfig {
                degrade_samples: 1,
                recover_samples: 3,
                transport_samples: 1,
            },
        );
        let mut bad = healthy(false, false);
        bad.packet_loss = 0.12;
        assert_eq!(controller.observe(bad).tier, QualityTier::Emergency);
        assert_eq!(
            controller.observe(healthy(false, false)).tier,
            QualityTier::Emergency
        );
        assert_eq!(
            controller.observe(healthy(false, false)).tier,
            QualityTier::Emergency
        );
        assert_eq!(
            controller.observe(healthy(false, false)).tier,
            QualityTier::High
        );
    }

    #[test]
    fn interactive_profile_ladder_preserves_motion_before_resolution() {
        let medium = profile_for(StreamKind::Interactive, QualityTier::Medium);
        let low = profile_for(StreamKind::Interactive, QualityTier::Low);
        let emergency = profile_for(StreamKind::Interactive, QualityTier::Emergency);

        assert_eq!(medium.fps, 30);
        assert_eq!(low.fps, 30);
        assert_eq!(low.width, 960);
        assert_eq!(low.height, 540);
        assert_eq!(emergency.fps, 20);
        assert_eq!(emergency.width, 640);
        assert_eq!(emergency.height, 360);
    }

    #[test]
    fn presentation_profile_can_trade_frame_rate_before_interactive() {
        let presentation_low =
            profile_for(StreamKind::TeacherPresentation, QualityTier::Low);
        let interactive_low = profile_for(StreamKind::Interactive, QualityTier::Low);

        assert_eq!(presentation_low.fps, 20);
        assert_eq!(interactive_low.fps, 30);
        assert!(interactive_low.width < presentation_low.width);
        assert_eq!(interactive_low.bitrate_kbps, presentation_low.bitrate_kbps);
    }

    #[test]
    fn transport_change_waits_for_repeated_topology_observations() {
        let mut controller = AdaptiveController::new(
            StreamKind::TeacherPresentation,
            AdaptationPolicy::default(),
            HysteresisConfig {
                degrade_samples: 1,
                recover_samples: 1,
                transport_samples: 2,
            },
        );
        assert_eq!(
            controller.observe(healthy(false, true)).transport,
            MediaTransport::UdpMulticast
        );
        assert_eq!(
            controller.observe(healthy(true, false)).transport,
            MediaTransport::UdpMulticast
        );
        assert_eq!(
            controller.observe(healthy(true, false)).transport,
            MediaTransport::QuicDatagram
        );
    }
}
