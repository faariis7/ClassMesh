use crate::{MediaTransport, NetworkMetrics, StreamKind};

pub const MAX_STREAM_WIDTH: u16 = 1920;
pub const MAX_STREAM_HEIGHT: u16 = 1080;
pub const MAX_STREAM_FPS: u8 = 60;
pub const MAX_STREAM_BITRATE_KBPS: u32 = 50_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamProfileError {
    InvalidGeometry,
    InvalidFps,
    InvalidBitrate,
}

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

    pub const fn validate(self) -> Result<Self, StreamProfileError> {
        if self.width < 2
            || self.height < 2
            || self.width > MAX_STREAM_WIDTH
            || self.height > MAX_STREAM_HEIGHT
            || self.width % 2 != 0
            || self.height % 2 != 0
        {
            return Err(StreamProfileError::InvalidGeometry);
        }
        if self.fps == 0 || self.fps > MAX_STREAM_FPS {
            return Err(StreamProfileError::InvalidFps);
        }
        if self.bitrate_kbps == 0 || self.bitrate_kbps > MAX_STREAM_BITRATE_KBPS {
            return Err(StreamProfileError::InvalidBitrate);
        }
        Ok(self)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FocusedProfileDecision {
    pub profile: StreamProfile,
    pub tier: QualityTier,
    pub changed: bool,
}

/// Profile-only adaptation for a focused stream.
///
/// This deliberately does not choose or change media transport. Phase 4 physical
/// qualification still owns the UDP-vs-QUIC-Datagram default decision.
#[derive(Debug)]
pub struct FocusedProfileController {
    kind: StreamKind,
    policy: AdaptationPolicy,
    hysteresis: HysteresisConfig,
    current_tier: Option<QualityTier>,
    pending_tier: Option<QualityTier>,
    pending_tier_samples: u8,
}

impl FocusedProfileController {
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
            current_tier: None,
            pending_tier: None,
            pending_tier_samples: 0,
        }
    }

    #[must_use]
    pub const fn with_initial_tier(
        kind: StreamKind,
        policy: AdaptationPolicy,
        hysteresis: HysteresisConfig,
        initial_tier: QualityTier,
    ) -> Self {
        Self {
            kind,
            policy,
            hysteresis,
            current_tier: Some(initial_tier),
            pending_tier: None,
            pending_tier_samples: 0,
        }
    }

    #[must_use]
    pub const fn current(&self) -> Option<FocusedProfileDecision> {
        match self.current_tier {
            Some(tier) => Some(FocusedProfileDecision {
                profile: profile_for(self.kind, tier),
                tier,
                changed: false,
            }),
            None => None,
        }
    }

    pub fn observe(&mut self, metrics: NetworkMetrics) -> FocusedProfileDecision {
        let candidate = self.policy.quality_tier(metrics);
        let Some(current) = self.current_tier else {
            self.current_tier = Some(candidate);
            return FocusedProfileDecision {
                profile: profile_for(self.kind, candidate),
                tier: candidate,
                changed: true,
            };
        };

        let tier = apply_tier_hysteresis(
            current,
            candidate,
            &mut self.pending_tier,
            &mut self.pending_tier_samples,
            self.hysteresis,
        );
        let changed = tier != current;
        self.current_tier = Some(tier);

        FocusedProfileDecision {
            profile: profile_for(self.kind, tier),
            tier,
            changed,
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
        apply_tier_hysteresis(
            current,
            candidate,
            &mut self.pending_tier,
            &mut self.pending_tier_samples,
            self.hysteresis,
        )
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

fn apply_tier_hysteresis(
    current: QualityTier,
    candidate: QualityTier,
    pending_tier: &mut Option<QualityTier>,
    pending_tier_samples: &mut u8,
    hysteresis: HysteresisConfig,
) -> QualityTier {
    if candidate == current {
        *pending_tier = None;
        *pending_tier_samples = 0;
        return current;
    }

    if *pending_tier == Some(candidate) {
        *pending_tier_samples = (*pending_tier_samples).saturating_add(1);
    } else {
        *pending_tier = Some(candidate);
        *pending_tier_samples = 1;
    }

    let required = if candidate < current {
        hysteresis.degrade_samples.max(1)
    } else {
        hysteresis.recover_samples.max(1)
    };
    if *pending_tier_samples >= required {
        *pending_tier = None;
        *pending_tier_samples = 0;
        candidate
    } else {
        current
    }
}

#[must_use]
pub const fn profile_for(kind: StreamKind, tier: QualityTier) -> StreamProfile {
    match (kind, tier) {
        (StreamKind::Monitoring, QualityTier::High) => StreamProfile::new(640, 360, 5, 700),
        (StreamKind::Monitoring, QualityTier::Medium) => StreamProfile::new(480, 270, 4, 450),
        (StreamKind::Monitoring, QualityTier::Low) => StreamProfile::new(320, 180, 3, 250),
        (StreamKind::Monitoring, QualityTier::Emergency) => StreamProfile::new(320, 180, 1, 120),
        (StreamKind::Interactive, QualityTier::High) => StreamProfile::new(1920, 1080, 30, 5_000),
        (StreamKind::Interactive, QualityTier::Medium) => StreamProfile::new(1280, 720, 30, 2_500),
        (StreamKind::Interactive, QualityTier::Low) => StreamProfile::new(960, 540, 30, 1_500),
        (StreamKind::Interactive, QualityTier::Emergency) => StreamProfile::new(640, 360, 20, 700),
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
    fn stream_profile_contract_rejects_invalid_bounds() {
        assert_eq!(
            StreamProfile::new(1920, 1080, 60, 50_000).validate(),
            Ok(StreamProfile::new(1920, 1080, 60, 50_000))
        );
        assert_eq!(
            StreamProfile::new(1919, 1080, 30, 5_000).validate(),
            Err(StreamProfileError::InvalidGeometry)
        );
        assert_eq!(
            StreamProfile::new(1920, 1080, 0, 5_000).validate(),
            Err(StreamProfileError::InvalidFps)
        );
        assert_eq!(
            StreamProfile::new(1920, 1080, 30, 50_001).validate(),
            Err(StreamProfileError::InvalidBitrate)
        );
    }

    #[test]
    fn every_builtin_adaptation_profile_satisfies_stream_contract() {
        for kind in [
            StreamKind::Monitoring,
            StreamKind::Interactive,
            StreamKind::TeacherPresentation,
        ] {
            for tier in [
                QualityTier::Emergency,
                QualityTier::Low,
                QualityTier::Medium,
                QualityTier::High,
            ] {
                assert!(profile_for(kind, tier).validate().is_ok());
            }
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
        assert_eq!(decision.profile.fps, 20);
    }

    #[test]
    fn teacher_presentation_emergency_profile_stays_conservative() {
        let profile = profile_for(StreamKind::TeacherPresentation, QualityTier::Emergency);
        assert_eq!(profile.fps, 10);
        assert_eq!((profile.width, profile.height), (854, 480));
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
    fn focused_interactive_profile_preserves_motion_before_resolution() {
        let medium = profile_for(StreamKind::Interactive, QualityTier::Medium);
        let low = profile_for(StreamKind::Interactive, QualityTier::Low);
        let emergency = profile_for(StreamKind::Interactive, QualityTier::Emergency);

        assert_eq!(medium.fps, 30);
        assert_eq!(low.fps, 30);
        assert_eq!((low.width, low.height), (960, 540));
        assert_eq!(emergency.fps, 20);
        assert_eq!((emergency.width, emergency.height), (640, 360));
    }

    #[test]
    fn focused_profile_controller_can_start_from_existing_stream_tier() {
        let mut controller = FocusedProfileController::with_initial_tier(
            StreamKind::Interactive,
            AdaptationPolicy::default(),
            HysteresisConfig {
                degrade_samples: 2,
                recover_samples: 3,
                transport_samples: 1,
            },
            QualityTier::High,
        );
        let mut bad = healthy(false, false);
        bad.packet_loss = 0.12;

        let pending = controller.observe(bad);
        assert_eq!(pending.tier, QualityTier::High);
        assert!(!pending.changed);

        let degraded = controller.observe(bad);
        assert_eq!(degraded.tier, QualityTier::Emergency);
        assert!(degraded.changed);
        assert_eq!(degraded.profile.fps, 20);
    }

    #[test]
    fn focused_profile_controller_does_not_expose_transport_choice() {
        let mut controller = FocusedProfileController::new(
            StreamKind::Interactive,
            AdaptationPolicy::default(),
            HysteresisConfig {
                degrade_samples: 2,
                recover_samples: 3,
                transport_samples: 1,
            },
        );

        let first = controller.observe(healthy(true, false));
        assert_eq!(first.tier, QualityTier::High);
        assert!(first.changed);

        let mut bad = healthy(false, true);
        bad.packet_loss = 0.12;
        let pending = controller.observe(bad);
        assert_eq!(pending.tier, QualityTier::High);
        assert!(!pending.changed);

        let degraded = controller.observe(bad);
        assert_eq!(degraded.tier, QualityTier::Emergency);
        assert!(degraded.changed);
        assert_eq!(degraded.profile.fps, 20);
    }

    #[test]
    fn focused_profile_recovery_uses_existing_hysteresis() {
        let mut controller = FocusedProfileController::new(
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

        assert!(!controller.observe(healthy(false, false)).changed);
        assert!(!controller.observe(healthy(false, false)).changed);
        let recovered = controller.observe(healthy(false, false));
        assert!(recovered.changed);
        assert_eq!(recovered.tier, QualityTier::High);
        assert_eq!(recovered.profile.fps, 30);
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
