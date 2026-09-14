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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QualityTier {
    High,
    Medium,
    Low,
    Emergency,
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

        if kind == StreamKind::TeacherPresentation
            && !metrics.wireless
            && metrics.multicast_viable
        {
            return MediaTransport::UdpMulticast;
        }

        if metrics.wireless {
            return MediaTransport::QuicDatagram;
        }

        MediaTransport::UdpUnicast
    }
}

#[must_use]
pub const fn profile_for(kind: StreamKind, tier: QualityTier) -> StreamProfile {
    match (kind, tier) {
        (StreamKind::Monitoring, QualityTier::High) => StreamProfile::new(640, 360, 5, 700),
        (StreamKind::Monitoring, QualityTier::Medium) => StreamProfile::new(480, 270, 4, 450),
        (StreamKind::Monitoring, QualityTier::Low) => StreamProfile::new(320, 180, 3, 250),
        (StreamKind::Monitoring, QualityTier::Emergency) => StreamProfile::new(320, 180, 1, 120),
        (_, QualityTier::High) => StreamProfile::new(1920, 1080, 30, 5_000),
        (_, QualityTier::Medium) => StreamProfile::new(1280, 720, 30, 2_500),
        (_, QualityTier::Low) => StreamProfile::new(1280, 720, 20, 1_500),
        (_, QualityTier::Emergency) => StreamProfile::new(854, 480, 10, 700),
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
        let decision = AdaptationPolicy::default().decide(
            StreamKind::TeacherPresentation,
            healthy(false, true),
        );
        assert_eq!(decision.transport, MediaTransport::UdpMulticast);
        assert_eq!(decision.tier, QualityTier::High);
    }

    #[test]
    fn wireless_presentation_avoids_ip_multicast() {
        let decision = AdaptationPolicy::default().decide(
            StreamKind::TeacherPresentation,
            healthy(true, true),
        );
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
}
