#![forbid(unsafe_code)]

pub mod adaptation;
pub mod metrics;
pub mod queue;
pub mod recovery;

/// High-level media workloads supported by ClassMesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Monitoring,
    Interactive,
    TeacherPresentation,
}

/// Control connectivity is intentionally independent from media health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlState {
    Disconnected,
    Connecting,
    Authenticated,
    Recovering,
}

/// Media failures must be recoverable without automatically dropping control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaState {
    Idle,
    Starting,
    Streaming,
    Degraded,
    Recovering,
    Stopped,
}

/// Transport selected for a specific receiver or presentation cohort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaTransport {
    UdpMulticast,
    UdpUnicast,
    QuicDatagram,
    WebRtc,
    ReliableFallback,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NetworkMetrics {
    pub rtt_ms: f32,
    pub packet_loss: f32,
    pub jitter_ms: f32,
    pub decode_fps: f32,
    pub queue_delay_ms: f32,
    pub estimated_mbps: f32,
    pub multicast_viable: bool,
    pub wireless: bool,
}

impl NetworkMetrics {
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.rtt_ms >= 0.0
            && (0.0..=1.0).contains(&self.packet_loss)
            && self.jitter_ms >= 0.0
            && self.decode_fps >= 0.0
            && self.queue_delay_ms >= 0.0
            && self.estimated_mbps >= 0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_metrics_reject_invalid_loss() {
        let metrics = NetworkMetrics {
            rtt_ms: 10.0,
            packet_loss: 1.2,
            jitter_ms: 1.0,
            decode_fps: 30.0,
            queue_delay_ms: 0.0,
            estimated_mbps: 100.0,
            multicast_viable: true,
            wireless: false,
        };
        assert!(!metrics.is_valid());
    }
}
