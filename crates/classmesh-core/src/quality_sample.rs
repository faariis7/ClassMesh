use crate::NetworkMetrics;

pub const RECEIVER_QUALITY_SAMPLE_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverCapabilityHealth {
    pub hardware_decode_available: bool,
    pub profile_supported: bool,
    pub decoder_healthy: bool,
    pub renderer_healthy: bool,
}

impl ReceiverCapabilityHealth {
    #[must_use]
    pub const fn media_healthy(self) -> bool {
        self.hardware_decode_available
            && self.profile_supported
            && self.decoder_healthy
            && self.renderer_healthy
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReceiverQualitySample {
    pub schema_version: u16,
    pub sample_sequence: u64,
    pub observed_at_us: u64,
    pub network: NetworkMetrics,
    pub reordered_packet_rate: f32,
    pub decode_delay_ms: f32,
    pub render_delay_ms: f32,
    pub queue_depth: u32,
    pub queue_drop_rate: f32,
    pub capability: ReceiverCapabilityHealth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverQualitySampleError {
    UnsupportedVersion(u16),
    InvalidSequence,
    InvalidNetworkMetrics,
    InvalidReorderedPacketRate,
    InvalidDecodeDelay,
    InvalidRenderDelay,
    InvalidQueueDropRate,
}

impl ReceiverQualitySample {
    pub fn validate(self) -> Result<Self, ReceiverQualitySampleError> {
        todo!("Phase 10A RED: validate the complete per-receiver quality sample")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_sample() -> ReceiverQualitySample {
        ReceiverQualitySample {
            schema_version: RECEIVER_QUALITY_SAMPLE_VERSION,
            sample_sequence: 1,
            observed_at_us: 0,
            network: NetworkMetrics {
                rtt_ms: 12.0,
                packet_loss: 0.002,
                jitter_ms: 1.5,
                decode_fps: 30.0,
                queue_delay_ms: 4.0,
                estimated_mbps: 80.0,
                multicast_viable: true,
                wireless: false,
            },
            reordered_packet_rate: 0.001,
            decode_delay_ms: 5.0,
            render_delay_ms: 3.0,
            queue_depth: 2,
            queue_drop_rate: 0.0,
            capability: ReceiverCapabilityHealth {
                hardware_decode_available: true,
                profile_supported: true,
                decoder_healthy: true,
                renderer_healthy: true,
            },
        }
    }

    #[test]
    fn complete_receiver_quality_sample_validates() {
        let sample = healthy_sample();
        assert_eq!(sample.validate(), Ok(sample));
        assert!(sample.capability.media_healthy());
    }

    #[test]
    fn unsupported_version_and_unset_sequence_fail_closed() {
        let mut version = healthy_sample();
        version.schema_version += 1;
        assert_eq!(
            version.validate(),
            Err(ReceiverQualitySampleError::UnsupportedVersion(2))
        );

        let mut sequence = healthy_sample();
        sequence.sample_sequence = 0;
        assert_eq!(
            sequence.validate(),
            Err(ReceiverQualitySampleError::InvalidSequence)
        );
    }

    #[test]
    fn non_finite_network_input_is_rejected_even_if_legacy_metric_check_would_accept_it() {
        let mut sample = healthy_sample();
        sample.network.estimated_mbps = f32::INFINITY;
        assert_eq!(
            sample.validate(),
            Err(ReceiverQualitySampleError::InvalidNetworkMetrics)
        );
    }

    #[test]
    fn rate_fields_are_bounded_to_zero_through_one() {
        let mut reordered = healthy_sample();
        reordered.reordered_packet_rate = 1.1;
        assert_eq!(
            reordered.validate(),
            Err(ReceiverQualitySampleError::InvalidReorderedPacketRate)
        );

        let mut dropped = healthy_sample();
        dropped.queue_drop_rate = f32::NAN;
        assert_eq!(
            dropped.validate(),
            Err(ReceiverQualitySampleError::InvalidQueueDropRate)
        );
    }

    #[test]
    fn decode_and_render_delays_must_be_finite_and_non_negative() {
        let mut decode = healthy_sample();
        decode.decode_delay_ms = -1.0;
        assert_eq!(
            decode.validate(),
            Err(ReceiverQualitySampleError::InvalidDecodeDelay)
        );

        let mut render = healthy_sample();
        render.render_delay_ms = f32::INFINITY;
        assert_eq!(
            render.validate(),
            Err(ReceiverQualitySampleError::InvalidRenderDelay)
        );
    }

    #[test]
    fn unhealthy_capability_state_is_valid_signal_not_malformed_input() {
        let mut sample = healthy_sample();
        sample.capability.decoder_healthy = false;
        assert_eq!(sample.validate(), Ok(sample));
        assert!(!sample.capability.media_healthy());
    }
}
