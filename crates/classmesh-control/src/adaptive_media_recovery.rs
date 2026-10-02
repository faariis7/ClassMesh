use classmesh_core::keyframe::PresentationKeyframeRequest;
use classmesh_core::quality_sample::ReceiverQualitySample;
use classmesh_core::receiver_quality::{
    ReceiverQualityObservation, ReceiverQualityPolicy, ReceiverQualityPolicyError,
    ReceiverQualitySampleStatus,
};

use crate::presentation_recovery::PresentationRecoveryDecision;
use crate::presentation_sender_plan::{
    TeacherPresentationSenderAction, TeacherPresentationSenderPlan,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverMediaRecoveryPlan {
    pub catch_up_latest: bool,
    pub keyframe_request: Option<PresentationKeyframeRequest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiverMediaRecoveryPlanError {
    InvalidQualityPolicy(ReceiverQualityPolicyError),
}

pub fn plan_receiver_media_recovery(
    sample: ReceiverQualitySample,
    observation: ReceiverQualityObservation,
    quality_policy: ReceiverQualityPolicy,
    recovery: Option<PresentationRecoveryDecision>,
) -> Result<ReceiverMediaRecoveryPlan, ReceiverMediaRecoveryPlanError> {
    let quality_policy = quality_policy
        .validate()
        .map_err(ReceiverMediaRecoveryPlanError::InvalidQualityPolicy)?;

    let sample_is_valid = sample.validate().is_ok();
    let accepted = observation.status == ReceiverQualitySampleStatus::Accepted;
    let queue_pressure = sample.queue_depth >= quality_policy.degraded_queue_depth
        || sample.queue_drop_rate >= quality_policy.degraded_queue_drop_rate;

    Ok(ReceiverMediaRecoveryPlan {
        catch_up_latest: accepted && sample_is_valid && queue_pressure,
        keyframe_request: recovery.and_then(sanitized_keyframe_request),
    })
}

fn sanitized_keyframe_request(
    recovery: PresentationRecoveryDecision,
) -> Option<PresentationKeyframeRequest> {
    match TeacherPresentationSenderPlan::recovery_action(recovery) {
        Some(TeacherPresentationSenderAction::RequestKeyframe(request)) => Some(request),
        Some(
            TeacherPresentationSenderAction::AttachUnicast(_)
            | TeacherPresentationSenderAction::DetachUnicast(_),
        )
        | None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use classmesh_core::NetworkMetrics;
    use classmesh_core::adaptation::{FocusedProfileDecision, QualityTier, StreamProfile};
    use classmesh_core::quality_sample::{
        RECEIVER_QUALITY_SAMPLE_VERSION, ReceiverCapabilityHealth,
    };
    use classmesh_core::receiver_quality::ReceiverQualitySampleStatus;
    use classmesh_video::distributor::{FrameDistributor, SharedEncodedFrame, SinkId, SinkMode};
    use classmesh_video::{Codec, EncodedFrameMeta};

    fn sample() -> ReceiverQualitySample {
        ReceiverQualitySample {
            schema_version: RECEIVER_QUALITY_SAMPLE_VERSION,
            sample_sequence: 1,
            observed_at_us: 1_000_000,
            network: NetworkMetrics {
                rtt_ms: 10.0,
                packet_loss: 0.001,
                jitter_ms: 1.0,
                decode_fps: 30.0,
                queue_delay_ms: 4.0,
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

    fn observation(status: ReceiverQualitySampleStatus) -> ReceiverQualityObservation {
        ReceiverQualityObservation {
            decision: FocusedProfileDecision {
                profile: StreamProfile::new(1280, 720, 30, 2_500),
                tier: QualityTier::High,
                changed: false,
            },
            status,
        }
    }

    fn frame(id: u64, keyframe: bool) -> SharedEncodedFrame {
        SharedEncodedFrame::new(
            EncodedFrameMeta {
                frame_id: id,
                timestamp_us: id * 1_000,
                keyframe,
            },
            Codec::H264,
            vec![u8::try_from(id).unwrap_or(0); 8],
        )
    }

    #[test]
    fn accepted_queue_pressure_requests_latest_frame_catch_up() {
        let policy = ReceiverQualityPolicy::default();
        let mut congested = sample();
        congested.queue_depth = policy.degraded_queue_depth;

        let plan = plan_receiver_media_recovery(
            congested,
            observation(ReceiverQualitySampleStatus::Accepted),
            policy,
            None,
        )
        .unwrap();

        assert!(plan.catch_up_latest);
        assert!(plan.keyframe_request.is_none());
    }

    #[test]
    fn rejected_or_invalid_telemetry_cannot_force_media_drops() {
        let policy = ReceiverQualityPolicy::default();
        let mut congested = sample();
        congested.queue_depth = policy.severe_queue_depth;
        congested.queue_drop_rate = policy.severe_queue_drop_rate;

        for status in [
            ReceiverQualitySampleStatus::StaleAge,
            ReceiverQualitySampleStatus::NonMonotonicSequence,
            ReceiverQualitySampleStatus::FutureObservation,
        ] {
            let plan =
                plan_receiver_media_recovery(congested, observation(status), policy, None).unwrap();
            assert!(!plan.catch_up_latest);
        }

        congested.queue_drop_rate = f32::NAN;
        let plan = plan_receiver_media_recovery(
            congested,
            observation(ReceiverQualitySampleStatus::Accepted),
            policy,
            None,
        )
        .unwrap();
        assert!(!plan.catch_up_latest);
    }

    #[test]
    fn only_existing_sanitized_granted_recovery_produces_keyframe_action() {
        use crate::presentation_recovery::{
            PresentationRecoveryDecision, PresentationRecoveryOutcome,
        };

        let request = PresentationKeyframeRequest::new(55, 7, 91).unwrap();
        let granted = PresentationRecoveryDecision {
            outcome: PresentationRecoveryOutcome::KeyframeGranted { after_frame_id: 91 },
            keyframe_request: Some(request),
        };
        let suppressed = PresentationRecoveryDecision {
            outcome: PresentationRecoveryOutcome::KeyframeSuppressed { after_frame_id: 92 },
            keyframe_request: None,
        };

        let policy = ReceiverQualityPolicy::default();
        let granted_plan = plan_receiver_media_recovery(
            sample(),
            observation(ReceiverQualitySampleStatus::Accepted),
            policy,
            Some(granted),
        )
        .unwrap();
        assert_eq!(granted_plan.keyframe_request, Some(request));

        let suppressed_plan = plan_receiver_media_recovery(
            sample(),
            observation(ReceiverQualitySampleStatus::Accepted),
            policy,
            Some(suppressed),
        )
        .unwrap();
        assert_eq!(suppressed_plan.keyframe_request, None);
    }

    #[test]
    fn catch_up_uses_decoder_safe_latest_frame_wins_without_touching_peer_queue() {
        let policy = ReceiverQualityPolicy::default();
        let mut congested = sample();
        congested.queue_depth = policy.degraded_queue_depth;
        let plan = plan_receiver_media_recovery(
            congested,
            observation(ReceiverQualitySampleStatus::Accepted),
            policy,
            None,
        )
        .unwrap();
        assert!(plan.catch_up_latest);

        let mut distributor = FrameDistributor::default();
        distributor
            .add_sink(SinkId(1), SinkMode::Unicast, 4)
            .unwrap();
        distributor
            .add_sink(SinkId(2), SinkMode::Unicast, 4)
            .unwrap();

        distributor.publish(frame(1, true));
        distributor.publish(frame(2, false));
        distributor.publish(frame(3, false));
        distributor.publish(frame(4, false));

        let peer_before = distributor.stats(SinkId(2)).unwrap();

        let recovery = distributor.pop_next_decodable(SinkId(1)).unwrap();
        assert!(recovery.meta.keyframe);
        assert_eq!(recovery.meta.frame_id, 1);

        let latest = distributor.pop_next_decodable(SinkId(1)).unwrap();
        assert_eq!(latest.meta.frame_id, 4);
        assert!(!latest.meta.keyframe);

        let receiver_after = distributor.stats(SinkId(1)).unwrap();
        let peer_after = distributor.stats(SinkId(2)).unwrap();
        assert_eq!(receiver_after.queued, 0);
        assert_eq!(peer_after, peer_before);
        assert_eq!(peer_after.queued, 4);
    }
}
