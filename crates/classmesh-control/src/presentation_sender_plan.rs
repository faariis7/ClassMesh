use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use classmesh_core::adaptation::StreamProfile;
use classmesh_core::keyframe::PresentationKeyframeRequest;
use classmesh_security::PrincipalId;
use classmesh_security::group_media::GroupMediaEpoch;

use crate::group_media_delivery::PresentationUnicastSenderTarget;
use crate::presentation_recovery::{PresentationRecoveryDecision, PresentationRecoveryOutcome};

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    fn target(receiver: u8, port: u16, epoch: u64) -> PresentationUnicastSenderTarget {
        PresentationUnicastSenderTarget {
            receiver: principal(receiver),
            destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, receiver)), port),
            presentation_id: 55,
            stream_id: 7,
            profile: StreamProfile::new(1920, 1080, 30, 5_000),
            epoch: GroupMediaEpoch::new(epoch).expect("non-zero epoch"),
        }
    }

    #[test]
    fn exact_target_is_idempotent_and_drift_replaces_exact_previous_binding() {
        let mut plan = TeacherPresentationSenderPlan::with_limit(2).expect("bounded plan");
        let first = target(7, 49_000, 1);

        assert_eq!(
            plan.apply_unicast_target(first).expect("first target"),
            vec![TeacherPresentationSenderAction::AttachUnicast(first)]
        );
        assert!(
            plan.apply_unicast_target(first)
                .expect("exact retry")
                .is_empty()
        );

        let drifted = target(7, 49_001, 2);
        assert_eq!(
            plan.apply_unicast_target(drifted).expect("drifted target"),
            vec![
                TeacherPresentationSenderAction::DetachUnicast(first),
                TeacherPresentationSenderAction::AttachUnicast(drifted),
            ]
        );
        assert_eq!(plan.len(), 1);
    }

    #[test]
    fn cleanup_detaches_only_known_receiver_binding() {
        let mut plan = TeacherPresentationSenderPlan::with_limit(2).expect("bounded plan");
        let first = target(7, 49_000, 1);
        plan.apply_unicast_target(first).expect("first target");

        assert_eq!(
            plan.remove_receiver(principal(7)),
            Some(TeacherPresentationSenderAction::DetachUnicast(first))
        );
        assert_eq!(plan.remove_receiver(principal(7)), None);
        assert!(plan.is_empty());
    }

    #[test]
    fn plan_is_bounded_by_receiver_count() {
        let mut plan = TeacherPresentationSenderPlan::with_limit(1).expect("bounded plan");
        plan.apply_unicast_target(target(7, 49_000, 1))
            .expect("first target");
        assert_eq!(
            plan.apply_unicast_target(target(8, 49_001, 1)),
            Err(TeacherPresentationSenderPlanError::ReceiverLimitReached)
        );
    }

    #[test]
    fn recovery_action_exists_only_for_granted_sanitized_request() {
        let request = PresentationKeyframeRequest::new(55, 7, 91).expect("valid request");
        let granted = PresentationRecoveryDecision {
            outcome: PresentationRecoveryOutcome::KeyframeGranted { after_frame_id: 91 },
            keyframe_request: Some(request),
        };
        assert_eq!(
            TeacherPresentationSenderPlan::recovery_action(granted),
            Some(TeacherPresentationSenderAction::RequestKeyframe(request))
        );

        let suppressed = PresentationRecoveryDecision {
            outcome: PresentationRecoveryOutcome::KeyframeSuppressed { after_frame_id: 92 },
            keyframe_request: None,
        };
        assert_eq!(
            TeacherPresentationSenderPlan::recovery_action(suppressed),
            None
        );
    }
}
