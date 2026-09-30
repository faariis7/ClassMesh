use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use classmesh_core::adaptation::StreamProfile;
use classmesh_core::keyframe::PresentationKeyframeRequest;
use classmesh_security::PrincipalId;
use classmesh_security::group_media::GroupMediaEpoch;
use classmesh_security::group_media_coordinator::MAX_GROUP_MEDIA_RECEIVERS;

use crate::group_media_delivery::PresentationUnicastSenderTarget;
use crate::presentation_recovery::{PresentationRecoveryDecision, PresentationRecoveryOutcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherPresentationSenderAction {
    AttachUnicast(PresentationUnicastSenderTarget),
    DetachUnicast(PresentationUnicastSenderTarget),
    RequestKeyframe(PresentationKeyframeRequest),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherPresentationSenderPlanError {
    InvalidReceiverLimit,
    ReceiverLimitReached,
}

#[derive(Debug)]
pub struct TeacherPresentationSenderPlan {
    targets: BTreeMap<PrincipalId, PresentationUnicastSenderTarget>,
    max_receivers: usize,
}

impl Default for TeacherPresentationSenderPlan {
    fn default() -> Self {
        Self {
            targets: BTreeMap::new(),
            max_receivers: MAX_GROUP_MEDIA_RECEIVERS,
        }
    }
}

impl TeacherPresentationSenderPlan {
    pub fn with_limit(max_receivers: usize) -> Result<Self, TeacherPresentationSenderPlanError> {
        if max_receivers == 0 || max_receivers > MAX_GROUP_MEDIA_RECEIVERS {
            return Err(TeacherPresentationSenderPlanError::InvalidReceiverLimit);
        }
        Ok(Self {
            targets: BTreeMap::new(),
            max_receivers,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    pub fn apply_unicast_target(
        &mut self,
        target: PresentationUnicastSenderTarget,
    ) -> Result<Vec<TeacherPresentationSenderAction>, TeacherPresentationSenderPlanError> {
        match self.targets.get(&target.receiver).copied() {
            Some(previous) if previous == target => Ok(Vec::new()),
            Some(previous) => {
                self.targets.insert(target.receiver, target);
                Ok(vec![
                    TeacherPresentationSenderAction::DetachUnicast(previous),
                    TeacherPresentationSenderAction::AttachUnicast(target),
                ])
            }
            None => {
                if self.targets.len() >= self.max_receivers {
                    return Err(TeacherPresentationSenderPlanError::ReceiverLimitReached);
                }
                self.targets.insert(target.receiver, target);
                Ok(vec![TeacherPresentationSenderAction::AttachUnicast(target)])
            }
        }
    }

    pub fn remove_receiver(
        &mut self,
        receiver: PrincipalId,
    ) -> Option<TeacherPresentationSenderAction> {
        self.targets
            .remove(&receiver)
            .map(TeacherPresentationSenderAction::DetachUnicast)
    }

    #[must_use]
    pub fn recovery_action(
        decision: PresentationRecoveryDecision,
    ) -> Option<TeacherPresentationSenderAction> {
        match (decision.outcome, decision.keyframe_request) {
            (
                PresentationRecoveryOutcome::KeyframeGranted { after_frame_id },
                Some(request),
            ) if request.after_frame_id() == after_frame_id => {
                Some(TeacherPresentationSenderAction::RequestKeyframe(request))
            }
            _ => None,
        }
    }
}

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
    fn recovery_action_rejects_inconsistent_manually_constructed_decision() {
        let request = PresentationKeyframeRequest::new(55, 7, 91).expect("valid request");
        let inconsistent = PresentationRecoveryDecision {
            outcome: PresentationRecoveryOutcome::KeyframeGranted { after_frame_id: 90 },
            keyframe_request: Some(request),
        };
        assert_eq!(
            TeacherPresentationSenderPlan::recovery_action(inconsistent),
            None
        );

        let suppressed_with_request = PresentationRecoveryDecision {
            outcome: PresentationRecoveryOutcome::KeyframeSuppressed { after_frame_id: 91 },
            keyframe_request: Some(request),
        };
        assert_eq!(
            TeacherPresentationSenderPlan::recovery_action(suppressed_with_request),
            None
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
