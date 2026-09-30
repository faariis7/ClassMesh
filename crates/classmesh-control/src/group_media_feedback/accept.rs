use classmesh_protocol::control_wire::ControlEnvelope;
use classmesh_protocol::feedback::FeedbackMessage;
use classmesh_security::{AuthorizationStore, Permission, PrincipalId};

use crate::authorization::AuthenticatedControlGuard;
use crate::client_session::ClientControlSession;
use crate::group_media_delivery::TeacherGroupMediaDeliveryManager;
use crate::presentation_recovery::{
    PresentationRecoveryCoordinator, PresentationRecoveryDecision, PresentationRecoveryOutcome,
};

use super::PresentationFeedbackError;
use super::wire::feedback_from_envelope;

pub struct PresentationFeedbackRequest<'a> {
    receiver: PrincipalId,
    session: &'a ClientControlSession,
    envelope: &'a ControlEnvelope,
    expected_stream_id: u32,
}

impl<'a> PresentationFeedbackRequest<'a> {
    #[must_use]
    pub const fn new(
        receiver: PrincipalId,
        session: &'a ClientControlSession,
        envelope: &'a ControlEnvelope,
        expected_stream_id: u32,
    ) -> Self {
        Self {
            receiver,
            session,
            envelope,
            expected_stream_id,
        }
    }
}

pub struct PresentationRecoveryPlanRequest<'a> {
    feedback: PresentationFeedbackRequest<'a>,
    presentation_id: u64,
    recovery_now_us: u64,
}

impl<'a> PresentationRecoveryPlanRequest<'a> {
    #[must_use]
    pub const fn new(
        feedback: PresentationFeedbackRequest<'a>,
        presentation_id: u64,
        recovery_now_us: u64,
    ) -> Self {
        Self {
            feedback,
            presentation_id,
            recovery_now_us,
        }
    }
}

pub fn accept_presentation_feedback(
    delivery: &TeacherGroupMediaDeliveryManager,
    request: PresentationFeedbackRequest<'_>,
    guard: &mut AuthenticatedControlGuard,
    authorization: &AuthorizationStore,
    now_unix_ms: u64,
) -> Result<FeedbackMessage, PresentationFeedbackError> {
    if request.expected_stream_id == 0 {
        return Err(PresentationFeedbackError::InvalidExpectedStream);
    }

    let feedback = feedback_from_envelope(request.envelope)?;

    delivery.validate_registered_client(
        request.receiver,
        request.session,
        authorization,
        now_unix_ms,
    )?;
    if guard.peer().principal_id() != request.receiver {
        return Err(PresentationFeedbackError::PeerMismatch);
    }

    guard.authorize(
        authorization,
        request.envelope,
        Permission::ReceivePresentation,
        now_unix_ms,
    )?;

    if request.envelope.request_id != 0 {
        return Err(PresentationFeedbackError::CorrelatedRequestUnsupported);
    }
    if feedback.stream_id() != request.expected_stream_id {
        return Err(PresentationFeedbackError::StreamMismatch {
            expected: request.expected_stream_id,
            received: feedback.stream_id(),
        });
    }

    Ok(feedback)
}

pub fn accept_and_coordinate_presentation_feedback(
    delivery: &TeacherGroupMediaDeliveryManager,
    request: PresentationFeedbackRequest<'_>,
    guard: &mut AuthenticatedControlGuard,
    authorization: &AuthorizationStore,
    now_unix_ms: u64,
    recovery: &mut PresentationRecoveryCoordinator,
    recovery_now_us: u64,
) -> Result<PresentationRecoveryOutcome, PresentationFeedbackError> {
    let feedback =
        accept_presentation_feedback(delivery, request, guard, authorization, now_unix_ms)?;
    recovery
        .observe(recovery_now_us, &feedback)
        .map_err(Into::into)
}

pub fn accept_and_plan_presentation_feedback(
    delivery: &TeacherGroupMediaDeliveryManager,
    request: PresentationRecoveryPlanRequest<'_>,
    guard: &mut AuthenticatedControlGuard,
    authorization: &AuthorizationStore,
    now_unix_ms: u64,
    recovery: &mut PresentationRecoveryCoordinator,
) -> Result<PresentationRecoveryDecision, PresentationFeedbackError> {
    let feedback =
        accept_presentation_feedback(delivery, request.feedback, guard, authorization, now_unix_ms)?;
    recovery
        .observe_and_plan(request.presentation_id, request.recovery_now_us, &feedback)
        .map_err(Into::into)
}
