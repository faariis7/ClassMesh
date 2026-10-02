pub mod monitoring;

#[cfg(windows)]
use classmesh_control::authorization::AuthenticatedControlGuard;
#[cfg(windows)]
use classmesh_control::group_media_delivery::{
    PresentationUnicastSenderTargetRequest, TeacherGroupMediaDeliveryError,
    TeacherGroupMediaDeliveryManager,
};
#[cfg(windows)]
use classmesh_control::group_media_feedback::{
    PresentationFeedbackError, PresentationRecoveryPlanRequest,
    accept_and_plan_presentation_feedback,
};
#[cfg(windows)]
use classmesh_control::presentation_fallback::PresentationFallbackCoordinator;
#[cfg(windows)]
use classmesh_control::presentation_recovery::PresentationRecoveryCoordinator;
use classmesh_control::presentation_sender_plan::{
    TeacherPresentationOutlierBinding, TeacherPresentationSenderAction,
};
#[cfg(windows)]
use classmesh_control::presentation_sender_plan::{
    TeacherPresentationSenderPlan, TeacherPresentationSenderPlanError,
};
#[cfg(windows)]
use classmesh_control::presentation_state::PresentationOwnership;
use classmesh_core::keyframe::PresentationKeyframeRequest;
use classmesh_windows_runtime::ipc::{
    ServicePresentationSenderUnicastAction, ServicePresentationSenderUnicastActionKind,
};

#[cfg(windows)]
use classmesh_capture_win::{CapturedFrameMeta, DxgiFrame};
#[cfg(windows)]
use classmesh_security::AuthorizationStore;
#[cfg(windows)]
use classmesh_security::group_media_coordinator::GroupMediaCoordinator;
#[cfg(windows)]
use classmesh_video::distributor::DEFAULT_MAX_QUEUE_DEPTH;
#[cfg(windows)]
use classmesh_worker::presentation_multicast_send::{
    PresentationMulticastSendBinding, PresentationMulticastSendRuntime,
    PresentationMulticastSendRuntimeError, PresentationMulticastSendStep,
};

#[cfg(windows)]
#[derive(Debug)]
pub enum TeacherVideoEngineApplyError {
    Runtime(PresentationMulticastSendRuntimeError),
}

#[cfg(windows)]
impl std::fmt::Display for TeacherVideoEngineApplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(error) => write!(formatter, "Teacher video engine runtime: {error}"),
        }
    }
}

#[cfg(windows)]
impl std::error::Error for TeacherVideoEngineApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
        }
    }
}

#[cfg(windows)]
impl From<PresentationMulticastSendRuntimeError> for TeacherVideoEngineApplyError {
    fn from(value: PresentationMulticastSendRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

#[cfg(windows)]
#[derive(Debug)]
pub enum TeacherVideoEngineLifecycleError {
    Apply(TeacherVideoEngineApplyError),
    NoActiveRuntime,
    ActiveRuntimeExists,
    InvalidUnicastQueueCapacity,
    BindingMismatch {
        active: PresentationMulticastSendBinding,
        requested: PresentationMulticastSendBinding,
    },
}

#[cfg(windows)]
impl std::fmt::Display for TeacherVideoEngineLifecycleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Apply(error) => write!(formatter, "Teacher video directive apply: {error}"),
            Self::NoActiveRuntime => formatter.write_str("Teacher video runtime is not active"),
            Self::ActiveRuntimeExists => {
                formatter.write_str("Teacher video runtime is already active")
            }
            Self::InvalidUnicastQueueCapacity => {
                formatter.write_str("Teacher video unicast queue capacity is out of bounds")
            }
            Self::BindingMismatch { active, requested } => write!(
                formatter,
                "Teacher video stop binding mismatch: active={}/{}/{} requested={}/{}/{}",
                active.presentation_id(),
                active.stream_id(),
                active.epoch(),
                requested.presentation_id(),
                requested.stream_id(),
                requested.epoch()
            ),
        }
    }
}

#[cfg(windows)]
impl std::error::Error for TeacherVideoEngineLifecycleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Apply(error) => Some(error),
            Self::NoActiveRuntime
            | Self::ActiveRuntimeExists
            | Self::InvalidUnicastQueueCapacity
            | Self::BindingMismatch { .. } => None,
        }
    }
}

#[cfg(windows)]
impl From<TeacherVideoEngineApplyError> for TeacherVideoEngineLifecycleError {
    fn from(value: TeacherVideoEngineApplyError) -> Self {
        Self::Apply(value)
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct ActiveTeacherVideoEngineRuntime {
    binding: PresentationMulticastSendBinding,
    runtime: PresentationMulticastSendRuntime,
    unicast_queue_capacity: usize,
}

#[cfg(windows)]
#[derive(Debug, Default)]
pub struct TeacherVideoEngineLifecycle {
    active: Option<ActiveTeacherVideoEngineRuntime>,
}

#[cfg(windows)]
impl TeacherVideoEngineLifecycle {
    pub fn start(
        &mut self,
        runtime: PresentationMulticastSendRuntime,
        unicast_queue_capacity: usize,
    ) -> Result<(), TeacherVideoEngineLifecycleError> {
        if self.active.is_some() {
            return Err(TeacherVideoEngineLifecycleError::ActiveRuntimeExists);
        }
        if unicast_queue_capacity == 0 || unicast_queue_capacity > DEFAULT_MAX_QUEUE_DEPTH {
            return Err(TeacherVideoEngineLifecycleError::InvalidUnicastQueueCapacity);
        }

        let binding = runtime.binding();
        self.active = Some(ActiveTeacherVideoEngineRuntime {
            binding,
            runtime,
            unicast_queue_capacity,
        });
        Ok(())
    }

    #[must_use]
    pub fn active_binding(&self) -> Option<PresentationMulticastSendBinding> {
        self.active.as_ref().map(|active| active.binding)
    }

    pub fn apply(
        &mut self,
        directive: TeacherVideoEngineDirective,
    ) -> Result<bool, TeacherVideoEngineLifecycleError> {
        let active = self
            .active
            .as_mut()
            .ok_or(TeacherVideoEngineLifecycleError::NoActiveRuntime)?;
        directive
            .apply(&mut active.runtime, active.unicast_queue_capacity)
            .map_err(Into::into)
    }

    pub fn process_frame(
        &mut self,
        meta: CapturedFrameMeta,
        frame: DxgiFrame,
        coordinator: &mut GroupMediaCoordinator,
        authorization: &AuthorizationStore,
    ) -> Result<PresentationMulticastSendStep, TeacherVideoEngineLifecycleError> {
        let active = self
            .active
            .as_mut()
            .ok_or(TeacherVideoEngineLifecycleError::NoActiveRuntime)?;
        active
            .runtime
            .process_frame(meta, frame, coordinator, authorization)
            .map_err(TeacherVideoEngineApplyError::from)
            .map_err(Into::into)
    }

    pub fn stop(
        &mut self,
        binding: PresentationMulticastSendBinding,
    ) -> Result<bool, TeacherVideoEngineLifecycleError> {
        let Some(active) = self.active.as_ref() else {
            return Ok(false);
        };
        if active.binding != binding {
            return Err(TeacherVideoEngineLifecycleError::BindingMismatch {
                active: active.binding,
                requested: binding,
            });
        }
        self.active = None;
        Ok(true)
    }
}

#[cfg(windows)]
#[derive(Debug)]
pub enum TeacherVideoRecoveryApplyError {
    Feedback(PresentationFeedbackError),
    Runtime(TeacherVideoEngineLifecycleError),
    DirectiveBindingMismatch,
    UnexpectedRecoveryAction,
}

#[cfg(windows)]
impl std::fmt::Display for TeacherVideoRecoveryApplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Feedback(error) => write!(formatter, "Teacher recovery feedback: {error}"),
            Self::Runtime(error) => write!(formatter, "Teacher recovery runtime: {error}"),
            Self::DirectiveBindingMismatch => {
                formatter.write_str("Teacher recovery directive did not match the active sender")
            }
            Self::UnexpectedRecoveryAction => formatter
                .write_str("Teacher recovery planner produced a non-keyframe sender action"),
        }
    }
}

#[cfg(windows)]
impl std::error::Error for TeacherVideoRecoveryApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Feedback(error) => Some(error),
            Self::Runtime(error) => Some(error),
            Self::DirectiveBindingMismatch | Self::UnexpectedRecoveryAction => None,
        }
    }
}

#[cfg(windows)]
pub fn accept_plan_and_apply_presentation_feedback(
    delivery: &TeacherGroupMediaDeliveryManager,
    request: PresentationRecoveryPlanRequest<'_>,
    guard: &mut AuthenticatedControlGuard,
    authorization: &AuthorizationStore,
    now_unix_ms: u64,
    recovery: &mut PresentationRecoveryCoordinator,
    lifecycle: &mut TeacherVideoEngineLifecycle,
) -> Result<bool, TeacherVideoRecoveryApplyError> {
    let decision = accept_and_plan_presentation_feedback(
        delivery,
        request,
        guard,
        authorization,
        now_unix_ms,
        recovery,
    )
    .map_err(TeacherVideoRecoveryApplyError::Feedback)?;

    let Some(action) = TeacherPresentationSenderPlan::recovery_action(decision) else {
        return Ok(false);
    };
    if !matches!(action, TeacherPresentationSenderAction::RequestKeyframe(_)) {
        return Err(TeacherVideoRecoveryApplyError::UnexpectedRecoveryAction);
    }

    let applied = lifecycle
        .apply(TeacherVideoEngineDirective::from_sender_action(action))
        .map_err(TeacherVideoRecoveryApplyError::Runtime)?;
    if !applied {
        return Err(TeacherVideoRecoveryApplyError::DirectiveBindingMismatch);
    }
    Ok(true)
}

#[cfg(windows)]
pub struct TeacherAuthorizedFallbackContext<'a> {
    pub delivery: &'a TeacherGroupMediaDeliveryManager,
    pub fallback: &'a PresentationFallbackCoordinator,
    pub coordinator: &'a GroupMediaCoordinator,
    pub authorization: &'a AuthorizationStore,
    pub ownership: &'a PresentationOwnership,
}

#[cfg(windows)]
#[derive(Debug)]
pub enum TeacherVideoAuthorizedFallbackError {
    Validation(TeacherGroupMediaDeliveryError),
    Apply(TeacherVideoFallbackApplyError),
}

#[cfg(windows)]
impl std::fmt::Display for TeacherVideoAuthorizedFallbackError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(error) => write!(formatter, "Teacher fallback validation: {error}"),
            Self::Apply(error) => write!(formatter, "Teacher fallback apply: {error}"),
        }
    }
}

#[cfg(windows)]
impl std::error::Error for TeacherVideoAuthorizedFallbackError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Validation(error) => Some(error),
            Self::Apply(error) => Some(error),
        }
    }
}

#[cfg(windows)]
pub fn apply_authorized_unicast_fallback(
    context: TeacherAuthorizedFallbackContext<'_>,
    request: PresentationUnicastSenderTargetRequest<'_>,
    plan: &mut TeacherPresentationSenderPlan,
    lifecycle: &mut TeacherVideoEngineLifecycle,
) -> Result<usize, TeacherVideoAuthorizedFallbackError> {
    let target = context
        .delivery
        .build_unicast_sender_target(
            context.fallback,
            context.coordinator,
            context.authorization,
            context.ownership,
            request,
        )
        .map_err(TeacherVideoAuthorizedFallbackError::Validation)?;
    apply_unicast_target_transactionally(plan, lifecycle, target)
        .map_err(TeacherVideoAuthorizedFallbackError::Apply)
}

#[cfg(windows)]
#[derive(Debug)]
pub enum TeacherVideoFallbackApplyError {
    Plan(TeacherPresentationSenderPlanError),
    Runtime(TeacherVideoEngineLifecycleError),
    Rollback(TeacherVideoEngineLifecycleError),
    RollbackDidNotChangeState,
    UnexpectedPreparedAction,
}

#[cfg(windows)]
impl std::fmt::Display for TeacherVideoFallbackApplyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plan(error) => write!(formatter, "Teacher sender plan: {error:?}"),
            Self::Runtime(error) => write!(formatter, "Teacher video runtime apply: {error}"),
            Self::Rollback(error) => write!(formatter, "Teacher video runtime rollback: {error}"),
            Self::RollbackDidNotChangeState => formatter
                .write_str("Teacher video runtime rollback did not restore the prior state"),
            Self::UnexpectedPreparedAction => formatter
                .write_str("Teacher fallback transaction contained a non-unicast sender action"),
        }
    }
}

#[cfg(windows)]
impl std::error::Error for TeacherVideoFallbackApplyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) | Self::Rollback(error) => Some(error),
            Self::Plan(_) | Self::RollbackDidNotChangeState | Self::UnexpectedPreparedAction => {
                None
            }
        }
    }
}

#[cfg(windows)]
pub fn apply_unicast_target_transactionally(
    plan: &mut TeacherPresentationSenderPlan,
    lifecycle: &mut TeacherVideoEngineLifecycle,
    target: classmesh_control::group_media_delivery::PresentationUnicastSenderTarget,
) -> Result<usize, TeacherVideoFallbackApplyError> {
    let prepared = plan
        .prepare_unicast_target(target)
        .map_err(TeacherVideoFallbackApplyError::Plan)?;
    let actions = prepared.actions().to_vec();
    let mut rollback_actions = Vec::with_capacity(actions.len());

    for action in actions {
        let inverse = inverse_sender_action(action)
            .ok_or(TeacherVideoFallbackApplyError::UnexpectedPreparedAction)?;
        match lifecycle.apply(TeacherVideoEngineDirective::from_sender_action(action)) {
            Ok(true) => rollback_actions.push(inverse),
            Ok(false) => {}
            Err(error) => {
                rollback_applied_sender_actions(lifecycle, &rollback_actions)?;
                return Err(TeacherVideoFallbackApplyError::Runtime(error));
            }
        }
    }

    if let Err(error) = plan.commit_unicast_target(prepared) {
        rollback_applied_sender_actions(lifecycle, &rollback_actions)?;
        return Err(TeacherVideoFallbackApplyError::Plan(error));
    }

    Ok(rollback_actions.len())
}

#[cfg(windows)]
fn rollback_applied_sender_actions(
    lifecycle: &mut TeacherVideoEngineLifecycle,
    actions: &[TeacherPresentationSenderAction],
) -> Result<(), TeacherVideoFallbackApplyError> {
    for action in actions.iter().rev().copied() {
        let changed = lifecycle
            .apply(TeacherVideoEngineDirective::from_sender_action(action))
            .map_err(TeacherVideoFallbackApplyError::Rollback)?;
        require_rollback_change(changed)?;
    }
    Ok(())
}

#[cfg(windows)]
fn require_rollback_change(changed: bool) -> Result<(), TeacherVideoFallbackApplyError> {
    if changed {
        Ok(())
    } else {
        Err(TeacherVideoFallbackApplyError::RollbackDidNotChangeState)
    }
}

#[must_use]
pub const fn inverse_sender_action(
    action: TeacherPresentationSenderAction,
) -> Option<TeacherPresentationSenderAction> {
    match action {
        TeacherPresentationSenderAction::AttachUnicast(binding) => {
            Some(TeacherPresentationSenderAction::DetachUnicast(binding))
        }
        TeacherPresentationSenderAction::DetachUnicast(binding) => {
            Some(TeacherPresentationSenderAction::AttachUnicast(binding))
        }
        TeacherPresentationSenderAction::RequestKeyframe(_) => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherVideoEngineDirective {
    Unicast(ServicePresentationSenderUnicastAction),
    Keyframe(PresentationKeyframeRequest),
}

impl TeacherVideoEngineDirective {
    #[must_use]
    pub fn from_sender_action(action: TeacherPresentationSenderAction) -> Self {
        match action {
            TeacherPresentationSenderAction::AttachUnicast(binding) => Self::Unicast(
                unicast_directive(ServicePresentationSenderUnicastActionKind::Attach, binding),
            ),
            TeacherPresentationSenderAction::DetachUnicast(binding) => Self::Unicast(
                unicast_directive(ServicePresentationSenderUnicastActionKind::Detach, binding),
            ),
            TeacherPresentationSenderAction::RequestKeyframe(request) => Self::Keyframe(request),
        }
    }

    #[cfg(windows)]
    pub fn apply(
        self,
        runtime: &mut PresentationMulticastSendRuntime,
        unicast_queue_capacity: usize,
    ) -> Result<bool, TeacherVideoEngineApplyError> {
        match self {
            Self::Unicast(action) => runtime
                .apply_unicast_sender_action(action, unicast_queue_capacity)
                .map_err(Into::into),
            Self::Keyframe(request) => runtime.apply_keyframe_request(request).map_err(Into::into),
        }
    }
}

fn unicast_directive(
    kind: ServicePresentationSenderUnicastActionKind,
    binding: TeacherPresentationOutlierBinding,
) -> ServicePresentationSenderUnicastAction {
    let target = binding.target();
    ServicePresentationSenderUnicastAction {
        kind,
        slot_id: binding.slot_id(),
        presentation_id: target.presentation_id,
        stream_id: target.stream_id,
        epoch: target.epoch.get(),
        destination: target.destination,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use classmesh_control::group_media_delivery::PresentationUnicastSenderTarget;
    use classmesh_control::presentation_sender_plan::{
        TeacherPresentationOutlierBinding, TeacherPresentationSenderAction,
    };
    use classmesh_core::adaptation::StreamProfile;
    use classmesh_core::keyframe::PresentationKeyframeRequest;
    use classmesh_security::PrincipalId;
    use classmesh_security::group_media::GroupMediaEpoch;
    use classmesh_windows_runtime::ipc::ServicePresentationSenderUnicastActionKind;

    use super::*;

    fn target(receiver: u8, port: u16, epoch: u32) -> PresentationUnicastSenderTarget {
        PresentationUnicastSenderTarget {
            receiver: PrincipalId([receiver; 32]),
            destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, receiver)), port),
            presentation_id: 55,
            stream_id: 7,
            profile: StreamProfile::new(1920, 1080, 30, 5_000),
            epoch: GroupMediaEpoch::new(epoch).expect("non-zero epoch"),
        }
    }

    #[test]
    fn attach_is_sanitized_to_exact_video_engine_binding() {
        let binding =
            TeacherPresentationOutlierBinding::new(11, target(7, 49_000, 3)).expect("binding");
        let directive = TeacherVideoEngineDirective::from_sender_action(
            TeacherPresentationSenderAction::AttachUnicast(binding),
        );

        let TeacherVideoEngineDirective::Unicast(action) = directive else {
            panic!("expected unicast directive");
        };
        assert_eq!(
            action.kind,
            ServicePresentationSenderUnicastActionKind::Attach
        );
        assert_eq!(action.slot_id, 11);
        assert_eq!(action.presentation_id, 55);
        assert_eq!(action.stream_id, 7);
        assert_eq!(action.epoch, 3);
        assert_eq!(action.destination, target(7, 49_000, 3).destination);
    }

    #[test]
    fn detach_keeps_exact_old_binding_without_receiver_identity() {
        let binding =
            TeacherPresentationOutlierBinding::new(11, target(9, 49_001, 4)).expect("binding");
        let directive = TeacherVideoEngineDirective::from_sender_action(
            TeacherPresentationSenderAction::DetachUnicast(binding),
        );

        let TeacherVideoEngineDirective::Unicast(action) = directive else {
            panic!("expected unicast directive");
        };
        assert_eq!(
            action.kind,
            ServicePresentationSenderUnicastActionKind::Detach
        );
        assert_eq!(action.slot_id, 11);
        assert_eq!(action.presentation_id, 55);
        assert_eq!(action.stream_id, 7);
        assert_eq!(action.epoch, 4);
        assert_eq!(action.destination, target(9, 49_001, 4).destination);
    }

    #[cfg(windows)]
    #[test]
    fn directive_exposes_real_video_runtime_apply_contract() {
        use classmesh_worker::presentation_multicast_send::PresentationMulticastSendRuntime;

        fn assert_apply(
            directive: TeacherVideoEngineDirective,
            runtime: &mut PresentationMulticastSendRuntime,
        ) {
            let _: Result<bool, TeacherVideoEngineApplyError> = directive.apply(runtime, 2);
        }

        let _ =
            assert_apply as fn(TeacherVideoEngineDirective, &mut PresentationMulticastSendRuntime);
    }

    #[cfg(windows)]
    #[test]
    fn lifecycle_rejects_directive_without_active_video_runtime() {
        let mut lifecycle = TeacherVideoEngineLifecycle::default();
        let directive = TeacherVideoEngineDirective::Keyframe(
            PresentationKeyframeRequest::new(55, 7, 42).expect("valid keyframe request"),
        );

        assert!(matches!(
            lifecycle.apply(directive),
            Err(TeacherVideoEngineLifecycleError::NoActiveRuntime)
        ));
        assert_eq!(lifecycle.active_binding(), None);
    }

    #[cfg(windows)]
    #[test]
    fn lifecycle_exposes_exact_start_apply_stop_contract() {
        use classmesh_worker::presentation_multicast_send::{
            PresentationMulticastSendBinding, PresentationMulticastSendRuntime,
        };

        fn assert_contract(
            lifecycle: &mut TeacherVideoEngineLifecycle,
            runtime: PresentationMulticastSendRuntime,
            binding: PresentationMulticastSendBinding,
            directive: TeacherVideoEngineDirective,
        ) {
            let _: Result<(), TeacherVideoEngineLifecycleError> = lifecycle.start(runtime, 2);
            let _: Option<PresentationMulticastSendBinding> = lifecycle.active_binding();
            let _: Result<bool, TeacherVideoEngineLifecycleError> = lifecycle.apply(directive);
            let _: Result<bool, TeacherVideoEngineLifecycleError> = lifecycle.stop(binding);
        }

        let _ = assert_contract
            as fn(
                &mut TeacherVideoEngineLifecycle,
                PresentationMulticastSendRuntime,
                PresentationMulticastSendBinding,
                TeacherVideoEngineDirective,
            );
    }

    #[cfg(windows)]
    #[test]
    fn lifecycle_exposes_caller_owned_frame_processing_contract() {
        use classmesh_capture_win::{CapturedFrameMeta, DxgiFrame};
        use classmesh_security::AuthorizationStore;
        use classmesh_security::group_media_coordinator::GroupMediaCoordinator;
        use classmesh_worker::presentation_multicast_send::PresentationMulticastSendStep;

        fn assert_process_frame(
            lifecycle: &mut TeacherVideoEngineLifecycle,
            meta: CapturedFrameMeta,
            frame: DxgiFrame,
            coordinator: &mut GroupMediaCoordinator,
            authorization: &AuthorizationStore,
        ) {
            let _: Result<PresentationMulticastSendStep, TeacherVideoEngineLifecycleError> =
                lifecycle.process_frame(meta, frame, coordinator, authorization);
        }

        let _ = assert_process_frame
            as fn(
                &mut TeacherVideoEngineLifecycle,
                CapturedFrameMeta,
                DxgiFrame,
                &mut GroupMediaCoordinator,
                &AuthorizationStore,
            );
    }

    #[test]
    fn sender_action_inverse_restores_exact_runtime_binding() {
        let binding =
            TeacherPresentationOutlierBinding::new(11, target(7, 49_000, 3)).expect("binding");

        assert_eq!(
            inverse_sender_action(TeacherPresentationSenderAction::AttachUnicast(binding)),
            Some(TeacherPresentationSenderAction::DetachUnicast(binding))
        );
        assert_eq!(
            inverse_sender_action(TeacherPresentationSenderAction::DetachUnicast(binding)),
            Some(TeacherPresentationSenderAction::AttachUnicast(binding))
        );

        let keyframe = PresentationKeyframeRequest::new(55, 7, 42).expect("valid keyframe request");
        assert_eq!(
            inverse_sender_action(TeacherPresentationSenderAction::RequestKeyframe(keyframe)),
            None
        );
    }

    #[cfg(windows)]
    #[test]
    fn rollback_requires_an_actual_runtime_state_change() {
        assert!(require_rollback_change(true).is_ok());
        assert!(matches!(
            require_rollback_change(false),
            Err(TeacherVideoFallbackApplyError::RollbackDidNotChangeState)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn transactional_target_apply_exposes_live_plan_runtime_contract() {
        use classmesh_control::presentation_sender_plan::TeacherPresentationSenderPlan;

        fn assert_contract(
            plan: &mut TeacherPresentationSenderPlan,
            lifecycle: &mut TeacherVideoEngineLifecycle,
            target: PresentationUnicastSenderTarget,
        ) {
            let _: Result<usize, TeacherVideoFallbackApplyError> =
                apply_unicast_target_transactionally(plan, lifecycle, target);
        }

        let _ = assert_contract
            as fn(
                &mut TeacherPresentationSenderPlan,
                &mut TeacherVideoEngineLifecycle,
                PresentationUnicastSenderTarget,
            );
    }

    #[cfg(windows)]
    #[test]
    fn authorized_fallback_orchestration_exposes_exact_contract() {
        use classmesh_control::group_media_delivery::PresentationUnicastSenderTargetRequest;
        use classmesh_control::presentation_sender_plan::TeacherPresentationSenderPlan;

        fn assert_contract(
            context: TeacherAuthorizedFallbackContext<'_>,
            request: PresentationUnicastSenderTargetRequest<'_>,
            plan: &mut TeacherPresentationSenderPlan,
            lifecycle: &mut TeacherVideoEngineLifecycle,
        ) {
            let _: Result<usize, TeacherVideoAuthorizedFallbackError> =
                apply_authorized_unicast_fallback(context, request, plan, lifecycle);
        }

        let _ = assert_contract;
    }

    #[cfg(windows)]
    #[test]
    fn authenticated_recovery_orchestration_exposes_exact_contract() {
        fn assert_contract(
            delivery: &TeacherGroupMediaDeliveryManager,
            request: PresentationRecoveryPlanRequest<'_>,
            guard: &mut AuthenticatedControlGuard,
            authorization: &AuthorizationStore,
            now_unix_ms: u64,
            recovery: &mut PresentationRecoveryCoordinator,
            lifecycle: &mut TeacherVideoEngineLifecycle,
        ) {
            let _: Result<bool, TeacherVideoRecoveryApplyError> =
                accept_plan_and_apply_presentation_feedback(
                    delivery,
                    request,
                    guard,
                    authorization,
                    now_unix_ms,
                    recovery,
                    lifecycle,
                );
        }

        let _ = assert_contract;
    }

    #[test]
    fn granted_keyframe_is_forwarded_without_control_identity() {
        let request = PresentationKeyframeRequest::new(55, 7, 42).expect("valid keyframe request");
        let directive = TeacherVideoEngineDirective::from_sender_action(
            TeacherPresentationSenderAction::RequestKeyframe(request),
        );
        assert_eq!(directive, TeacherVideoEngineDirective::Keyframe(request));
    }
}
