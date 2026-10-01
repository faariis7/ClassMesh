use classmesh_control::presentation_sender_plan::{
    TeacherPresentationOutlierBinding, TeacherPresentationSenderAction,
};
use classmesh_core::keyframe::PresentationKeyframeRequest;
use classmesh_windows_runtime::ipc::{
    ServicePresentationSenderUnicastAction, ServicePresentationSenderUnicastActionKind,
};

#[cfg(windows)]
use classmesh_video::distributor::DEFAULT_MAX_QUEUE_DEPTH;
#[cfg(windows)]
use classmesh_worker::presentation_multicast_send::{
    PresentationMulticastSendBinding, PresentationMulticastSendRuntime,
    PresentationMulticastSendRuntimeError,
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
pub enum TeacherVideoEngineLifecycleError {
    NoActiveRuntime,
    AlreadyActiveRuntime,
    InvalidUnicastQueueCapacity,
    Apply(TeacherVideoEngineApplyError),
}

#[cfg(windows)]
impl std::fmt::Display for TeacherVideoEngineLifecycleError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoActiveRuntime => formatter.write_str("Teacher video engine has no active runtime"),
            Self::AlreadyActiveRuntime => {
                formatter.write_str("Teacher video engine runtime is already active")
            }
            Self::InvalidUnicastQueueCapacity => {
                formatter.write_str("Teacher video engine unicast queue capacity must be non-zero")
            }
            Self::Apply(error) => write!(formatter, "{error}"),
        }
    }
}

#[cfg(windows)]
impl std::error::Error for TeacherVideoEngineLifecycleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Apply(error) => Some(error),
            Self::NoActiveRuntime
            | Self::AlreadyActiveRuntime
            | Self::InvalidUnicastQueueCapacity => None,
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
#[derive(Debug, Default)]
pub struct TeacherVideoEngineLifecycle {
    runtime: Option<PresentationMulticastSendRuntime>,
    unicast_queue_capacity: usize,
}

#[cfg(windows)]
impl TeacherVideoEngineLifecycle {
    pub fn start(
        &mut self,
        runtime: PresentationMulticastSendRuntime,
        unicast_queue_capacity: usize,
    ) -> Result<(), TeacherVideoEngineLifecycleError> {
        if self.runtime.is_some() {
            return Err(TeacherVideoEngineLifecycleError::AlreadyActiveRuntime);
        }
        if unicast_queue_capacity == 0 {
            return Err(TeacherVideoEngineLifecycleError::InvalidUnicastQueueCapacity);
        }
        self.runtime = Some(runtime);
        self.unicast_queue_capacity = unicast_queue_capacity;
        Ok(())
    }

    #[must_use]
    pub fn active_binding(&self) -> Option<PresentationMulticastSendBinding> {
        self.runtime.as_ref().map(PresentationMulticastSendRuntime::binding)
    }

    pub fn apply(
        &mut self,
        directive: TeacherVideoEngineDirective,
    ) -> Result<bool, TeacherVideoEngineLifecycleError> {
        let runtime = self
            .runtime
            .as_mut()
            .ok_or(TeacherVideoEngineLifecycleError::NoActiveRuntime)?;
        directive
            .apply(runtime, self.unicast_queue_capacity)
            .map_err(Into::into)
    }

    pub fn stop(
        &mut self,
        binding: PresentationMulticastSendBinding,
    ) -> Result<bool, TeacherVideoEngineLifecycleError> {
        let Some(runtime) = self.runtime.as_ref() else {
            return Ok(false);
        };
        if runtime.binding() != binding {
            return Ok(false);
        }
        self.runtime = None;
        self.unicast_queue_capacity = 0;
        Ok(true)
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

    #[test]
    fn granted_keyframe_is_forwarded_without_control_identity() {
        let request = PresentationKeyframeRequest::new(55, 7, 42).expect("valid keyframe request");
        let directive = TeacherVideoEngineDirective::from_sender_action(
            TeacherPresentationSenderAction::RequestKeyframe(request),
        );
        assert_eq!(directive, TeacherVideoEngineDirective::Keyframe(request));
    }
}
