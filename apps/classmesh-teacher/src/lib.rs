use classmesh_control::presentation_sender_plan::{
    TeacherPresentationOutlierBinding, TeacherPresentationSenderAction,
};
use classmesh_core::keyframe::PresentationKeyframeRequest;
use classmesh_windows_runtime::ipc::{
    ServicePresentationSenderUnicastAction, ServicePresentationSenderUnicastActionKind,
};

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
            destination: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, receiver)),
                port,
            ),
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

    #[test]
    fn granted_keyframe_is_forwarded_without_control_identity() {
        let request = PresentationKeyframeRequest::new(55, 7, 42).expect("valid keyframe request");
        let directive = TeacherVideoEngineDirective::from_sender_action(
            TeacherPresentationSenderAction::RequestKeyframe(request),
        );
        assert_eq!(directive, TeacherVideoEngineDirective::Keyframe(request));
    }
}
