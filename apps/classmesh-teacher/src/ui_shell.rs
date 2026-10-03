use std::collections::BTreeSet;

use classmesh_core::MediaState;
use classmesh_core::adaptation::QualityTier;
use classmesh_core::presence::PresenceState;
use classmesh_core::transport_topology::TransportTopologyEvidence;
use classmesh_protocol::Capability;
use classmesh_protocol::control_wire::StreamOffer;
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

use crate::classroom_view::{ClassroomViewError, TeacherClassroomViewModel};
use crate::device_diagnostics::{
    TeacherDeviceDiagnosticsViewModel, TroubleshootingOverrideError,
    TroubleshootingOverrideRequest, ValidatedTroubleshootingOverride,
};
use crate::focus_view::{FocusViewError, TeacherFocusViewModel};
use crate::monitoring_promotion::TeacherMonitoringCoordinator;
use crate::presentation_view::PresentationBindingView;
#[cfg(windows)]
use crate::presentation_view::TeacherPresentationViewModel;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TeacherUiSection {
    #[default]
    Classroom,
    Focus,
    Presentation,
    Diagnostics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherUiMessage {
    Navigate(TeacherUiSection),
    SelectDevice(Option<MonitoringSourceId>),
    RequestInteractive(MonitoringSourceId),
    ResumeThumbnail(MonitoringSourceId),
    StartPresentation,
    StopPresentation(PresentationBindingView),
    RequestTroubleshootingOverride {
        source_id: MonitoringSourceId,
        request: TroubleshootingOverrideRequest,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherFocusUiAction {
    RequestInteractive { source_id: MonitoringSourceId },
    ResumeThumbnail { source_id: MonitoringSourceId },
}

impl TeacherFocusUiAction {
    #[must_use]
    pub const fn source_id(self) -> MonitoringSourceId {
        match self {
            Self::RequestInteractive { source_id } | Self::ResumeThumbnail { source_id } => {
                source_id
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherPresentationUiAction {
    Start,
    Stop { binding: PresentationBindingView },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TeacherDiagnosticsUiAction {
    pub source_id: MonitoringSourceId,
    pub request: TroubleshootingOverrideRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherUiAction {
    SelectDevice(Option<MonitoringSourceId>),
    Focus(TeacherFocusUiAction),
    Presentation(TeacherPresentationUiAction),
    Diagnostics(TeacherDiagnosticsUiAction),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherUiClassroomActionError {
    NotClassroomAction,
    Classroom(ClassroomViewError),
}

impl TeacherUiAction {
    pub fn apply_to_classroom(
        self,
        classroom: &mut TeacherClassroomViewModel,
    ) -> Result<(), TeacherUiClassroomActionError> {
        match self {
            Self::SelectDevice(source_id) => classroom
                .select(source_id)
                .map_err(TeacherUiClassroomActionError::Classroom),
            Self::Focus(_) | Self::Presentation(_) | Self::Diagnostics(_) => {
                Err(TeacherUiClassroomActionError::NotClassroomAction)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeacherFocusUiActionError {
    SelectionChanged {
        expected: MonitoringSourceId,
        selected: Option<MonitoringSourceId>,
    },
    MissingInteractiveContext,
    Focus(FocusViewError),
}

pub fn apply_focus_ui_action(
    action: TeacherFocusUiAction,
    classroom: &TeacherClassroomViewModel,
    monitoring: &mut TeacherMonitoringCoordinator,
    interactive: Option<(&StreamOffer, &BTreeSet<Capability>)>,
) -> Result<(), TeacherFocusUiActionError> {
    let expected = action.source_id();
    let selected = classroom.selected();
    if selected != Some(expected) {
        return Err(TeacherFocusUiActionError::SelectionChanged { expected, selected });
    }

    match action {
        TeacherFocusUiAction::RequestInteractive { .. } => {
            let (offer, negotiated_capabilities) =
                interactive.ok_or(TeacherFocusUiActionError::MissingInteractiveContext)?;
            TeacherFocusViewModel::request_interactive(
                classroom,
                monitoring,
                offer,
                negotiated_capabilities,
            )
            .map_err(TeacherFocusUiActionError::Focus)
        }
        TeacherFocusUiAction::ResumeThumbnail { .. } => {
            TeacherFocusViewModel::resume_thumbnail(classroom, monitoring)
                .map_err(TeacherFocusUiActionError::Focus)
        }
    }
}

#[cfg(windows)]
#[derive(Debug)]
pub enum TeacherPresentationUiActionError {
    MissingStartContext,
    BindingChanged {
        expected: PresentationBindingView,
        active: Option<PresentationBindingView>,
    },
    Presentation(crate::TeacherVideoEngineLifecycleError),
}

#[cfg(windows)]
fn active_presentation_binding(
    lifecycle: &crate::TeacherVideoEngineLifecycle,
) -> Option<PresentationBindingView> {
    lifecycle
        .active_binding()
        .map(|binding| PresentationBindingView {
            presentation_id: binding.presentation_id(),
            stream_id: binding.stream_id(),
            epoch: binding.epoch(),
        })
}

#[cfg(windows)]
pub fn apply_presentation_ui_action(
    action: TeacherPresentationUiAction,
    lifecycle: &mut crate::TeacherVideoEngineLifecycle,
    start_context: Option<(
        classmesh_worker::presentation_multicast_send::PresentationMulticastSendRuntime,
        usize,
    )>,
) -> Result<(), TeacherPresentationUiActionError> {
    match action {
        TeacherPresentationUiAction::Start => {
            let (runtime, unicast_queue_capacity) =
                start_context.ok_or(TeacherPresentationUiActionError::MissingStartContext)?;
            TeacherPresentationViewModel::start(lifecycle, runtime, unicast_queue_capacity)
                .map_err(TeacherPresentationUiActionError::Presentation)
        }
        TeacherPresentationUiAction::Stop { binding } => {
            let active = active_presentation_binding(lifecycle);
            if active != Some(binding) {
                return Err(TeacherPresentationUiActionError::BindingChanged {
                    expected: binding,
                    active,
                });
            }

            let stopped = TeacherPresentationViewModel::stop(lifecycle)
                .map_err(TeacherPresentationUiActionError::Presentation)?;
            if stopped {
                Ok(())
            } else {
                Err(TeacherPresentationUiActionError::BindingChanged {
                    expected: binding,
                    active: None,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherDiagnosticsUiActionError {
    SelectionChanged {
        expected: MonitoringSourceId,
        selected: Option<MonitoringSourceId>,
    },
    Validation(TroubleshootingOverrideError),
}

pub fn apply_diagnostics_ui_action(
    action: TeacherDiagnosticsUiAction,
    classroom: &TeacherClassroomViewModel,
    diagnostics: &TeacherDeviceDiagnosticsViewModel,
    live_evidence: TransportTopologyEvidence,
) -> Result<ValidatedTroubleshootingOverride, TeacherDiagnosticsUiActionError> {
    let selected = classroom.selected();
    if selected != Some(action.source_id) {
        return Err(TeacherDiagnosticsUiActionError::SelectionChanged {
            expected: action.source_id,
            selected,
        });
    }

    diagnostics
        .validate_override(action.request, live_evidence)
        .map_err(TeacherDiagnosticsUiActionError::Validation)
}

#[must_use]
pub const fn presence_label(presence: PresenceState) -> &'static str {
    match presence {
        PresenceState::Offline => "Offline",
        PresenceState::Connecting => "Connecting",
        PresenceState::Online => "Online",
        PresenceState::ControlRecovering => "Control recovering",
    }
}

#[must_use]
pub const fn media_label(media: MediaState) -> &'static str {
    match media {
        MediaState::Idle => "Idle",
        MediaState::Starting => "Starting",
        MediaState::Streaming => "Streaming",
        MediaState::Degraded => "Degraded",
        MediaState::Recovering => "Recovering",
        MediaState::Stopped => "Stopped",
    }
}

#[must_use]
pub const fn quality_label(quality: Option<QualityTier>) -> &'static str {
    match quality {
        None => "Unknown",
        Some(QualityTier::Emergency) => "Emergency",
        Some(QualityTier::Low) => "Low",
        Some(QualityTier::Medium) => "Medium",
        Some(QualityTier::High) => "High",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TeacherUiShellState {
    active_section: TeacherUiSection,
}

impl TeacherUiShellState {
    #[must_use]
    pub const fn active_section(&self) -> TeacherUiSection {
        self.active_section
    }

    pub fn handle(&mut self, message: TeacherUiMessage) -> Option<TeacherUiAction> {
        match message {
            TeacherUiMessage::Navigate(section) => {
                self.active_section = section;
                None
            }
            TeacherUiMessage::SelectDevice(source_id) => {
                Some(TeacherUiAction::SelectDevice(source_id))
            }
            TeacherUiMessage::RequestInteractive(source_id) => Some(TeacherUiAction::Focus(
                TeacherFocusUiAction::RequestInteractive { source_id },
            )),
            TeacherUiMessage::ResumeThumbnail(source_id) => Some(TeacherUiAction::Focus(
                TeacherFocusUiAction::ResumeThumbnail { source_id },
            )),
            TeacherUiMessage::StartPresentation => Some(TeacherUiAction::Presentation(
                TeacherPresentationUiAction::Start,
            )),
            TeacherUiMessage::StopPresentation(binding) => Some(TeacherUiAction::Presentation(
                TeacherPresentationUiAction::Stop { binding },
            )),
            TeacherUiMessage::RequestTroubleshootingOverride { source_id, request } => {
                Some(TeacherUiAction::Diagnostics(TeacherDiagnosticsUiAction {
                    source_id,
                    request,
                }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use classmesh_core::MediaTransport as CoreMediaTransport;
    use classmesh_core::presence::DeviceHealth;
    use classmesh_core::transport_topology::{
        MediaPath, MediaTopology, PhysicalGateStatus, PhysicalPathGate,
    };
    use classmesh_protocol::control_wire::{MediaTransport, StreamKind, VideoCodec, VideoProfile};
    use classmesh_video::monitoring::MonitoringProfile;
    use classmesh_video::monitoring_fanin::MonitoringFanInConfig;
    use classmesh_video::monitoring_scheduler::{MonitoringPriority, MonitoringSchedulerConfig};

    use crate::classroom_view::{ClassroomDeviceSnapshot, ClassroomViewConfig};
    use crate::monitoring_promotion::TeacherMonitoringAction;

    use super::*;

    fn classroom() -> TeacherClassroomViewModel {
        let mut classroom = TeacherClassroomViewModel::new(ClassroomViewConfig::default()).unwrap();
        classroom
            .upsert(ClassroomDeviceSnapshot {
                source_id: MonitoringSourceId(7),
                display_name: "Student 07".to_owned(),
                health: DeviceHealth {
                    presence: PresenceState::Online,
                    media: MediaState::Recovering,
                    worker_ready: true,
                    service_ready: true,
                },
                quality_tier: Some(QualityTier::Medium),
                thumbnail_available: true,
                interactive_active: false,
            })
            .unwrap();
        classroom
    }

    fn monitoring() -> TeacherMonitoringCoordinator {
        let mut monitoring = TeacherMonitoringCoordinator::new(
            MonitoringSchedulerConfig {
                max_sources: 4,
                max_actions_per_tick: 4,
            },
            MonitoringFanInConfig {
                max_sources: 4,
                max_updates_per_drain: 4,
            },
        )
        .unwrap();
        monitoring
            .add_source(
                MonitoringSourceId(7),
                MonitoringProfile::for_thumbnail_at_fps(320, 180, 3).unwrap(),
                MonitoringPriority::Visible,
            )
            .unwrap();
        monitoring
    }

    fn interactive_offer() -> StreamOffer {
        StreamOffer {
            stream_id: 11,
            kind: StreamKind::Interactive as i32,
            transport: MediaTransport::UdpUnicast as i32,
            profile: Some(VideoProfile {
                width: 1280,
                height: 720,
                fps: 30,
                bitrate_kbps: 2_500,
                codec: VideoCodec::H264 as i32,
            }),
            transport_parameters: vec![1, 0x23, 0x28],
        }
    }

    fn capabilities() -> BTreeSet<Capability> {
        BTreeSet::from([Capability::UdpUnicast])
    }

    #[test]
    fn shell_defaults_to_classroom_without_engine_action() {
        let shell = TeacherUiShellState::default();
        assert_eq!(shell.active_section(), TeacherUiSection::Classroom);
    }

    #[test]
    fn navigation_is_shell_local_and_emits_no_engine_action() {
        let mut shell = TeacherUiShellState::default();
        assert_eq!(
            shell.handle(TeacherUiMessage::Navigate(TeacherUiSection::Diagnostics)),
            None
        );
        assert_eq!(shell.active_section(), TeacherUiSection::Diagnostics);
    }

    #[test]
    fn selection_action_delegates_to_authoritative_classroom_model() {
        let mut shell = TeacherUiShellState::default();
        let mut classroom = classroom();

        let action = shell
            .handle(TeacherUiMessage::SelectDevice(Some(MonitoringSourceId(7))))
            .expect("selection action");
        assert_eq!(action.apply_to_classroom(&mut classroom), Ok(()));
        assert_eq!(classroom.selected(), Some(MonitoringSourceId(7)));

        let unknown = shell
            .handle(TeacherUiMessage::SelectDevice(Some(MonitoringSourceId(99))))
            .expect("selection action");
        assert_eq!(
            unknown.apply_to_classroom(&mut classroom),
            Err(TeacherUiClassroomActionError::Classroom(
                ClassroomViewError::UnknownDevice
            ))
        );
        assert_eq!(classroom.selected(), Some(MonitoringSourceId(7)));

        let clear = shell
            .handle(TeacherUiMessage::SelectDevice(None))
            .expect("selection action");
        assert_eq!(clear.apply_to_classroom(&mut classroom), Ok(()));
        assert_eq!(classroom.selected(), None);
    }

    #[test]
    fn focus_request_captures_source_and_delegates_to_existing_focus_contract() {
        let mut shell = TeacherUiShellState::default();
        let mut classroom = classroom();
        classroom.select(Some(MonitoringSourceId(7))).unwrap();
        let mut monitoring = monitoring();

        let action = shell
            .handle(TeacherUiMessage::RequestInteractive(MonitoringSourceId(7)))
            .expect("focus action");
        let TeacherUiAction::Focus(focus_action) = action else {
            panic!("expected focus action");
        };
        assert_eq!(
            focus_action,
            TeacherFocusUiAction::RequestInteractive {
                source_id: MonitoringSourceId(7)
            }
        );

        let offer = interactive_offer();
        let capabilities = capabilities();
        apply_focus_ui_action(
            focus_action,
            &classroom,
            &mut monitoring,
            Some((&offer, &capabilities)),
        )
        .unwrap();

        assert!(monitoring.poll(0).unwrap().iter().any(|action| {
            matches!(
                action,
                TeacherMonitoringAction::StartInteractive { source_id, .. }
                    if *source_id == MonitoringSourceId(7)
            )
        }));
    }

    #[test]
    fn interactive_focus_request_without_engine_context_fails_closed() {
        let mut classroom = classroom();
        classroom.select(Some(MonitoringSourceId(7))).unwrap();
        let mut monitoring = monitoring();
        let action = TeacherFocusUiAction::RequestInteractive {
            source_id: MonitoringSourceId(7),
        };

        assert_eq!(
            apply_focus_ui_action(action, &classroom, &mut monitoring, None),
            Err(TeacherFocusUiActionError::MissingInteractiveContext)
        );
        assert!(
            monitoring.poll(0).unwrap().iter().all(|action| {
                !matches!(action, TeacherMonitoringAction::StartInteractive { .. })
            })
        );
    }

    #[test]
    fn stale_focus_action_fails_closed_after_selection_changes() {
        let mut classroom = classroom();
        classroom.select(Some(MonitoringSourceId(7))).unwrap();
        let mut monitoring = monitoring();
        let action = TeacherFocusUiAction::ResumeThumbnail {
            source_id: MonitoringSourceId(7),
        };

        classroom.select(None).unwrap();
        assert_eq!(
            apply_focus_ui_action(action, &classroom, &mut monitoring, None),
            Err(TeacherFocusUiActionError::SelectionChanged {
                expected: MonitoringSourceId(7),
                selected: None,
            })
        );
    }

    #[test]
    fn focus_resume_message_emits_typed_action() {
        let mut shell = TeacherUiShellState::default();
        assert_eq!(
            shell.handle(TeacherUiMessage::ResumeThumbnail(MonitoringSourceId(7))),
            Some(TeacherUiAction::Focus(
                TeacherFocusUiAction::ResumeThumbnail {
                    source_id: MonitoringSourceId(7)
                }
            ))
        );
    }

    #[test]
    fn presentation_messages_emit_typed_actions_and_capture_stop_binding() {
        let mut shell = TeacherUiShellState::default();
        assert_eq!(
            shell.handle(TeacherUiMessage::StartPresentation),
            Some(TeacherUiAction::Presentation(
                TeacherPresentationUiAction::Start
            ))
        );

        let binding = PresentationBindingView {
            presentation_id: 700,
            stream_id: 800,
            epoch: 4,
        };
        assert_eq!(
            shell.handle(TeacherUiMessage::StopPresentation(binding)),
            Some(TeacherUiAction::Presentation(
                TeacherPresentationUiAction::Stop { binding }
            ))
        );
    }

    #[cfg(windows)]
    #[test]
    fn presentation_start_without_engine_context_fails_closed() {
        let mut lifecycle = crate::TeacherVideoEngineLifecycle::default();

        assert!(matches!(
            apply_presentation_ui_action(TeacherPresentationUiAction::Start, &mut lifecycle, None),
            Err(TeacherPresentationUiActionError::MissingStartContext)
        ));
        assert_eq!(lifecycle.active_binding(), None);
    }

    #[cfg(windows)]
    #[test]
    fn stale_presentation_stop_fails_closed_without_stopping_another_binding() {
        let mut lifecycle = crate::TeacherVideoEngineLifecycle::default();
        let binding = PresentationBindingView {
            presentation_id: 700,
            stream_id: 800,
            epoch: 4,
        };

        assert!(matches!(
            apply_presentation_ui_action(
                TeacherPresentationUiAction::Stop { binding },
                &mut lifecycle,
                None
            ),
            Err(TeacherPresentationUiActionError::BindingChanged {
                expected,
                active: None,
            }) if expected == binding
        ));
    }

    #[test]
    fn diagnostics_message_emits_typed_source_bound_action() {
        let mut shell = TeacherUiShellState::default();
        let request = TroubleshootingOverrideRequest::Automatic;

        assert_eq!(
            shell.handle(TeacherUiMessage::RequestTroubleshootingOverride {
                source_id: MonitoringSourceId(7),
                request,
            }),
            Some(TeacherUiAction::Diagnostics(TeacherDiagnosticsUiAction {
                source_id: MonitoringSourceId(7),
                request,
            }))
        );
    }

    #[test]
    fn stale_diagnostics_action_fails_closed_after_selection_changes() {
        let mut classroom = classroom();
        classroom.select(Some(MonitoringSourceId(7))).unwrap();
        let diagnostics = TeacherDeviceDiagnosticsViewModel::new(
            crate::device_diagnostics::DeviceDiagnosticsConfig::default(),
        )
        .unwrap();
        let action = TeacherDiagnosticsUiAction {
            source_id: MonitoringSourceId(7),
            request: TroubleshootingOverrideRequest::Automatic,
        };

        classroom.select(None).unwrap();
        assert_eq!(
            apply_diagnostics_ui_action(
                action,
                &classroom,
                &diagnostics,
                TransportTopologyEvidence::default(),
            ),
            Err(TeacherDiagnosticsUiActionError::SelectionChanged {
                expected: MonitoringSourceId(7),
                selected: None,
            })
        );
    }

    #[test]
    fn diagnostics_action_revalidates_open_physical_gate_at_apply_time() {
        let mut classroom = classroom();
        classroom.select(Some(MonitoringSourceId(7))).unwrap();
        let diagnostics = TeacherDeviceDiagnosticsViewModel::new(
            crate::device_diagnostics::DeviceDiagnosticsConfig::default(),
        )
        .unwrap();
        let path = MediaPath {
            transport: CoreMediaTransport::UdpUnicast,
            topology: MediaTopology::Direct,
        };
        let action = TeacherDiagnosticsUiAction {
            source_id: MonitoringSourceId(7),
            request: TroubleshootingOverrideRequest::MediaPath(path),
        };

        assert_eq!(
            apply_diagnostics_ui_action(
                action,
                &classroom,
                &diagnostics,
                TransportTopologyEvidence::default(),
            ),
            Err(TeacherDiagnosticsUiActionError::Validation(
                TroubleshootingOverrideError::BlockedMediaPath {
                    gate: PhysicalPathGate::Phase4UdpUnicast,
                    evidence: PhysicalGateStatus::Pending,
                }
            ))
        );
    }

    #[test]
    fn status_labels_keep_control_presence_independent_from_media_health() {
        let classroom = classroom();
        let row = classroom.rows().remove(0);

        assert_eq!(presence_label(row.health.presence), "Online");
        assert_eq!(media_label(row.health.media), "Recovering");
        assert_eq!(quality_label(row.quality_tier), "Medium");
    }
}
