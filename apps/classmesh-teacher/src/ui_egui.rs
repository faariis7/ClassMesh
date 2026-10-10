use eframe::egui;

use crate::classroom_grid::{MonitoringGridViewConfig, TeacherMonitoringGridViewModel};
use crate::classroom_view::{ClassroomViewConfig, TeacherClassroomViewModel};
use crate::device_diagnostics::{
    DeviceDiagnosticsConfig, DeviceDiagnosticsError, DeviceDiagnosticsSnapshot,
    DeviceDiagnosticsView, TeacherDeviceDiagnosticsViewModel,
};
use crate::presentation_view::{
    PresentationRuntimeSnapshot, PresentationViewState, TeacherPresentationViewModel,
};
use crate::ui_actions::{
    TeacherInteractionDraft, reset_teacher_interaction_draft, show_device_actions,
};
use crate::ui_classroom::show_classroom;
use crate::ui_diagnostics::{DiagnosticsOverrideDraft, show_diagnostics};
use crate::ui_file_transfer::{
    TeacherFilePullContext, TeacherStagedFileCandidate, prepare_file_pull_action,
    staged_file_candidate_ready, validate_file_pull_action,
};
use crate::ui_focus::show_focus;
use crate::ui_presentation::show_presentation;
use crate::ui_shell::{
    TeacherInteractionUiContext, TeacherInteractionUiRequest, TeacherUiAction, TeacherUiMessage,
    TeacherUiSection, TeacherUiShellState, prepare_teacher_interaction_ui_action,
    validate_teacher_interaction_ui_action,
};

const APP_TITLE: &str = "ClassMesh Teacher";
const DEFAULT_WINDOW_SIZE: [f32; 2] = [800.0, 600.0];
const MIN_WINDOW_SIZE: [f32; 2] = [600.0, 420.0];

#[derive(Debug)]
pub struct TeacherEguiShell {
    shell: TeacherUiShellState,
    classroom: TeacherClassroomViewModel,
    monitoring: TeacherMonitoringGridViewModel,
    presentation: PresentationViewState,
    diagnostics_model: TeacherDeviceDiagnosticsViewModel,
    diagnostics: Option<DeviceDiagnosticsView>,
    diagnostics_draft: DiagnosticsOverrideDraft,
    teacher_interaction_context: Option<TeacherInteractionUiContext>,
    file_pull_context: Option<TeacherFilePullContext>,
    staged_file_candidate: Option<TeacherStagedFileCandidate>,
    teacher_interaction_draft: TeacherInteractionDraft,
    pending_action: Option<TeacherUiAction>,
}

impl Default for TeacherEguiShell {
    fn default() -> Self {
        Self {
            shell: TeacherUiShellState::default(),
            classroom: TeacherClassroomViewModel::new(ClassroomViewConfig::default())
                .expect("default classroom view configuration is valid"),
            monitoring: TeacherMonitoringGridViewModel::new(MonitoringGridViewConfig::default())
                .expect("default monitoring grid configuration is valid"),
            presentation: TeacherPresentationViewModel::state(
                PresentationRuntimeSnapshot::default(),
            ),
            diagnostics_model: TeacherDeviceDiagnosticsViewModel::new(
                DeviceDiagnosticsConfig::default(),
            )
            .expect("default diagnostics view configuration is valid"),
            diagnostics: None,
            diagnostics_draft: DiagnosticsOverrideDraft::default(),
            teacher_interaction_context: None,
            file_pull_context: None,
            staged_file_candidate: None,
            teacher_interaction_draft: TeacherInteractionDraft::default(),
            pending_action: None,
        }
    }
}

impl TeacherEguiShell {
    #[must_use]
    pub fn new(
        classroom: TeacherClassroomViewModel,
        monitoring: TeacherMonitoringGridViewModel,
    ) -> Self {
        Self {
            shell: TeacherUiShellState::default(),
            classroom,
            monitoring,
            presentation: TeacherPresentationViewModel::state(
                PresentationRuntimeSnapshot::default(),
            ),
            diagnostics_model: TeacherDeviceDiagnosticsViewModel::new(
                DeviceDiagnosticsConfig::default(),
            )
            .expect("default diagnostics view configuration is valid"),
            diagnostics: None,
            diagnostics_draft: DiagnosticsOverrideDraft::default(),
            teacher_interaction_context: None,
            file_pull_context: None,
            staged_file_candidate: None,
            teacher_interaction_draft: TeacherInteractionDraft::default(),
            pending_action: None,
        }
    }

    pub fn set_teacher_interaction_context(&mut self, context: TeacherInteractionUiContext) {
        if self
            .teacher_interaction_context
            .as_ref()
            .map(|current| (current.source_id, current.control_session_id))
            != Some((context.source_id, context.control_session_id))
        {
            reset_teacher_interaction_draft(&mut self.teacher_interaction_draft);
        }
        self.teacher_interaction_context = Some(context);
    }

    pub fn clear_teacher_interaction_context(&mut self) {
        self.teacher_interaction_context = None;
        reset_teacher_interaction_draft(&mut self.teacher_interaction_draft);
    }

    pub fn set_file_pull_context(&mut self, context: TeacherFilePullContext) {
        if self.file_pull_context.as_ref().is_some_and(|current| {
            (current.source_id, current.control_session_id)
                != (context.source_id, context.control_session_id)
        }) || !classmesh_protocol::file_transfer::file_transfer_pull_available(
            context.version,
            &context.capabilities,
        ) {
            self.staged_file_candidate = None;
        }
        self.file_pull_context = Some(context);
    }

    pub fn clear_file_pull_context(&mut self) {
        self.file_pull_context = None;
        self.staged_file_candidate = None;
    }

    pub fn set_staged_file_candidate(&mut self, candidate: TeacherStagedFileCandidate) {
        self.staged_file_candidate = Some(candidate);
    }

    pub fn clear_staged_file_candidate(&mut self) {
        self.staged_file_candidate = None;
    }

    pub fn set_presentation_snapshot(&mut self, snapshot: PresentationRuntimeSnapshot) {
        self.presentation = TeacherPresentationViewModel::state(snapshot);
    }

    pub fn update_diagnostics(
        &mut self,
        snapshot: DeviceDiagnosticsSnapshot<'_>,
    ) -> Result<(), DeviceDiagnosticsError> {
        let view = self.diagnostics_model.project(snapshot)?;
        if self.diagnostics.as_ref().map(|current| current.source_id) != Some(view.source_id) {
            self.diagnostics_draft = DiagnosticsOverrideDraft::default();
        }
        self.diagnostics = Some(view);
        Ok(())
    }

    pub fn clear_diagnostics(&mut self) {
        self.diagnostics = None;
        self.diagnostics_draft = DiagnosticsOverrideDraft::default();
    }

    #[must_use]
    pub fn take_pending_action(&mut self) -> Option<TeacherUiAction> {
        let action = self.pending_action.take()?;
        if let TeacherUiAction::TeacherInteraction(interaction) = &action {
            validate_teacher_interaction_ui_action(
                interaction,
                &self.classroom,
                self.teacher_interaction_context.as_ref(),
            )
            .ok()?;
        }
        if let TeacherUiAction::FilePull(pull) = &action {
            validate_file_pull_action(
                pull,
                self.classroom.selected(),
                self.file_pull_context.as_ref(),
            )
            .ok()?;
        }
        Some(action)
    }

    fn queue_action(&mut self, action: TeacherUiAction) {
        if self.pending_action.is_none() {
            self.pending_action = Some(action);
        }
    }

    fn queue_teacher_interaction_request(&mut self, request: TeacherInteractionUiRequest) {
        let Some(source_id) = self.classroom.selected() else {
            return;
        };
        let Ok(action) = prepare_teacher_interaction_ui_action(
            source_id,
            request,
            &self.classroom,
            self.teacher_interaction_context.as_ref(),
        ) else {
            return;
        };
        self.queue_action(TeacherUiAction::TeacherInteraction(action));
    }

    pub fn queue_file_pull_request(&mut self, transfer_id: [u8; 16], source_id: [u8; 16]) {
        let Some(selected) = self.classroom.selected() else {
            return;
        };
        let Ok(action) = prepare_file_pull_action(
            selected,
            transfer_id,
            source_id,
            self.classroom.selected(),
            self.file_pull_context.as_ref(),
        ) else {
            return;
        };
        self.queue_action(TeacherUiAction::FilePull(action));
    }

    fn navigate(&mut self, section: TeacherUiSection) {
        let _ = self.shell.handle(TeacherUiMessage::Navigate(section));
    }

    fn navigation(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            for (section, label) in [
                (TeacherUiSection::Classroom, "Classroom"),
                (TeacherUiSection::Focus, "Focus"),
                (TeacherUiSection::Presentation, "Presentation"),
                (TeacherUiSection::DeviceActions, "Device Actions"),
                (TeacherUiSection::Diagnostics, "Diagnostics"),
            ] {
                let selected = self.shell.active_section() == section;
                if ui.selectable_label(selected, label).clicked() {
                    self.navigate(section);
                }
            }
        });
    }

    fn section_body(&mut self, ui: &mut egui::Ui) {
        match self.shell.active_section() {
            TeacherUiSection::Classroom => {
                show_classroom(ui, &mut self.shell, &mut self.classroom, &self.monitoring)
            }
            TeacherUiSection::Focus => {
                if let Some(message) =
                    show_focus(ui, &self.classroom, self.pending_action.is_some())
                {
                    if let Some(action) = self.shell.handle(message) {
                        self.queue_action(action);
                    }
                }
            }
            TeacherUiSection::Presentation => {
                if let Some(message) =
                    show_presentation(ui, self.presentation, self.pending_action.is_some())
                {
                    if let Some(action) = self.shell.handle(message) {
                        self.queue_action(action);
                    }
                }
            }
            TeacherUiSection::DeviceActions => {
                if let Some(request) = show_device_actions(
                    ui,
                    self.classroom.selected(),
                    self.teacher_interaction_context.as_ref(),
                    &mut self.teacher_interaction_draft,
                    self.pending_action.is_some(),
                ) {
                    self.queue_teacher_interaction_request(request);
                }
                ui.separator();
                ui.strong("Receive staged file");
                let ready = self.staged_file_candidate.is_some_and(|candidate| {
                    staged_file_candidate_ready(
                        candidate,
                        self.classroom.selected(),
                        self.file_pull_context.as_ref(),
                    )
                });
                if !ready {
                    ui.small("No authorized staged file is available for the selected device.");
                }
                if ui
                    .add_enabled(
                        ready && self.pending_action.is_none(),
                        egui::Button::new("Receive staged file"),
                    )
                    .clicked()
                {
                    if let Some(candidate) = self.staged_file_candidate {
                        self.queue_file_pull_request(
                            candidate.transfer_id,
                            candidate.opaque_source_id,
                        );
                    }
                }
            }
            TeacherUiSection::Diagnostics => {
                if let Some(message) = show_diagnostics(
                    ui,
                    self.classroom.selected(),
                    self.diagnostics.as_ref(),
                    &mut self.diagnostics_draft,
                    self.pending_action.is_some(),
                ) {
                    if let Some(action) = self.shell.handle(message) {
                        self.queue_action(action);
                    }
                }
            }
        }
    }
}

impl eframe::App for TeacherEguiShell {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("classmesh_teacher_navigation").show(ctx, |ui| {
            self.navigation(ui);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            self.section_body(ui);
        });
    }
}

fn teacher_native_options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(DEFAULT_WINDOW_SIZE)
            .with_min_inner_size(MIN_WINDOW_SIZE)
            .with_clamp_size_to_monitor_size(true),
        ..Default::default()
    }
}

pub fn run_teacher_ui() -> eframe::Result<()> {
    eframe::run_native(
        APP_TITLE,
        teacher_native_options(),
        Box::new(|_creation_context| Ok(Box::<TeacherEguiShell>::default())),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use classmesh_core::MediaState;
    use classmesh_core::presence::{DeviceHealth, PresenceState};
    use classmesh_core::transport_topology::TransportTopologyEvidence;
    use classmesh_protocol::Capability;
    use classmesh_protocol::control_wire::TeacherInteractionKind;
    use classmesh_video::monitoring_scheduler::MonitoringSourceId;

    use crate::classroom_view::{ClassroomDeviceRow, ClassroomDeviceSnapshot};
    use crate::device_diagnostics::{DEFAULT_MAX_DIAGNOSTIC_CODES, DeviceDiagnosticsError};
    use crate::ui_shell::TeacherFocusUiAction;

    use super::*;

    #[test]
    fn teacher_ui_viewport_has_explicit_default_and_minimum_size() {
        let options = teacher_native_options();

        assert_eq!(
            options.viewport.inner_size,
            Some(egui::vec2(DEFAULT_WINDOW_SIZE[0], DEFAULT_WINDOW_SIZE[1]))
        );
        assert_eq!(
            options.viewport.min_inner_size,
            Some(egui::vec2(MIN_WINDOW_SIZE[0], MIN_WINDOW_SIZE[1]))
        );
        assert_eq!(options.viewport.clamp_size_to_monitor_size, Some(true));
    }

    #[test]
    fn presentation_snapshot_is_projected_through_existing_11d_view_model() {
        let mut app = TeacherEguiShell::default();
        app.set_presentation_snapshot(PresentationRuntimeSnapshot {
            binding: Some(crate::presentation_view::PresentationBindingView {
                presentation_id: 700,
                stream_id: 800,
                epoch: 4,
            }),
            profile: Some(crate::presentation_view::PresentationProfileView {
                width: 1280,
                height: 720,
                fps: 30,
                bitrate_bps: 2_500_000,
            }),
            metrics: crate::presentation_view::PresentationMetricsView {
                encoded_frames: 12,
                ..crate::presentation_view::PresentationMetricsView::default()
            },
        });

        assert_eq!(
            app.presentation.media_state,
            classmesh_core::MediaState::Streaming
        );
        assert_eq!(app.presentation.binding.unwrap().presentation_id, 700);
        assert_eq!(app.presentation.metrics.encoded_frames, 12);
    }

    #[test]
    fn diagnostics_projection_enforces_11e_code_bound_before_storage() {
        let mut app = TeacherEguiShell::default();
        let row = ClassroomDeviceRow {
            source_id: MonitoringSourceId(7),
            display_name: "Student 07".into(),
            health: DeviceHealth {
                presence: PresenceState::Online,
                media: MediaState::Recovering,
                worker_ready: true,
                service_ready: true,
            },
            quality_tier: None,
            thumbnail_available: true,
            interactive_active: false,
            selected: true,
        };
        let codes = ["diagnostic.code"; DEFAULT_MAX_DIAGNOSTIC_CODES + 1];

        assert_eq!(
            app.update_diagnostics(DeviceDiagnosticsSnapshot {
                device: &row,
                quality_sample: None,
                active_path: None,
                topology_evidence: TransportTopologyEvidence::default(),
                diagnostic_codes: &codes,
            }),
            Err(DeviceDiagnosticsError::TooManyDiagnosticCodes)
        );
        assert!(app.diagnostics.is_none());
    }

    fn select_test_device(app: &mut TeacherEguiShell) {
        app.classroom
            .upsert(ClassroomDeviceSnapshot {
                source_id: MonitoringSourceId(7),
                display_name: "Student 07".to_owned(),
                health: DeviceHealth {
                    presence: PresenceState::Online,
                    media: MediaState::Idle,
                    worker_ready: true,
                    service_ready: true,
                },
                quality_tier: None,
                thumbnail_available: true,
                interactive_active: false,
            })
            .unwrap();
        app.classroom.select(Some(MonitoringSourceId(7))).unwrap();
    }

    fn interaction_context(capabilities: BTreeSet<Capability>) -> TeacherInteractionUiContext {
        TeacherInteractionUiContext {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            version: classmesh_protocol::PROTOCOL_VERSION,
            capabilities,
        }
    }

    #[test]
    fn control_session_change_resets_teacher_interaction_draft_and_stales_pending_action() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::TeacherMessage,
        ])));
        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::Message(
            "hello".to_owned(),
        ));

        let mut reconnected = interaction_context(BTreeSet::from([Capability::TeacherMessage]));
        reconnected.control_session_id = 78;
        app.set_teacher_interaction_context(reconnected);

        assert_eq!(app.take_pending_action(), None);
    }

    #[test]
    fn device_action_queue_builds_only_valid_source_bound_protocol_action() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::TeacherMessage,
        ])));

        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::Message(
            "Class starts now.".to_owned(),
        ));

        let Some(TeacherUiAction::TeacherInteraction(action)) = app.take_pending_action() else {
            panic!("expected Teacher interaction action");
        };
        assert_eq!(action.source_id, MonitoringSourceId(7));
        assert_eq!(
            classmesh_protocol::teacher_interaction::validate_request(&action.request),
            Ok(TeacherInteractionKind::Message)
        );
    }

    #[test]
    fn device_action_queue_fails_closed_for_missing_or_stale_context() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);

        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::Message(
            "hello".to_owned(),
        ));
        assert_eq!(app.take_pending_action(), None);

        app.set_teacher_interaction_context(TeacherInteractionUiContext {
            source_id: MonitoringSourceId(8),
            control_session_id: 88,
            version: classmesh_protocol::PROTOCOL_VERSION,
            capabilities: BTreeSet::from([Capability::TeacherMessage]),
        });
        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::Message(
            "hello".to_owned(),
        ));
        assert_eq!(app.take_pending_action(), None);
    }

    #[test]
    fn device_action_queue_respects_exact_open_target_capability() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::TeacherMessage,
        ])));

        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::App(
            classmesh_protocol::control_wire::AppIdentity::Calculator,
        ));
        assert_eq!(app.take_pending_action(), None);

        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::OpenTarget,
        ])));
        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::App(
            classmesh_protocol::control_wire::AppIdentity::Calculator,
        ));
        assert!(matches!(
            app.take_pending_action(),
            Some(TeacherUiAction::TeacherInteraction(_))
        ));
    }

    #[test]
    fn queued_teacher_interaction_is_revalidated_at_dispatch_handoff() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::TeacherMessage,
        ])));
        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::Message(
            "hello".to_owned(),
        ));

        app.classroom.select(None).unwrap();
        assert_eq!(app.take_pending_action(), None);
    }

    #[test]
    fn queued_teacher_interaction_is_dropped_if_capability_changes_before_handoff() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::TeacherMessage,
        ])));
        app.queue_teacher_interaction_request(TeacherInteractionUiRequest::Message(
            "hello".to_owned(),
        ));

        app.set_teacher_interaction_context(interaction_context(BTreeSet::from([
            Capability::OpenTarget,
        ])));
        assert_eq!(app.take_pending_action(), None);
    }

    #[test]
    fn file_pull_handoff_rechecks_exact_selection_session_and_capability() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let context = TeacherFilePullContext {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            version: classmesh_protocol::PROTOCOL_VERSION,
            capabilities: BTreeSet::from([Capability::FileTransfer]),
        };
        app.set_file_pull_context(context.clone());
        app.queue_file_pull_request([1; 16], [2; 16]);
        app.set_file_pull_context(TeacherFilePullContext {
            control_session_id: 78,
            ..context.clone()
        });
        assert_eq!(app.take_pending_action(), None);

        app.set_file_pull_context(context.clone());
        app.queue_file_pull_request([1; 16], [2; 16]);
        app.classroom.select(None).unwrap();
        assert_eq!(app.take_pending_action(), None);

        app.classroom.select(Some(MonitoringSourceId(7))).unwrap();
        app.set_file_pull_context(context);
        app.queue_file_pull_request([1; 16], [2; 16]);
        assert!(matches!(
            app.take_pending_action(),
            Some(TeacherUiAction::FilePull(_))
        ));
    }

    #[test]
    fn reconnect_discards_staged_candidate_and_never_reactivates_it() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let context = TeacherFilePullContext {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            version: classmesh_protocol::PROTOCOL_VERSION,
            capabilities: BTreeSet::from([Capability::FileTransfer]),
        };
        let candidate = TeacherStagedFileCandidate {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            transfer_id: [1; 16],
            opaque_source_id: [2; 16],
        };
        app.set_file_pull_context(context.clone());
        app.set_staged_file_candidate(candidate);
        assert_eq!(app.staged_file_candidate, Some(candidate));
        app.set_file_pull_context(TeacherFilePullContext {
            control_session_id: 78,
            ..context.clone()
        });
        assert_eq!(app.staged_file_candidate, None);
        app.set_file_pull_context(context);
        assert_eq!(app.staged_file_candidate, None);
    }

    #[test]
    fn revoked_file_transfer_capability_discards_staged_candidate() {
        let mut app = TeacherEguiShell::default();
        select_test_device(&mut app);
        let context = TeacherFilePullContext {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            version: classmesh_protocol::PROTOCOL_VERSION,
            capabilities: BTreeSet::from([Capability::FileTransfer]),
        };
        let candidate = TeacherStagedFileCandidate {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            transfer_id: [1; 16],
            opaque_source_id: [2; 16],
        };
        app.set_file_pull_context(context.clone());
        app.set_staged_file_candidate(candidate);
        let mut revoked = context.clone();
        revoked.capabilities.clear();
        app.set_file_pull_context(revoked);
        assert_eq!(app.staged_file_candidate, None);
        app.set_file_pull_context(context);
        assert_eq!(app.staged_file_candidate, None);
    }

    #[test]
    fn pending_action_slot_is_bounded_and_preserves_oldest_action() {
        let mut app = TeacherEguiShell::default();
        let first = TeacherUiAction::SelectDevice(Some(MonitoringSourceId(7)));
        let second = TeacherUiAction::Focus(TeacherFocusUiAction::RequestInteractive {
            source_id: MonitoringSourceId(7),
        });

        app.queue_action(first.clone());
        app.queue_action(second);

        assert_eq!(app.take_pending_action(), Some(first));
        assert_eq!(app.take_pending_action(), None);
    }
}
