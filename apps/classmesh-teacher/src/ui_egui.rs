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
use crate::ui_classroom::show_classroom;
use crate::ui_diagnostics::{DiagnosticsOverrideDraft, show_diagnostics};
use crate::ui_focus::show_focus;
use crate::ui_presentation::show_presentation;
use crate::ui_shell::{TeacherUiAction, TeacherUiMessage, TeacherUiSection, TeacherUiShellState};

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
            pending_action: None,
        }
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
        self.pending_action.take()
    }

    fn queue_action(&mut self, action: TeacherUiAction) {
        if self.pending_action.is_none() {
            self.pending_action = Some(action);
        }
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
    use classmesh_core::MediaState;
    use classmesh_core::presence::{DeviceHealth, PresenceState};
    use classmesh_core::transport_topology::TransportTopologyEvidence;
    use classmesh_video::monitoring_scheduler::MonitoringSourceId;

    use crate::classroom_view::ClassroomDeviceRow;
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

    #[test]
    fn pending_action_slot_is_bounded_and_preserves_oldest_action() {
        let mut app = TeacherEguiShell::default();
        let first = TeacherUiAction::SelectDevice(Some(MonitoringSourceId(7)));
        let second = TeacherUiAction::Focus(TeacherFocusUiAction::RequestInteractive {
            source_id: MonitoringSourceId(7),
        });

        app.queue_action(first);
        app.queue_action(second);

        assert_eq!(app.take_pending_action(), Some(first));
        assert_eq!(app.take_pending_action(), None);
    }
}
