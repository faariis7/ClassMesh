use eframe::egui;

use crate::classroom_grid::{MonitoringGridViewConfig, TeacherMonitoringGridViewModel};
use crate::classroom_view::{ClassroomViewConfig, TeacherClassroomViewModel};
use crate::ui_classroom::show_classroom;
use crate::ui_focus::show_focus;
use crate::ui_shell::{TeacherUiAction, TeacherUiMessage, TeacherUiSection, TeacherUiShellState};

const APP_TITLE: &str = "ClassMesh Teacher";

#[derive(Debug)]
pub struct TeacherEguiShell {
    shell: TeacherUiShellState,
    classroom: TeacherClassroomViewModel,
    monitoring: TeacherMonitoringGridViewModel,
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
            pending_action: None,
        }
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
        ui.horizontal(|ui| {
            ui.heading(APP_TITLE);
            ui.separator();

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
            TeacherUiSection::Presentation => placeholder(
                ui,
                "Presentation",
                "Presentation lifecycle actions remain owned by the existing Phase 11D contracts.",
            ),
            TeacherUiSection::Diagnostics => placeholder(
                ui,
                "Diagnostics",
                "Diagnostics and typed overrides remain owned by the existing Phase 11E contracts.",
            ),
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

fn placeholder(ui: &mut egui::Ui, heading: &str, description: &str) {
    ui.heading(heading);
    ui.label(description);
}

#[cfg(test)]
mod tests {
    use classmesh_video::monitoring_scheduler::MonitoringSourceId;

    use crate::ui_shell::TeacherFocusUiAction;

    use super::*;

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

pub fn run_teacher_ui() -> eframe::Result<()> {
    eframe::run_native(
        APP_TITLE,
        eframe::NativeOptions::default(),
        Box::new(|_creation_context| Ok(Box::<TeacherEguiShell>::default())),
    )
}
