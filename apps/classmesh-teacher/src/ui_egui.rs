use eframe::egui;

use crate::classroom_grid::{MonitoringGridViewConfig, TeacherMonitoringGridViewModel};
use crate::classroom_view::{ClassroomViewConfig, TeacherClassroomViewModel};
use crate::ui_classroom::show_classroom;
use crate::ui_shell::{TeacherUiMessage, TeacherUiSection, TeacherUiShellState};

const APP_TITLE: &str = "ClassMesh Teacher";

#[derive(Debug)]
pub struct TeacherEguiShell {
    shell: TeacherUiShellState,
    classroom: TeacherClassroomViewModel,
    monitoring: TeacherMonitoringGridViewModel,
}

impl Default for TeacherEguiShell {
    fn default() -> Self {
        Self {
            shell: TeacherUiShellState::default(),
            classroom: TeacherClassroomViewModel::new(ClassroomViewConfig::default())
                .expect("default classroom view configuration is valid"),
            monitoring: TeacherMonitoringGridViewModel::new(MonitoringGridViewConfig::default())
                .expect("default monitoring grid configuration is valid"),
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
            TeacherUiSection::Classroom => show_classroom(
                ui,
                &mut self.shell,
                &mut self.classroom,
                &self.monitoring,
            ),
            TeacherUiSection::Focus => placeholder(
                ui,
                "Focus",
                "Interactive focus actions remain owned by the existing Phase 11C contracts.",
            ),
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

pub fn run_teacher_ui() -> eframe::Result<()> {
    eframe::run_native(
        APP_TITLE,
        eframe::NativeOptions::default(),
        Box::new(|_creation_context| Ok(Box::<TeacherEguiShell>::default())),
    )
}
