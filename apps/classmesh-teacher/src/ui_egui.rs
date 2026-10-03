use eframe::egui;

use crate::ui_shell::{TeacherUiMessage, TeacherUiSection, TeacherUiShellState};

const APP_TITLE: &str = "ClassMesh Teacher";

#[derive(Debug, Default)]
pub struct TeacherEguiShell {
    shell: TeacherUiShellState,
}

impl TeacherEguiShell {
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

    fn section_body(&self, ui: &mut egui::Ui) {
        let (heading, description) = match self.shell.active_section() {
            TeacherUiSection::Classroom => (
                "Classroom",
                "Classroom and monitoring projections are connected in Phase 11F2.",
            ),
            TeacherUiSection::Focus => (
                "Focus",
                "Interactive focus actions remain owned by the existing Phase 11C contracts.",
            ),
            TeacherUiSection::Presentation => (
                "Presentation",
                "Presentation lifecycle actions remain owned by the existing Phase 11D contracts.",
            ),
            TeacherUiSection::Diagnostics => (
                "Diagnostics",
                "Diagnostics and typed overrides remain owned by the existing Phase 11E contracts.",
            ),
        };

        ui.heading(heading);
        ui.label(description);
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

pub fn run_teacher_ui() -> eframe::Result<()> {
    eframe::run_native(
        APP_TITLE,
        eframe::NativeOptions::default(),
        Box::new(|_creation_context| Ok(Box::<TeacherEguiShell>::default())),
    )
}
