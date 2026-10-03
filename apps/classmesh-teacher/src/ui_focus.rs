use eframe::egui;

use crate::classroom_view::TeacherClassroomViewModel;
use crate::focus_view::TeacherFocusViewModel;
use crate::ui_shell::{TeacherUiMessage, media_label, presence_label, quality_label};

pub fn show_focus(
    ui: &mut egui::Ui,
    classroom: &TeacherClassroomViewModel,
    action_pending: bool,
) -> Option<TeacherUiMessage> {
    ui.heading("Focus");

    let Some(focused) = TeacherFocusViewModel::focused(classroom) else {
        ui.label("Select a classroom device before starting an interactive session.");
        return None;
    };

    ui.strong(&focused.display_name);
    ui.label(format!(
        "Control: {} · Media: {} · Quality: {}",
        presence_label(focused.health.presence),
        media_label(focused.health.media),
        quality_label(focused.quality_tier),
    ));

    if focused.thumbnail_available {
        ui.small("Monitoring thumbnail available");
    } else {
        ui.small("Monitoring thumbnail unavailable");
    }

    ui.separator();

    let (label, message) = if focused.interactive_active {
        (
            "Return to monitoring",
            TeacherUiMessage::ResumeThumbnail(focused.source_id),
        )
    } else {
        (
            "Start interactive control",
            TeacherUiMessage::RequestInteractive(focused.source_id),
        )
    };

    if ui
        .add_enabled(!action_pending, egui::Button::new(label))
        .clicked()
    {
        Some(message)
    } else {
        None
    }
}
