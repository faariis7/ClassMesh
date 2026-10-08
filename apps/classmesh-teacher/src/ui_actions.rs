use eframe::egui;

use classmesh_protocol::control_wire::AppIdentity;
use classmesh_protocol::teacher_interaction::{
    MAX_OPEN_URL_BYTES, MAX_TEACHER_MESSAGE_BYTES, open_target_available,
    teacher_message_available, validate_https_url, validate_message,
};
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

use crate::ui_shell::{TeacherInteractionUiContext, TeacherInteractionUiRequest};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TeacherInteractionDraft {
    message: String,
    https_url: String,
    app: Option<AppIdentity>,
}

impl TeacherInteractionDraft {
    fn clear(&mut self) {
        self.message.clear();
        self.https_url.clear();
        self.app = None;
    }
}

pub fn show_device_actions(
    ui: &mut egui::Ui,
    selected_source: Option<MonitoringSourceId>,
    context: Option<&TeacherInteractionUiContext>,
    draft: &mut TeacherInteractionDraft,
    action_pending: bool,
) -> Option<TeacherInteractionUiRequest> {
    ui.heading("Device Actions");

    let Some(source_id) = selected_source else {
        ui.label("Select a classroom device before sending an action.");
        return None;
    };
    let Some(context) = context else {
        ui.label("Control capabilities are not available for the selected device.");
        return None;
    };
    if context.source_id != source_id {
        ui.label("Control capabilities are stale for the current selection.");
        return None;
    }

    ui.small("Actions target only the currently selected classroom device.");

    let message_available = teacher_message_available(context.version, &context.capabilities);
    let open_available = open_target_available(context.version, &context.capabilities);

    ui.separator();
    ui.strong("Teacher message");
    ui.add_enabled(
        message_available && !action_pending,
        egui::TextEdit::multiline(&mut draft.message)
            .desired_rows(3)
            .hint_text("Message to display on the selected device"),
    );
    truncate_utf8_bytes(&mut draft.message, MAX_TEACHER_MESSAGE_BYTES);
    if !message_available {
        ui.small("Teacher messages are unavailable for this device.");
    }
    let message_valid = validate_message(&draft.message).is_ok();
    if ui
        .add_enabled(
            message_available && message_valid && !action_pending,
            egui::Button::new("Send message"),
        )
        .clicked()
    {
        return Some(TeacherInteractionUiRequest::Message(draft.message.clone()));
    }

    ui.separator();
    ui.strong("Open HTTPS link");
    ui.add_enabled(
        open_available && !action_pending,
        egui::TextEdit::singleline(&mut draft.https_url).hint_text("https://example.com/lesson"),
    );
    truncate_utf8_bytes(&mut draft.https_url, MAX_OPEN_URL_BYTES);
    if !open_available {
        ui.small("Open-target actions are unavailable for this device.");
    }
    let url_valid = validate_https_url(&draft.https_url).is_ok();
    if ui
        .add_enabled(
            open_available && url_valid && !action_pending,
            egui::Button::new("Open link"),
        )
        .clicked()
    {
        return Some(TeacherInteractionUiRequest::HttpsUrl(
            draft.https_url.clone(),
        ));
    }

    ui.separator();
    ui.strong("Open approved app");
    ui.add_enabled_ui(open_available && !action_pending, |ui| {
        egui::ComboBox::from_id_salt("classmesh_teacher_action_app")
            .selected_text(draft.app.map(app_label).unwrap_or("Select app"))
            .show_ui(ui, |ui| {
                for app in [
                    AppIdentity::DefaultBrowser,
                    AppIdentity::Calculator,
                    AppIdentity::TextEditor,
                ] {
                    ui.selectable_value(&mut draft.app, Some(app), app_label(app));
                }
            });
    });
    if let Some(app) = draft.app {
        if ui
            .add_enabled(
                open_available && !action_pending,
                egui::Button::new("Open app"),
            )
            .clicked()
        {
            return Some(TeacherInteractionUiRequest::App(app));
        }
    }

    None
}

pub fn reset_teacher_interaction_draft(draft: &mut TeacherInteractionDraft) {
    draft.clear();
}

fn truncate_utf8_bytes(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes.min(value.len());
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

const fn app_label(app: AppIdentity) -> &'static str {
    match app {
        AppIdentity::DefaultBrowser => "Default browser",
        AppIdentity::Calculator => "Calculator",
        AppIdentity::TextEditor => "Text editor",
        AppIdentity::Unspecified => "Unspecified",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use classmesh_protocol::{Capability, PROTOCOL_VERSION};

    use super::*;

    fn context(capabilities: BTreeSet<Capability>) -> TeacherInteractionUiContext {
        TeacherInteractionUiContext {
            source_id: MonitoringSourceId(7),
            control_session_id: 77,
            version: PROTOCOL_VERSION,
            capabilities,
        }
    }

    #[test]
    fn draft_starts_without_implicit_target_or_content() {
        let draft = TeacherInteractionDraft::default();
        assert!(draft.message.is_empty());
        assert!(draft.https_url.is_empty());
        assert_eq!(draft.app, None);
    }

    #[test]
    fn reset_clears_content_and_closed_app_choice() {
        let mut draft = TeacherInteractionDraft {
            message: "hello".to_owned(),
            https_url: "https://example.com".to_owned(),
            app: Some(AppIdentity::Calculator),
        };
        reset_teacher_interaction_draft(&mut draft);
        assert_eq!(draft, TeacherInteractionDraft::default());
    }

    #[test]
    fn draft_byte_bounds_preserve_utf8_boundaries() {
        let mut value = "é".repeat(MAX_TEACHER_MESSAGE_BYTES);
        truncate_utf8_bytes(&mut value, MAX_TEACHER_MESSAGE_BYTES);
        assert!(value.len() <= MAX_TEACHER_MESSAGE_BYTES);
        assert!(std::str::from_utf8(value.as_bytes()).is_ok());

        let mut url = format!("https://example.com/{}", "x".repeat(MAX_OPEN_URL_BYTES));
        truncate_utf8_bytes(&mut url, MAX_OPEN_URL_BYTES);
        assert_eq!(url.len(), MAX_OPEN_URL_BYTES);
    }

    #[test]
    fn capability_helpers_remain_action_specific() {
        let message = context(BTreeSet::from([Capability::TeacherMessage]));
        assert!(teacher_message_available(
            message.version,
            &message.capabilities
        ));
        assert!(!open_target_available(
            message.version,
            &message.capabilities
        ));

        let open = context(BTreeSet::from([Capability::OpenTarget]));
        assert!(open_target_available(open.version, &open.capabilities));
        assert!(!teacher_message_available(open.version, &open.capabilities));
    }
}
