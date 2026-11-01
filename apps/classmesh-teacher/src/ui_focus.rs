use eframe::egui;

use classmesh_core::presence::{DeviceHealth, PresenceState};

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

    if focused.interactive_active {
        ui.small("Interactive session active");
    } else if focused.thumbnail_available {
        ui.small("Monitoring thumbnail available");
    } else {
        ui.small("Monitoring thumbnail unavailable");
    }

    // Keep local resume available for an already-active session even when
    // control health has deteriorated. Only starting a new session is gated.
    let start_blocker = if focused.interactive_active {
        None
    } else {
        interactive_start_blocker(focused.health)
    };
    if let Some(reason) = start_blocker {
        ui.small(format!("Interactive control unavailable: {reason}"));
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
        .add_enabled(
            !action_pending && start_blocker.is_none(),
            egui::Button::new(label),
        )
        .clicked()
    {
        Some(message)
    } else {
        None
    }
}

fn interactive_start_blocker(health: DeviceHealth) -> Option<&'static str> {
    match health.presence {
        PresenceState::Offline => return Some("Device is offline."),
        PresenceState::Connecting => {
            return Some("Waiting for authenticated control connection.");
        }
        PresenceState::ControlRecovering => return Some("Control connection is recovering."),
        PresenceState::Online => {}
    }
    if !health.service_ready {
        return Some("Device service is not ready.");
    }
    if !health.worker_ready {
        return Some("Device worker is not ready.");
    }
    None
}

#[cfg(test)]
mod tests {
    use classmesh_core::MediaState;
    use classmesh_core::presence::{DeviceHealth, PresenceState};

    use super::interactive_start_blocker;

    fn health(presence: PresenceState, service_ready: bool, worker_ready: bool) -> DeviceHealth {
        DeviceHealth {
            presence,
            media: MediaState::Idle,
            service_ready,
            worker_ready,
        }
    }

    #[test]
    fn interactive_start_requires_online_control_and_ready_runtime() {
        assert_eq!(
            interactive_start_blocker(health(PresenceState::Offline, true, true)),
            Some("Device is offline.")
        );
        assert_eq!(
            interactive_start_blocker(health(PresenceState::Connecting, true, true)),
            Some("Waiting for authenticated control connection.")
        );
        assert_eq!(
            interactive_start_blocker(health(PresenceState::ControlRecovering, true, true)),
            Some("Control connection is recovering.")
        );
        assert_eq!(
            interactive_start_blocker(health(PresenceState::Online, false, true)),
            Some("Device service is not ready.")
        );
        assert_eq!(
            interactive_start_blocker(health(PresenceState::Online, true, false)),
            Some("Device worker is not ready.")
        );
        assert_eq!(
            interactive_start_blocker(health(PresenceState::Online, true, true)),
            None
        );
    }
}
