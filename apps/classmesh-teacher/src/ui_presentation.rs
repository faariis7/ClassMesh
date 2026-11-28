use eframe::egui;

use classmesh_protocol::control_wire::MediaTransport;

use crate::presentation_view::{PresentationUiStatus, PresentationViewState};
use crate::ui_shell::{TeacherUiMessage, media_label};

pub fn show_presentation(
    ui: &mut egui::Ui,
    state: PresentationViewState,
    status: Option<PresentationUiStatus>,
    action_pending: bool,
) -> Option<TeacherUiMessage> {
    ui.heading("Presentation");
    if let Some(status) = status {
        ui.label(status_text(status));
    } else {
        ui.label(format!("Media: {}", media_label(state.media_state)));
    }

    let action = match state.binding {
        Some(binding) => {
            ui.strong(format!(
                "Presentation {} · Stream {} · Epoch {}",
                binding.presentation_id, binding.stream_id, binding.epoch
            ));

            if let Some(profile) = state.profile {
                ui.label(format!(
                    "{}×{} @ {} FPS · {} kbps",
                    profile.width,
                    profile.height,
                    profile.fps,
                    profile.bitrate_bps / 1_000
                ));
            } else {
                ui.small("Presentation profile is not ready yet.");
            }

            ui.separator();
            metrics(ui, state);
            ui.separator();

            (
                "Stop presentation",
                TeacherUiMessage::StopPresentation(binding),
            )
        }
        None => ("Start presentation", TeacherUiMessage::StartPresentation),
    };

    let waiting = matches!(
        status,
        Some(
            PresentationUiStatus::Reserving
                | PresentationUiStatus::Stopping
                | PresentationUiStatus::Unavailable(_)
                | PresentationUiStatus::Disconnected
        )
    );
    if ui
        .add_enabled(!action_pending && !waiting, egui::Button::new(action.0))
        .clicked()
    {
        Some(action.1)
    } else {
        None
    }
}

fn status_text(status: PresentationUiStatus) -> &'static str {
    match status {
        PresentationUiStatus::Unavailable(message) | PresentationUiStatus::Failed(message) => {
            message
        }
        PresentationUiStatus::Ready(MediaTransport::UdpUnicast) => {
            "Ready to present over protected Unicast."
        }
        PresentationUiStatus::Ready(MediaTransport::UdpMulticast) => {
            "Ready to present over protected Multicast."
        }
        PresentationUiStatus::Ready(_) => "Ready to present.",
        PresentationUiStatus::Reserving => {
            "Waiting for the Student Service to reserve the presentation."
        }
        PresentationUiStatus::InstallingKey => {
            "Waiting for the Student Worker to confirm the media key."
        }
        PresentationUiStatus::PreparingReceiver => {
            "Waiting for the Student Worker to start receiving."
        }
        PresentationUiStatus::StartingCapture => "Starting Teacher capture and encoding.",
        PresentationUiStatus::Sending => "Sending protected video to the Student.",
        PresentationUiStatus::RecoveringCapture => "Recovering Teacher screen capture.",
        PresentationUiStatus::Stopping => "Stopping the presentation and waiting for cleanup.",
        PresentationUiStatus::Disconnected => "Student disconnected. See the connection status.",
    }
}

fn metrics(ui: &mut egui::Ui, state: PresentationViewState) {
    let metrics = state.metrics;
    egui::Grid::new("classmesh_presentation_metrics")
        .num_columns(1)
        .show(ui, |ui| {
            metric(ui, "Captured", metrics.captured_frames);
            metric(ui, "Submitted", metrics.submitted_frames);
            metric(ui, "Encoded", metrics.encoded_frames);
            metric(ui, "Encoded bytes", metrics.encoded_bytes);
            metric(ui, "Rate drops", metrics.rate_dropped_frames);
            metric(ui, "Pool drops", metrics.pool_dropped_frames);
            metric(ui, "Keyframes", metrics.keyframes);
            metric(ui, "Keyframe requests", metrics.keyframe_requests);
            metric(ui, "Multicast queued", metrics.multicast_queued);
            metric(ui, "Multicast drops", metrics.multicast_dropped);
            metric(ui, "Unicast outliers", metrics.unicast_outliers);
        });
}

// Keep the name and its value in one accessibility node. Two separate
// widgets read as an unlabelled number in some screen-reader navigation modes.
fn metric_readout(label: &str, value: impl std::fmt::Display) -> String {
    format!("{label}: {value}")
}

fn metric(ui: &mut egui::Ui, label: &str, value: impl std::fmt::Display) {
    ui.monospace(metric_readout(label, value));
    ui.end_row();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presentation_metric_readout_keeps_label_and_full_value_together() {
        assert_eq!(metric_readout("Captured", 0_u64), "Captured: 0");
        assert_eq!(
            metric_readout("Encoded bytes", u64::MAX),
            format!("Encoded bytes: {}", u64::MAX)
        );
        assert_eq!(
            metric_readout("Multicast queued", 42_usize),
            "Multicast queued: 42"
        );
    }
}
