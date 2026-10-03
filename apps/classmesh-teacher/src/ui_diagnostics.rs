use eframe::egui;

use classmesh_core::adaptation::QualityTier;
use classmesh_core::transport_topology::{MediaPath, MediaTopology, PhysicalGateStatus};
use classmesh_core::{MediaTransport, StreamKind};
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

use crate::device_diagnostics::{DeviceDiagnosticsView, TroubleshootingOverrideRequest};
use crate::ui_shell::{TeacherUiMessage, media_label, presence_label, quality_label};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DiagnosticsOverrideDraft {
    stream_kind: Option<StreamKind>,
    quality_tier: Option<QualityTier>,
    transport: Option<MediaTransport>,
    topology: Option<MediaTopology>,
}

pub fn show_diagnostics(
    ui: &mut egui::Ui,
    selected_source: Option<MonitoringSourceId>,
    diagnostics: Option<&DeviceDiagnosticsView>,
    draft: &mut DiagnosticsOverrideDraft,
    action_pending: bool,
) -> Option<TeacherUiMessage> {
    ui.heading("Diagnostics");

    let Some(source_id) = selected_source else {
        ui.label("Select a classroom device to inspect diagnostics.");
        return None;
    };
    let Some(view) = diagnostics else {
        ui.label("No diagnostics snapshot is available for the selected device.");
        return None;
    };
    if view.source_id != source_id {
        ui.label("The diagnostics snapshot does not match the current selection.");
        return None;
    }

    ui.strong(&view.display_name);
    ui.label(format!(
        "Control: {} · Media: {} · Quality: {}",
        presence_label(view.health.presence),
        media_label(view.health.media),
        quality_label(view.quality_tier),
    ));
    ui.small(format!(
        "Service: {} · Worker: {}",
        readiness_label(view.health.service_ready),
        readiness_label(view.health.worker_ready),
    ));

    if let Some(path) = view.active_path {
        ui.label(format!("Active media path: {}", media_path_label(path)));
    } else {
        ui.label("Active media path: unknown");
    }

    if let Some(sample) = view.quality_sample {
        ui.collapsing("Receiver quality sample", |ui| {
            egui::Grid::new("classmesh_diagnostics_quality_sample")
                .num_columns(2)
                .show(ui, |ui| {
                    sample_metric(ui, "RTT", format!("{:.1} ms", sample.network.rtt_ms));
                    sample_metric(
                        ui,
                        "Packet loss",
                        format!("{:.2}%", sample.network.packet_loss * 100.0),
                    );
                    sample_metric(ui, "Jitter", format!("{:.1} ms", sample.network.jitter_ms));
                    sample_metric(
                        ui,
                        "Decode FPS",
                        format!("{:.1}", sample.network.decode_fps),
                    );
                    sample_metric(
                        ui,
                        "Queue delay",
                        format!("{:.1} ms", sample.network.queue_delay_ms),
                    );
                    sample_metric(
                        ui,
                        "Estimated bandwidth",
                        format!("{:.1} Mbps", sample.network.estimated_mbps),
                    );
                    sample_metric(ui, "Queue depth", sample.queue_depth);
                    sample_metric(
                        ui,
                        "Queue drop rate",
                        format!("{:.2}%", sample.queue_drop_rate * 100.0),
                    );
                    sample_metric(
                        ui,
                        "Decode delay",
                        format!("{:.1} ms", sample.decode_delay_ms),
                    );
                    sample_metric(
                        ui,
                        "Render delay",
                        format!("{:.1} ms", sample.render_delay_ms),
                    );
                });
        });
    }

    ui.collapsing("Diagnostic codes", |ui| {
        if view.diagnostic_codes.is_empty() {
            ui.label("No diagnostic codes.");
        } else {
            for code in &view.diagnostic_codes {
                ui.monospace(*code);
            }
        }
    });

    ui.collapsing("Physical evidence", |ui| {
        gate_status(ui, "UDP unicast", view.topology_evidence.udp_unicast);
        gate_status(ui, "QUIC datagram", view.topology_evidence.quic_datagram);
        gate_status(
            ui,
            "Wired multicast",
            view.topology_evidence.wired_multicast,
        );
        gate_status(ui, "WebRTC", view.topology_evidence.web_rtc);
        gate_status(ui, "Relay topology", view.topology_evidence.relay_topology);
    });

    ui.separator();
    ui.heading("Troubleshooting override");
    ui.small(
        "Overrides are requests only; live engine evidence is revalidated before application.",
    );

    if ui
        .add_enabled(!action_pending, egui::Button::new("Return to automatic"))
        .clicked()
    {
        return Some(TeacherUiMessage::RequestTroubleshootingOverride {
            source_id,
            request: TroubleshootingOverrideRequest::Automatic,
        });
    }

    ui.collapsing("Quality override", |ui| {
        stream_kind_picker(ui, &mut draft.stream_kind);
        quality_tier_picker(ui, &mut draft.quality_tier);
    });
    if let (Some(stream_kind), Some(tier)) = (draft.stream_kind, draft.quality_tier) {
        if ui
            .add_enabled(!action_pending, egui::Button::new("Apply quality override"))
            .clicked()
        {
            return Some(TeacherUiMessage::RequestTroubleshootingOverride {
                source_id,
                request: TroubleshootingOverrideRequest::Quality { stream_kind, tier },
            });
        }
    }

    ui.collapsing("Media path override", |ui| {
        transport_picker(ui, &mut draft.transport);
        topology_picker(ui, &mut draft.topology);
    });
    if let (Some(transport), Some(topology)) = (draft.transport, draft.topology) {
        if ui
            .add_enabled(
                !action_pending,
                egui::Button::new("Request media path override"),
            )
            .clicked()
        {
            return Some(TeacherUiMessage::RequestTroubleshootingOverride {
                source_id,
                request: TroubleshootingOverrideRequest::MediaPath(MediaPath {
                    transport,
                    topology,
                }),
            });
        }
    }

    None
}

fn stream_kind_picker(ui: &mut egui::Ui, selected: &mut Option<StreamKind>) {
    egui::ComboBox::from_id_salt("classmesh_diagnostics_stream_kind")
        .selected_text(selected.map(stream_kind_label).unwrap_or("Select workload"))
        .show_ui(ui, |ui| {
            for kind in [
                StreamKind::Monitoring,
                StreamKind::Interactive,
                StreamKind::TeacherPresentation,
            ] {
                ui.selectable_value(selected, Some(kind), stream_kind_label(kind));
            }
        });
}

fn quality_tier_picker(ui: &mut egui::Ui, selected: &mut Option<QualityTier>) {
    egui::ComboBox::from_id_salt("classmesh_diagnostics_quality_tier")
        .selected_text(
            selected
                .map(|tier| quality_label(Some(tier)))
                .unwrap_or("Select quality"),
        )
        .show_ui(ui, |ui| {
            for tier in [
                QualityTier::Emergency,
                QualityTier::Low,
                QualityTier::Medium,
                QualityTier::High,
            ] {
                ui.selectable_value(selected, Some(tier), quality_label(Some(tier)));
            }
        });
}

fn transport_picker(ui: &mut egui::Ui, selected: &mut Option<MediaTransport>) {
    egui::ComboBox::from_id_salt("classmesh_diagnostics_transport")
        .selected_text(selected.map(transport_label).unwrap_or("Select transport"))
        .show_ui(ui, |ui| {
            for transport in [
                MediaTransport::UdpMulticast,
                MediaTransport::UdpUnicast,
                MediaTransport::QuicDatagram,
                MediaTransport::WebRtc,
                MediaTransport::ReliableFallback,
            ] {
                ui.selectable_value(selected, Some(transport), transport_label(transport));
            }
        });
}

fn topology_picker(ui: &mut egui::Ui, selected: &mut Option<MediaTopology>) {
    egui::ComboBox::from_id_salt("classmesh_diagnostics_topology")
        .selected_text(selected.map(topology_label).unwrap_or("Select topology"))
        .show_ui(ui, |ui| {
            for topology in [MediaTopology::Direct, MediaTopology::Relay] {
                ui.selectable_value(selected, Some(topology), topology_label(topology));
            }
        });
}

const fn readiness_label(ready: bool) -> &'static str {
    if ready { "Ready" } else { "Unavailable" }
}

const fn stream_kind_label(kind: StreamKind) -> &'static str {
    match kind {
        StreamKind::Monitoring => "Monitoring",
        StreamKind::Interactive => "Interactive",
        StreamKind::TeacherPresentation => "Teacher presentation",
    }
}

const fn transport_label(transport: MediaTransport) -> &'static str {
    match transport {
        MediaTransport::UdpMulticast => "UDP multicast",
        MediaTransport::UdpUnicast => "UDP unicast",
        MediaTransport::QuicDatagram => "QUIC datagram",
        MediaTransport::WebRtc => "WebRTC",
        MediaTransport::ReliableFallback => "Reliable fallback",
    }
}

const fn topology_label(topology: MediaTopology) -> &'static str {
    match topology {
        MediaTopology::Direct => "Direct",
        MediaTopology::Relay => "Relay",
    }
}

fn media_path_label(path: MediaPath) -> String {
    format!(
        "{} / {}",
        transport_label(path.transport),
        topology_label(path.topology)
    )
}

fn gate_status(ui: &mut egui::Ui, label: &str, status: PhysicalGateStatus) {
    ui.label(format!("{label}: {}", gate_status_label(status)));
}

const fn gate_status_label(status: PhysicalGateStatus) -> &'static str {
    match status {
        PhysicalGateStatus::Pending => "Pending",
        PhysicalGateStatus::Qualified => "Qualified",
        PhysicalGateStatus::Rejected => "Rejected",
    }
}

fn sample_metric(ui: &mut egui::Ui, label: &str, value: impl std::fmt::Display) {
    ui.label(label);
    ui.monospace(value.to_string());
    ui.end_row();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_draft_starts_without_implicit_policy_choices() {
        let draft = DiagnosticsOverrideDraft::default();
        assert_eq!(draft.stream_kind, None);
        assert_eq!(draft.quality_tier, None);
        assert_eq!(draft.transport, None);
        assert_eq!(draft.topology, None);
    }
}
