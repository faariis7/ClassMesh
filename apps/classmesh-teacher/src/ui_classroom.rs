use std::collections::BTreeMap;

use eframe::egui;

use classmesh_video::monitoring_scheduler::MonitoringSourceId;

use crate::classroom_grid::TeacherMonitoringGridViewModel;
use crate::classroom_view::{ClassroomDeviceRow, TeacherClassroomViewModel};
use crate::ui_shell::{
    TeacherUiMessage, TeacherUiShellState, media_label, presence_label, quality_label,
};

pub fn show_classroom(
    ui: &mut egui::Ui,
    shell: &mut TeacherUiShellState,
    classroom: &mut TeacherClassroomViewModel,
    monitoring: &TeacherMonitoringGridViewModel,
) {
    let rows = classroom.rows();
    let tiles = monitoring.tiles(classroom);
    let names: BTreeMap<_, _> = rows
        .iter()
        .map(|row| (row.source_id, row.display_name.as_str()))
        .collect();
    let mut requested_message = None;

    ui.columns(2, |columns| {
        device_list(&mut columns[0], &rows, &mut requested_message);
        monitoring_grid(&mut columns[1], &tiles, &names, &mut requested_message);
    });

    if let Some(message) = requested_message {
        if let Some(action) = shell.handle(message) {
            let _ = action.apply_to_classroom(classroom);
        }
    }
}

fn device_list(
    ui: &mut egui::Ui,
    rows: &[ClassroomDeviceRow],
    requested_message: &mut Option<TeacherUiMessage>,
) {
    ui.heading("Devices");
    ui.label(format!("{} enrolled", rows.len()));
    if rows.iter().any(|row| row.selected) && ui.button("Clear selection").clicked() {
        *requested_message = Some(TeacherUiMessage::SelectDevice(None));
    }
    ui.separator();

    if rows.is_empty() {
        ui.label("No classroom devices are available yet.");
        return;
    }

    egui::ScrollArea::vertical()
        .id_salt("classmesh_device_list")
        .show(ui, |ui| {
            for row in rows {
                let label = format!(
                    "{}\nControl: {} · Media: {} · Quality: {}",
                    row.display_name,
                    presence_label(row.health.presence),
                    media_label(row.health.media),
                    quality_label(row.quality_tier),
                );
                let response = ui.selectable_label(row.selected, label);
                if response.clicked() {
                    *requested_message = Some(TeacherUiMessage::SelectDevice(Some(row.source_id)));
                }
                if !row.health.service_ready || !row.health.worker_ready {
                    ui.small(format!(
                        "Service: {} · Worker: {}",
                        readiness_label(row.health.service_ready),
                        readiness_label(row.health.worker_ready)
                    ));
                }
                if row.interactive_active {
                    ui.small("Interactive session active");
                } else if !row.thumbnail_available {
                    ui.small("Monitoring thumbnail unavailable");
                }
                ui.separator();
            }
        });
}

fn monitoring_grid(
    ui: &mut egui::Ui,
    tiles: &[crate::classroom_grid::MonitoringGridTile],
    names: &BTreeMap<MonitoringSourceId, &str>,
    requested_message: &mut Option<TeacherUiMessage>,
) {
    ui.heading("Monitoring");
    ui.label(format!("{} latest thumbnails", tiles.len()));
    ui.separator();

    if tiles.is_empty() {
        ui.label("No monitoring thumbnails have arrived yet.");
        return;
    }

    egui::ScrollArea::vertical()
        .id_salt("classmesh_monitoring_grid")
        .show(ui, |ui| {
            egui::Grid::new("classmesh_monitoring_tiles")
                .num_columns(2)
                .show(ui, |ui| {
                    for (index, tile) in tiles.iter().enumerate() {
                        let name = names
                            .get(&tile.source_id)
                            .copied()
                            .unwrap_or("Unknown device");
                        ui.vertical(|ui| {
                            let title = format!(
                                "{name}\nFrame {} · {} bytes",
                                tile.frame.meta.frame_id,
                                tile.frame.data.len()
                            );
                            if names.contains_key(&tile.source_id) {
                                if ui.selectable_label(tile.selected, title).clicked() {
                                    *requested_message =
                                        Some(TeacherUiMessage::SelectDevice(Some(tile.source_id)));
                                }
                            } else {
                                ui.label(title);
                                ui.small("No matching classroom device");
                            }
                            ui.small(if tile.frame.meta.keyframe {
                                "Encoded thumbnail ready · keyframe"
                            } else {
                                "Encoded thumbnail ready"
                            });
                        });

                        if index % 2 == 1 {
                            ui.end_row();
                        }
                    }
                });
        });
}

const fn readiness_label(ready: bool) -> &'static str {
    if ready { "Ready" } else { "Unavailable" }
}
