use std::collections::BTreeMap;

use eframe::egui;

use classmesh_video::monitoring_scheduler::MonitoringSourceId;

use crate::classroom_grid::TeacherMonitoringGridViewModel;
use crate::classroom_view::{ClassroomDeviceRow, TeacherClassroomViewModel};
use crate::ui_shell::{
    TeacherUiMessage, TeacherUiShellState, media_label, presence_label, quality_label,
};

const MIN_SIDE_BY_SIDE_WIDTH: f32 = 1040.0;
const MIN_TWO_TILE_GRID_WIDTH: f32 = 480.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClassroomLayout {
    Stacked,
    SideBySide,
}

fn classroom_layout(available_width: f32) -> ClassroomLayout {
    if available_width.is_finite() && available_width >= MIN_SIDE_BY_SIDE_WIDTH {
        ClassroomLayout::SideBySide
    } else {
        ClassroomLayout::Stacked
    }
}

fn monitoring_grid_columns(available_width: f32) -> usize {
    if available_width.is_finite() && available_width >= MIN_TWO_TILE_GRID_WIDTH {
        2
    } else {
        1
    }
}

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

    match classroom_layout(ui.available_width()) {
        ClassroomLayout::SideBySide => {
            ui.columns(2, |columns| {
                device_list(&mut columns[0], &rows, &mut requested_message, true);
                monitoring_grid(
                    &mut columns[1],
                    &tiles,
                    &names,
                    &mut requested_message,
                    true,
                );
            });
        }
        ClassroomLayout::Stacked => {
            // One scroll owner keeps both panels reachable at the minimum
            // Windows viewport, rather than nesting two full-height scrollers.
            egui::ScrollArea::vertical()
                .id_salt("classmesh_classroom_stacked")
                .show(ui, |ui| {
                    device_list(ui, &rows, &mut requested_message, false);
                    ui.separator();
                    monitoring_grid(ui, &tiles, &names, &mut requested_message, false);
                });
        }
    }

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
    scroll: bool,
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

    if scroll {
        egui::ScrollArea::vertical()
            .id_salt("classmesh_device_list")
            .show(ui, |ui| device_rows(ui, rows, requested_message));
    } else {
        device_rows(ui, rows, requested_message);
    }
}

fn device_rows(
    ui: &mut egui::Ui,
    rows: &[ClassroomDeviceRow],
    requested_message: &mut Option<TeacherUiMessage>,
) {
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
}

fn monitoring_grid(
    ui: &mut egui::Ui,
    tiles: &[crate::classroom_grid::MonitoringGridTile],
    names: &BTreeMap<MonitoringSourceId, &str>,
    requested_message: &mut Option<TeacherUiMessage>,
    scroll: bool,
) {
    ui.heading("Monitoring");
    ui.label(format!("{} latest thumbnails", tiles.len()));
    ui.separator();

    if tiles.is_empty() {
        ui.label("No monitoring thumbnails have arrived yet.");
        return;
    }

    if scroll {
        egui::ScrollArea::vertical()
            .id_salt("classmesh_monitoring_grid")
            .show(ui, |ui| {
                monitoring_tiles(ui, tiles, names, requested_message)
            });
    } else {
        monitoring_tiles(ui, tiles, names, requested_message);
    }
}

fn monitoring_tiles(
    ui: &mut egui::Ui,
    tiles: &[crate::classroom_grid::MonitoringGridTile],
    names: &BTreeMap<MonitoringSourceId, &str>,
    requested_message: &mut Option<TeacherUiMessage>,
) {
    let columns = monitoring_grid_columns(ui.available_width());
    egui::Grid::new("classmesh_monitoring_tiles")
        .num_columns(columns)
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

                if (index + 1) % columns == 0 {
                    ui.end_row();
                }
            }
        });
}

const fn readiness_label(ready: bool) -> &'static str {
    if ready { "Ready" } else { "Unavailable" }
}

#[cfg(test)]
mod responsive_layout_tests {
    use super::*;

    #[test]
    fn classroom_panels_stack_before_the_monitoring_tiles_become_cramped() {
        assert_eq!(classroom_layout(600.0), ClassroomLayout::Stacked);
        assert_eq!(classroom_layout(800.0), ClassroomLayout::Stacked);
        assert_eq!(classroom_layout(1039.0), ClassroomLayout::Stacked);
        assert_eq!(classroom_layout(1040.0), ClassroomLayout::SideBySide);
    }

    #[test]
    fn monitoring_tiles_use_one_column_when_the_available_panel_is_narrow() {
        assert_eq!(monitoring_grid_columns(320.0), 1);
        assert_eq!(monitoring_grid_columns(479.0), 1);
        assert_eq!(monitoring_grid_columns(480.0), 2);
        assert_eq!(monitoring_grid_columns(600.0), 2);
    }
}
