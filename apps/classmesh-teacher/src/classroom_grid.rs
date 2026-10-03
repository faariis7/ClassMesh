use std::collections::BTreeMap;

use classmesh_video::distributor::SharedEncodedFrame;
use classmesh_video::monitoring_fanin::MonitoringThumbnailUpdate;
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

use crate::classroom_view::TeacherClassroomViewModel;

pub const DEFAULT_MAX_MONITORING_GRID_TILES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitoringGridViewConfig {
    pub max_tiles: usize,
}

impl Default for MonitoringGridViewConfig {
    fn default() -> Self {
        Self {
            max_tiles: DEFAULT_MAX_MONITORING_GRID_TILES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringGridViewError {
    InvalidMaxTiles,
    TileLimitReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringGridUpdate {
    Inserted,
    Replaced,
}

#[derive(Debug, Clone)]
pub struct MonitoringGridTile {
    pub source_id: MonitoringSourceId,
    pub frame: SharedEncodedFrame,
    pub selected: bool,
}

#[derive(Debug)]
pub struct TeacherMonitoringGridViewModel {
    config: MonitoringGridViewConfig,
    latest: BTreeMap<MonitoringSourceId, SharedEncodedFrame>,
}

impl TeacherMonitoringGridViewModel {
    pub fn new(_config: MonitoringGridViewConfig) -> Result<Self, MonitoringGridViewError> {
        todo!("Phase 11B RED: validate bounded grid configuration")
    }

    pub fn accept(
        &mut self,
        _update: MonitoringThumbnailUpdate,
    ) -> Result<MonitoringGridUpdate, MonitoringGridViewError> {
        todo!("Phase 11B RED: keep only the latest thumbnail per source")
    }

    pub fn remove(&mut self, _source_id: MonitoringSourceId) -> bool {
        todo!("Phase 11B RED: remove one source thumbnail")
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.latest.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.latest.is_empty()
    }

    #[must_use]
    pub fn tiles(&self, _classroom: &TeacherClassroomViewModel) -> Vec<MonitoringGridTile> {
        todo!("Phase 11B RED: project deterministic tiles with authoritative selection")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use classmesh_core::MediaState;
    use classmesh_core::adaptation::QualityTier;
    use classmesh_core::presence::{DeviceHealth, PresenceState};
    use classmesh_video::{Codec, EncodedFrameMeta};

    use crate::classroom_view::{
        ClassroomDeviceSnapshot, ClassroomViewConfig, TeacherClassroomViewModel,
    };

    use super::*;

    fn frame(frame_id: u64) -> SharedEncodedFrame {
        SharedEncodedFrame::new(
            EncodedFrameMeta {
                frame_id,
                timestamp_us: frame_id.saturating_mul(1_000),
                keyframe: true,
            },
            Codec::H264,
            vec![u8::try_from(frame_id).unwrap_or(0); 32],
        )
    }

    fn update(source_id: u64, frame_id: u64) -> MonitoringThumbnailUpdate {
        MonitoringThumbnailUpdate::new(MonitoringSourceId(source_id), frame(frame_id))
    }

    fn classroom(ids: &[u64]) -> TeacherClassroomViewModel {
        let mut model =
            TeacherClassroomViewModel::new(ClassroomViewConfig { max_devices: 16 }).unwrap();
        for id in ids {
            model
                .upsert(ClassroomDeviceSnapshot {
                    source_id: MonitoringSourceId(*id),
                    display_name: format!("Student {id:02}"),
                    health: DeviceHealth {
                        presence: PresenceState::Online,
                        media: MediaState::Streaming,
                        worker_ready: true,
                        service_ready: true,
                    },
                    quality_tier: Some(QualityTier::High),
                    thumbnail_available: true,
                    interactive_active: false,
                })
                .unwrap();
        }
        model
    }

    #[test]
    fn latest_thumbnail_replaces_stale_frame_without_growing_grid() {
        let mut grid =
            TeacherMonitoringGridViewModel::new(MonitoringGridViewConfig::default()).unwrap();
        assert_eq!(grid.accept(update(7, 1)), Ok(MonitoringGridUpdate::Inserted));
        assert_eq!(grid.accept(update(7, 2)), Ok(MonitoringGridUpdate::Replaced));

        let classroom = classroom(&[7]);
        let tiles = grid.tiles(&classroom);
        assert_eq!(grid.len(), 1);
        assert_eq!(tiles.len(), 1);
        assert_eq!(tiles[0].frame.meta.frame_id, 2);
    }

    #[test]
    fn projection_reuses_encoded_allocation_without_payload_copy() {
        let mut grid =
            TeacherMonitoringGridViewModel::new(MonitoringGridViewConfig::default()).unwrap();
        let update = update(3, 10);
        let allocation = Arc::clone(&update.frame().data);
        grid.accept(update).unwrap();

        let classroom = classroom(&[3]);
        let tiles = grid.tiles(&classroom);
        assert!(Arc::ptr_eq(&allocation, &tiles[0].frame.data));
    }

    #[test]
    fn new_sources_are_bounded_but_existing_source_can_be_replaced_at_capacity() {
        let mut grid =
            TeacherMonitoringGridViewModel::new(MonitoringGridViewConfig { max_tiles: 2 }).unwrap();
        grid.accept(update(1, 1)).unwrap();
        grid.accept(update(2, 1)).unwrap();

        assert_eq!(
            grid.accept(update(3, 1)),
            Err(MonitoringGridViewError::TileLimitReached)
        );
        assert_eq!(grid.accept(update(1, 2)), Ok(MonitoringGridUpdate::Replaced));
        assert_eq!(grid.len(), 2);
    }

    #[test]
    fn classroom_selection_marks_and_prioritizes_the_selected_tile() {
        let mut grid =
            TeacherMonitoringGridViewModel::new(MonitoringGridViewConfig::default()).unwrap();
        for id in [1, 2, 3] {
            grid.accept(update(id, 1)).unwrap();
        }

        let mut classroom = classroom(&[1, 2, 3]);
        classroom.select(Some(MonitoringSourceId(3))).unwrap();

        let tiles = grid.tiles(&classroom);
        assert_eq!(tiles[0].source_id, MonitoringSourceId(3));
        assert!(tiles[0].selected);
        assert!(tiles[1..].iter().all(|tile| !tile.selected));
    }

    #[test]
    fn selected_device_without_thumbnail_does_not_fabricate_grid_state() {
        let mut grid =
            TeacherMonitoringGridViewModel::new(MonitoringGridViewConfig::default()).unwrap();
        grid.accept(update(1, 1)).unwrap();

        let mut classroom = classroom(&[1, 2]);
        classroom.select(Some(MonitoringSourceId(2))).unwrap();

        let tiles = grid.tiles(&classroom);
        assert_eq!(tiles.len(), 1);
        assert_eq!(tiles[0].source_id, MonitoringSourceId(1));
        assert!(!tiles[0].selected);
    }

    #[test]
    fn removal_is_source_local_and_invalid_config_fails_closed() {
        assert!(matches!(
            TeacherMonitoringGridViewModel::new(MonitoringGridViewConfig { max_tiles: 0 }),
            Err(MonitoringGridViewError::InvalidMaxTiles)
        ));

        let mut grid =
            TeacherMonitoringGridViewModel::new(MonitoringGridViewConfig::default()).unwrap();
        grid.accept(update(1, 1)).unwrap();
        grid.accept(update(2, 1)).unwrap();

        assert!(grid.remove(MonitoringSourceId(1)));
        assert!(!grid.remove(MonitoringSourceId(1)));
        assert_eq!(grid.len(), 1);
        assert!(!grid.is_empty());
    }
}
