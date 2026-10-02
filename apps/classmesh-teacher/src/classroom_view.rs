use std::collections::BTreeMap;

use classmesh_core::adaptation::QualityTier;
use classmesh_core::presence::DeviceHealth;
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

pub const DEFAULT_MAX_CLASSROOM_DEVICES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassroomViewConfig {
    pub max_devices: usize,
}

impl Default for ClassroomViewConfig {
    fn default() -> Self {
        Self {
            max_devices: DEFAULT_MAX_CLASSROOM_DEVICES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassroomDeviceSnapshot {
    pub source_id: MonitoringSourceId,
    pub display_name: String,
    pub health: DeviceHealth,
    pub quality_tier: Option<QualityTier>,
    pub thumbnail_available: bool,
    pub interactive_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassroomDeviceRow {
    pub source_id: MonitoringSourceId,
    pub display_name: String,
    pub health: DeviceHealth,
    pub quality_tier: Option<QualityTier>,
    pub thumbnail_available: bool,
    pub interactive_active: bool,
    pub selected: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassroomViewError {
    InvalidMaxDevices,
    EmptyDisplayName,
    DeviceLimitReached,
    UnknownDevice,
}

#[derive(Debug)]
pub struct TeacherClassroomViewModel {
    config: ClassroomViewConfig,
    devices: BTreeMap<MonitoringSourceId, ClassroomDeviceSnapshot>,
    selected: Option<MonitoringSourceId>,
}

impl TeacherClassroomViewModel {
    pub fn new(_config: ClassroomViewConfig) -> Result<Self, ClassroomViewError> {
        todo!("Phase 11A RED: validate bounded classroom view state")
    }

    pub fn upsert(
        &mut self,
        _snapshot: ClassroomDeviceSnapshot,
    ) -> Result<(), ClassroomViewError> {
        todo!("Phase 11A RED: insert/update bounded device projection")
    }

    pub fn remove(&mut self, _source_id: MonitoringSourceId) -> bool {
        todo!("Phase 11A RED: remove device and clear stale selection")
    }

    pub fn select(
        &mut self,
        _source_id: Option<MonitoringSourceId>,
    ) -> Result<(), ClassroomViewError> {
        todo!("Phase 11A RED: select only known device")
    }

    #[must_use]
    pub fn selected(&self) -> Option<MonitoringSourceId> {
        self.selected
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    #[must_use]
    pub fn rows(&self) -> Vec<ClassroomDeviceRow> {
        todo!("Phase 11A RED: deterministic UI projection")
    }
}

#[cfg(test)]
mod tests {
    use classmesh_core::presence::PresenceState;
    use classmesh_core::MediaState;

    use super::*;

    fn health(presence: PresenceState, media: MediaState) -> DeviceHealth {
        DeviceHealth {
            presence,
            media,
            worker_ready: true,
            service_ready: true,
        }
    }

    fn device(
        id: u64,
        name: &str,
        presence: PresenceState,
        media: MediaState,
    ) -> ClassroomDeviceSnapshot {
        ClassroomDeviceSnapshot {
            source_id: MonitoringSourceId(id),
            display_name: name.to_owned(),
            health: health(presence, media),
            quality_tier: Some(QualityTier::High),
            thumbnail_available: true,
            interactive_active: false,
        }
    }

    #[test]
    fn projection_preserves_control_presence_independently_from_media_health() {
        let mut model = TeacherClassroomViewModel::new(ClassroomViewConfig::default()).unwrap();
        model
            .upsert(device(
                1,
                "Student 01",
                PresenceState::Online,
                MediaState::Recovering,
            ))
            .unwrap();

        let rows = model.rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].health.presence, PresenceState::Online);
        assert_eq!(rows[0].health.media, MediaState::Recovering);
    }

    #[test]
    fn device_state_is_bounded_and_updates_do_not_consume_capacity() {
        let mut model = TeacherClassroomViewModel::new(ClassroomViewConfig { max_devices: 2 }).unwrap();
        model
            .upsert(device(1, "A", PresenceState::Online, MediaState::Idle))
            .unwrap();
        model
            .upsert(device(2, "B", PresenceState::Online, MediaState::Idle))
            .unwrap();
        model
            .upsert(device(1, "A updated", PresenceState::Online, MediaState::Streaming))
            .unwrap();

        assert_eq!(model.len(), 2);
        assert_eq!(
            model.upsert(device(3, "C", PresenceState::Online, MediaState::Idle)),
            Err(ClassroomViewError::DeviceLimitReached)
        );
    }

    #[test]
    fn selection_survives_updates_and_is_cleared_when_device_is_removed() {
        let mut model = TeacherClassroomViewModel::new(ClassroomViewConfig::default()).unwrap();
        model
            .upsert(device(7, "Student 07", PresenceState::Online, MediaState::Idle))
            .unwrap();
        model.select(Some(MonitoringSourceId(7))).unwrap();
        model
            .upsert(device(
                7,
                "Student 07",
                PresenceState::Online,
                MediaState::Streaming,
            ))
            .unwrap();

        assert_eq!(model.selected(), Some(MonitoringSourceId(7)));
        assert!(model.rows()[0].selected);

        assert!(model.remove(MonitoringSourceId(7)));
        assert_eq!(model.selected(), None);
        assert!(model.is_empty());
    }

    #[test]
    fn rows_are_sorted_by_display_name_then_source_id() {
        let mut model = TeacherClassroomViewModel::new(ClassroomViewConfig::default()).unwrap();
        for snapshot in [
            device(3, "bravo", PresenceState::Online, MediaState::Idle),
            device(2, "Alpha", PresenceState::Online, MediaState::Idle),
            device(1, "alpha", PresenceState::Online, MediaState::Idle),
        ] {
            model.upsert(snapshot).unwrap();
        }

        let ids: Vec<_> = model.rows().into_iter().map(|row| row.source_id).collect();
        assert_eq!(
            ids,
            vec![
                MonitoringSourceId(1),
                MonitoringSourceId(2),
                MonitoringSourceId(3)
            ]
        );
    }

    #[test]
    fn invalid_config_name_and_unknown_selection_fail_closed() {
        assert!(matches!(
            TeacherClassroomViewModel::new(ClassroomViewConfig { max_devices: 0 }),
            Err(ClassroomViewError::InvalidMaxDevices)
        ));

        let mut model = TeacherClassroomViewModel::new(ClassroomViewConfig::default()).unwrap();
        assert_eq!(
            model.upsert(device(1, "   ", PresenceState::Online, MediaState::Idle)),
            Err(ClassroomViewError::EmptyDisplayName)
        );
        assert_eq!(
            model.select(Some(MonitoringSourceId(99))),
            Err(ClassroomViewError::UnknownDevice)
        );
    }
}
