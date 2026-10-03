use classmesh_core::MediaState;
use classmesh_core::adaptation::QualityTier;
use classmesh_core::presence::PresenceState;
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

use crate::classroom_view::{ClassroomViewError, TeacherClassroomViewModel};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TeacherUiSection {
    #[default]
    Classroom,
    Focus,
    Presentation,
    Diagnostics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherUiMessage {
    Navigate(TeacherUiSection),
    SelectDevice(Option<MonitoringSourceId>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherUiAction {
    SelectDevice(Option<MonitoringSourceId>),
}

impl TeacherUiAction {
    pub fn apply_to_classroom(
        self,
        classroom: &mut TeacherClassroomViewModel,
    ) -> Result<(), ClassroomViewError> {
        match self {
            Self::SelectDevice(source_id) => classroom.select(source_id),
        }
    }
}

#[must_use]
pub const fn presence_label(presence: PresenceState) -> &'static str {
    match presence {
        PresenceState::Offline => "Offline",
        PresenceState::Connecting => "Connecting",
        PresenceState::Online => "Online",
        PresenceState::ControlRecovering => "Control recovering",
    }
}

#[must_use]
pub const fn media_label(media: MediaState) -> &'static str {
    match media {
        MediaState::Idle => "Idle",
        MediaState::Starting => "Starting",
        MediaState::Streaming => "Streaming",
        MediaState::Degraded => "Degraded",
        MediaState::Recovering => "Recovering",
        MediaState::Stopped => "Stopped",
    }
}

#[must_use]
pub const fn quality_label(quality: Option<QualityTier>) -> &'static str {
    match quality {
        None => "Unknown",
        Some(QualityTier::Emergency) => "Emergency",
        Some(QualityTier::Low) => "Low",
        Some(QualityTier::Medium) => "Medium",
        Some(QualityTier::High) => "High",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TeacherUiShellState {
    active_section: TeacherUiSection,
}

impl TeacherUiShellState {
    #[must_use]
    pub const fn active_section(&self) -> TeacherUiSection {
        self.active_section
    }

    pub fn handle(&mut self, message: TeacherUiMessage) -> Option<TeacherUiAction> {
        match message {
            TeacherUiMessage::Navigate(section) => {
                self.active_section = section;
                None
            }
            TeacherUiMessage::SelectDevice(source_id) => {
                Some(TeacherUiAction::SelectDevice(source_id))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use classmesh_core::presence::DeviceHealth;

    use crate::classroom_view::{ClassroomDeviceSnapshot, ClassroomViewConfig};

    use super::*;

    fn classroom() -> TeacherClassroomViewModel {
        let mut classroom =
            TeacherClassroomViewModel::new(ClassroomViewConfig::default()).unwrap();
        classroom
            .upsert(ClassroomDeviceSnapshot {
                source_id: MonitoringSourceId(7),
                display_name: "Student 07".to_owned(),
                health: DeviceHealth {
                    presence: PresenceState::Online,
                    media: MediaState::Recovering,
                    worker_ready: true,
                    service_ready: true,
                },
                quality_tier: Some(QualityTier::Medium),
                thumbnail_available: true,
                interactive_active: false,
            })
            .unwrap();
        classroom
    }

    #[test]
    fn shell_defaults_to_classroom_without_engine_action() {
        let shell = TeacherUiShellState::default();
        assert_eq!(shell.active_section(), TeacherUiSection::Classroom);
    }

    #[test]
    fn navigation_is_shell_local_and_emits_no_engine_action() {
        let mut shell = TeacherUiShellState::default();
        assert_eq!(
            shell.handle(TeacherUiMessage::Navigate(TeacherUiSection::Diagnostics)),
            None
        );
        assert_eq!(shell.active_section(), TeacherUiSection::Diagnostics);
    }

    #[test]
    fn selection_action_delegates_to_authoritative_classroom_model() {
        let mut shell = TeacherUiShellState::default();
        let mut classroom = classroom();

        let action = shell
            .handle(TeacherUiMessage::SelectDevice(Some(MonitoringSourceId(7))))
            .expect("selection action");
        assert_eq!(action.apply_to_classroom(&mut classroom), Ok(()));
        assert_eq!(classroom.selected(), Some(MonitoringSourceId(7)));

        let unknown = shell
            .handle(TeacherUiMessage::SelectDevice(Some(MonitoringSourceId(99))))
            .expect("selection action");
        assert_eq!(
            unknown.apply_to_classroom(&mut classroom),
            Err(ClassroomViewError::UnknownDevice)
        );
        assert_eq!(classroom.selected(), Some(MonitoringSourceId(7)));
    }

    #[test]
    fn status_labels_keep_control_presence_independent_from_media_health() {
        let classroom = classroom();
        let row = classroom.rows().remove(0);

        assert_eq!(presence_label(row.health.presence), "Online");
        assert_eq!(media_label(row.health.media), "Recovering");
        assert_eq!(quality_label(row.quality_tier), "Medium");
    }
}
