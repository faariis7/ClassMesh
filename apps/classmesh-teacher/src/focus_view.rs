use std::collections::BTreeSet;

use classmesh_core::adaptation::QualityTier;
use classmesh_core::presence::DeviceHealth;
use classmesh_protocol::Capability;
use classmesh_protocol::control_wire::StreamOffer;
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

use crate::classroom_view::TeacherClassroomViewModel;
use crate::monitoring_promotion::{TeacherMonitoringCoordinator, TeacherMonitoringPromotionError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FocusedDeviceView {
    pub source_id: MonitoringSourceId,
    pub display_name: String,
    pub health: DeviceHealth,
    pub quality_tier: Option<QualityTier>,
    pub thumbnail_available: bool,
    pub interactive_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FocusViewError {
    NoSelectedDevice,
    Promotion(TeacherMonitoringPromotionError),
}

impl From<TeacherMonitoringPromotionError> for FocusViewError {
    fn from(value: TeacherMonitoringPromotionError) -> Self {
        Self::Promotion(value)
    }
}

#[derive(Debug, Default)]
pub struct TeacherFocusViewModel;

impl TeacherFocusViewModel {
    #[must_use]
    pub fn focused(classroom: &TeacherClassroomViewModel) -> Option<FocusedDeviceView> {
        let selected = classroom.selected()?;
        classroom
            .rows()
            .into_iter()
            .find(|row| row.source_id == selected)
            .map(|row| FocusedDeviceView {
                source_id: row.source_id,
                display_name: row.display_name,
                health: row.health,
                quality_tier: row.quality_tier,
                thumbnail_available: row.thumbnail_available,
                interactive_active: row.interactive_active,
            })
    }

    pub fn request_interactive(
        classroom: &TeacherClassroomViewModel,
        monitoring: &mut TeacherMonitoringCoordinator,
        offer: &StreamOffer,
        negotiated_capabilities: &BTreeSet<Capability>,
    ) -> Result<(), FocusViewError> {
        let source_id = classroom
            .selected()
            .ok_or(FocusViewError::NoSelectedDevice)?;
        monitoring
            .request_interactive_promotion(source_id, offer, negotiated_capabilities)
            .map_err(Into::into)
    }

    pub fn resume_thumbnail(
        classroom: &TeacherClassroomViewModel,
        monitoring: &mut TeacherMonitoringCoordinator,
    ) -> Result<(), FocusViewError> {
        let source_id = classroom
            .selected()
            .ok_or(FocusViewError::NoSelectedDevice)?;
        monitoring.resume_thumbnail(source_id).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use classmesh_core::MediaState;
    use classmesh_core::presence::PresenceState;
    use classmesh_protocol::control_wire::{MediaTransport, StreamKind, VideoCodec, VideoProfile};
    use classmesh_video::monitoring::MonitoringProfile;
    use classmesh_video::monitoring_fanin::MonitoringFanInConfig;
    use classmesh_video::monitoring_scheduler::{MonitoringPriority, MonitoringSchedulerConfig};

    use crate::classroom_view::{
        ClassroomDeviceSnapshot, ClassroomViewConfig, TeacherClassroomViewModel,
    };
    use crate::monitoring_promotion::TeacherMonitoringAction;

    use super::*;

    fn classroom() -> TeacherClassroomViewModel {
        let mut model =
            TeacherClassroomViewModel::new(ClassroomViewConfig { max_devices: 4 }).unwrap();
        for id in [1_u64, 2] {
            model
                .upsert(ClassroomDeviceSnapshot {
                    source_id: MonitoringSourceId(id),
                    display_name: format!("Student {id:02}"),
                    health: DeviceHealth {
                        presence: PresenceState::Online,
                        media: if id == 1 {
                            MediaState::Streaming
                        } else {
                            MediaState::Recovering
                        },
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

    fn monitoring() -> TeacherMonitoringCoordinator {
        let mut coordinator = TeacherMonitoringCoordinator::new(
            MonitoringSchedulerConfig {
                max_sources: 4,
                max_actions_per_tick: 4,
            },
            MonitoringFanInConfig {
                max_sources: 4,
                max_updates_per_drain: 4,
            },
        )
        .unwrap();
        let profile = MonitoringProfile::for_thumbnail_at_fps(320, 180, 3).unwrap();
        for id in [1_u64, 2] {
            coordinator
                .add_source(MonitoringSourceId(id), profile, MonitoringPriority::Visible)
                .unwrap();
        }
        coordinator
    }

    fn offer() -> StreamOffer {
        StreamOffer {
            stream_id: 11,
            kind: StreamKind::Interactive as i32,
            transport: MediaTransport::UdpUnicast as i32,
            profile: Some(VideoProfile {
                width: 1280,
                height: 720,
                fps: 30,
                bitrate_kbps: 2_500,
                codec: VideoCodec::H264 as i32,
            }),
            transport_parameters: vec![1, 0x23, 0x28],
        }
    }

    fn capabilities() -> BTreeSet<Capability> {
        BTreeSet::from([Capability::UdpUnicast])
    }

    #[test]
    fn focus_projection_uses_classroom_selection_without_own_selection_state() {
        let mut classroom = classroom();
        classroom.select(Some(MonitoringSourceId(2))).unwrap();

        let focused = TeacherFocusViewModel::focused(&classroom).unwrap();
        assert_eq!(focused.source_id, MonitoringSourceId(2));
        assert_eq!(focused.display_name, "Student 02");
        assert_eq!(focused.health.presence, PresenceState::Online);
        assert_eq!(focused.health.media, MediaState::Recovering);

        classroom.select(Some(MonitoringSourceId(1))).unwrap();
        assert_eq!(
            TeacherFocusViewModel::focused(&classroom)
                .unwrap()
                .source_id,
            MonitoringSourceId(1)
        );
    }

    #[test]
    fn selected_focus_delegates_to_existing_interactive_promotion_path() {
        let mut classroom = classroom();
        classroom.select(Some(MonitoringSourceId(2))).unwrap();
        let mut monitoring = monitoring();

        TeacherFocusViewModel::request_interactive(
            &classroom,
            &mut monitoring,
            &offer(),
            &capabilities(),
        )
        .unwrap();

        let actions = monitoring.poll(0).unwrap();
        assert!(actions.iter().any(|action| {
            matches!(
                action,
                TeacherMonitoringAction::StartInteractive { source_id, offer }
                    if *source_id == MonitoringSourceId(2)
                        && offer.stream_id == 11
                        && offer.profile.width == 1280
                        && offer.profile.height == 720
            )
        }));
    }

    #[test]
    fn no_selection_fails_closed_without_starting_interactive_path() {
        let classroom = classroom();
        let mut monitoring = monitoring();

        assert_eq!(
            TeacherFocusViewModel::request_interactive(
                &classroom,
                &mut monitoring,
                &offer(),
                &capabilities()
            ),
            Err(FocusViewError::NoSelectedDevice)
        );
        let actions = monitoring.poll(0).unwrap();
        assert!(
            actions.iter().all(|action| {
                !matches!(action, TeacherMonitoringAction::StartInteractive { .. })
            })
        );
    }

    #[test]
    fn invalid_offer_is_rejected_by_existing_promotion_validation() {
        let mut classroom = classroom();
        classroom.select(Some(MonitoringSourceId(1))).unwrap();
        let mut monitoring = monitoring();
        let mut invalid = offer();
        invalid.kind = StreamKind::TeacherPresentation as i32;

        assert!(matches!(
            TeacherFocusViewModel::request_interactive(
                &classroom,
                &mut monitoring,
                &invalid,
                &capabilities()
            ),
            Err(FocusViewError::Promotion(
                TeacherMonitoringPromotionError::InvalidInteractiveOffer(_)
            ))
        ));
        assert!(matches!(
            monitoring.poll(0).unwrap().as_slice(),
            [TeacherMonitoringAction::CaptureThumbnail { source_id, .. }, ..]
                if *source_id == MonitoringSourceId(1)
                    || *source_id == MonitoringSourceId(2)
        ));
    }

    #[test]
    fn resume_selected_focus_returns_to_low_cost_thumbnail_path() {
        let mut classroom = classroom();
        classroom.select(Some(MonitoringSourceId(1))).unwrap();
        let mut monitoring = monitoring();

        TeacherFocusViewModel::request_interactive(
            &classroom,
            &mut monitoring,
            &offer(),
            &capabilities(),
        )
        .unwrap();
        let _ = monitoring.poll(0).unwrap();

        TeacherFocusViewModel::resume_thumbnail(&classroom, &mut monitoring).unwrap();
        assert!(monitoring.poll(1_000_000).unwrap().iter().any(|action| {
            matches!(
                action,
                TeacherMonitoringAction::CaptureThumbnail { source_id, .. }
                    if *source_id == MonitoringSourceId(1)
            )
        }));
    }

    #[test]
    fn resume_without_selection_fails_closed() {
        let classroom = classroom();
        let mut monitoring = monitoring();
        assert_eq!(
            TeacherFocusViewModel::resume_thumbnail(&classroom, &mut monitoring),
            Err(FocusViewError::NoSelectedDevice)
        );
    }
}
