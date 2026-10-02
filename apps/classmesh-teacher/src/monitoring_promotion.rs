use std::collections::{BTreeMap, BTreeSet};

use classmesh_control::stream::{
    StreamOfferError, ValidatedInteractiveStreamOffer, validate_interactive_stream_offer,
};
use classmesh_protocol::Capability;
use classmesh_protocol::control_wire::StreamOffer;
use classmesh_video::monitoring::MonitoringProfile;
use classmesh_video::monitoring_fanin::{
    MonitoringFanInConfig, MonitoringFanInError, MonitoringFanInPush, MonitoringThumbnailUpdate,
};
use classmesh_video::monitoring_scheduler::{
    MonitoringPriority, MonitoringScheduleAction, MonitoringScheduler, MonitoringSchedulerConfig,
    MonitoringSchedulerError, MonitoringSourceId,
};

use crate::monitoring::TeacherMonitoringAggregator;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeacherMonitoringAction {
    CaptureThumbnail {
        source_id: MonitoringSourceId,
        profile: MonitoringProfile,
    },
    StartInteractive {
        source_id: MonitoringSourceId,
        offer: ValidatedInteractiveStreamOffer,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherMonitoringUpdateDisposition {
    Accepted(MonitoringFanInPush),
    SuppressedForInteractive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeacherMonitoringPromotionError {
    Scheduler(MonitoringSchedulerError),
    FanIn(MonitoringFanInError),
    InvalidInteractiveOffer(StreamOfferError),
    PromotionAlreadyPending,
    PromotionAlreadyActive,
    MissingPreparedPromotion,
}

#[derive(Debug)]
pub struct TeacherMonitoringCoordinator {
    scheduler: MonitoringScheduler,
    aggregator: TeacherMonitoringAggregator,
    pending_promotions: BTreeMap<MonitoringSourceId, ValidatedInteractiveStreamOffer>,
    promoted: BTreeSet<MonitoringSourceId>,
    suppressed_updates: u64,
}

impl TeacherMonitoringCoordinator {
    pub fn new(
        _scheduler_config: MonitoringSchedulerConfig,
        _fanin_config: MonitoringFanInConfig,
    ) -> Result<Self, TeacherMonitoringPromotionError> {
        todo!("Phase 9E RED: compose monitoring scheduler and fan-in")
    }

    pub fn add_source(
        &mut self,
        _source_id: MonitoringSourceId,
        _profile: MonitoringProfile,
        _priority: MonitoringPriority,
    ) -> Result<(), TeacherMonitoringPromotionError> {
        todo!("Phase 9E RED: register monitoring source")
    }

    pub fn remove_source(&mut self, _source_id: MonitoringSourceId) -> bool {
        todo!("Phase 9E RED: remove source from monitoring and promotion state")
    }

    pub fn accept(
        &mut self,
        _update: MonitoringThumbnailUpdate,
    ) -> Result<TeacherMonitoringUpdateDisposition, TeacherMonitoringPromotionError> {
        todo!("Phase 9E RED: suppress late thumbnails during interactive promotion")
    }

    pub fn request_interactive_promotion(
        &mut self,
        _source_id: MonitoringSourceId,
        _offer: &StreamOffer,
        _negotiated_capabilities: &BTreeSet<Capability>,
    ) -> Result<(), TeacherMonitoringPromotionError> {
        todo!("Phase 9E RED: validate existing interactive offer before suppressing monitoring")
    }

    pub fn resume_thumbnail(
        &mut self,
        _source_id: MonitoringSourceId,
    ) -> Result<(), TeacherMonitoringPromotionError> {
        todo!("Phase 9E RED: resume monitoring after interactive end/failure")
    }

    pub fn poll(
        &mut self,
        _now_us: u64,
    ) -> Result<Vec<TeacherMonitoringAction>, TeacherMonitoringPromotionError> {
        todo!("Phase 9E RED: emit existing interactive action exactly once")
    }

    #[must_use]
    pub fn drain_thumbnails(&mut self) -> Vec<MonitoringThumbnailUpdate> {
        self.aggregator.drain()
    }

    #[must_use]
    pub const fn suppressed_updates(&self) -> u64 {
        self.suppressed_updates
    }
}

#[cfg(test)]
mod tests {
    use classmesh_protocol::control_wire::{
        MediaTransport, StreamKind, VideoCodec, VideoProfile,
    };
    use classmesh_video::distributor::SharedEncodedFrame;
    use classmesh_video::{Codec, EncodedFrameMeta};

    use super::*;

    fn coordinator() -> TeacherMonitoringCoordinator {
        TeacherMonitoringCoordinator::new(
            MonitoringSchedulerConfig {
                max_sources: 4,
                max_actions_per_tick: 4,
            },
            MonitoringFanInConfig {
                max_sources: 4,
                max_updates_per_drain: 4,
            },
        )
        .unwrap()
    }

    fn profile() -> MonitoringProfile {
        MonitoringProfile::for_thumbnail_at_fps(320, 180, 3).unwrap()
    }

    fn interactive_offer() -> StreamOffer {
        StreamOffer {
            stream_id: 7,
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

    fn update(source: u64, frame_id: u64) -> MonitoringThumbnailUpdate {
        MonitoringThumbnailUpdate::new(
            MonitoringSourceId(source),
            SharedEncodedFrame::new(
                EncodedFrameMeta {
                    frame_id,
                    timestamp_us: frame_id * 1_000,
                    keyframe: true,
                },
                Codec::H264,
                vec![u8::try_from(frame_id).unwrap_or(0); 8],
            ),
        )
    }

    #[test]
    fn valid_promotion_emits_existing_interactive_offer_once_and_stops_thumbnail_work() {
        let mut coordinator = coordinator();
        let source_id = MonitoringSourceId(9);
        coordinator
            .add_source(source_id, profile(), MonitoringPriority::Visible)
            .unwrap();
        coordinator
            .request_interactive_promotion(source_id, &interactive_offer(), &capabilities())
            .unwrap();

        let actions = coordinator.poll(0).unwrap();
        assert!(matches!(
            actions.as_slice(),
            [TeacherMonitoringAction::StartInteractive { source_id: actual, offer }]
                if *actual == source_id
                    && offer.stream_id == 7
                    && offer.profile.width == 1280
                    && offer.profile.height == 720
        ));
        assert!(coordinator.poll(5_000_000).unwrap().is_empty());
    }

    #[test]
    fn invalid_interactive_offer_does_not_suppress_thumbnail_monitoring() {
        let mut coordinator = coordinator();
        let source_id = MonitoringSourceId(3);
        coordinator
            .add_source(source_id, profile(), MonitoringPriority::Visible)
            .unwrap();

        let mut invalid = interactive_offer();
        invalid.kind = StreamKind::TeacherPresentation as i32;
        assert!(matches!(
            coordinator.request_interactive_promotion(source_id, &invalid, &capabilities()),
            Err(TeacherMonitoringPromotionError::InvalidInteractiveOffer(
                StreamOfferError::UnsupportedKind
            ))
        ));
        assert!(matches!(
            coordinator.poll(0).unwrap().as_slice(),
            [TeacherMonitoringAction::CaptureThumbnail { source_id: actual, .. }]
                if *actual == source_id
        ));
    }

    #[test]
    fn late_thumbnail_updates_are_suppressed_and_pending_thumbnail_is_purged() {
        let mut coordinator = coordinator();
        let source_id = MonitoringSourceId(5);
        coordinator
            .add_source(source_id, profile(), MonitoringPriority::Visible)
            .unwrap();
        assert!(matches!(
            coordinator.accept(update(5, 1)).unwrap(),
            TeacherMonitoringUpdateDisposition::Accepted(_)
        ));

        coordinator
            .request_interactive_promotion(source_id, &interactive_offer(), &capabilities())
            .unwrap();
        assert_eq!(
            coordinator.accept(update(5, 2)).unwrap(),
            TeacherMonitoringUpdateDisposition::SuppressedForInteractive
        );
        let _ = coordinator.poll(0).unwrap();
        assert!(coordinator.drain_thumbnails().is_empty());
        assert_eq!(
            coordinator.accept(update(5, 3)).unwrap(),
            TeacherMonitoringUpdateDisposition::SuppressedForInteractive
        );
        assert_eq!(coordinator.suppressed_updates(), 2);
    }

    #[test]
    fn resume_returns_failed_or_finished_interactive_source_to_thumbnail_path() {
        let mut coordinator = coordinator();
        let source_id = MonitoringSourceId(6);
        coordinator
            .add_source(source_id, profile(), MonitoringPriority::Visible)
            .unwrap();
        coordinator
            .request_interactive_promotion(source_id, &interactive_offer(), &capabilities())
            .unwrap();
        let _ = coordinator.poll(0).unwrap();

        coordinator.resume_thumbnail(source_id).unwrap();
        assert!(matches!(
            coordinator.poll(1_000_000).unwrap().as_slice(),
            [TeacherMonitoringAction::CaptureThumbnail { source_id: actual, .. }]
                if *actual == source_id
        ));
        assert!(matches!(
            coordinator.accept(update(6, 4)).unwrap(),
            TeacherMonitoringUpdateDisposition::Accepted(_)
        ));
    }

    #[test]
    fn duplicate_promotion_is_rejected_before_and_after_start_action() {
        let mut coordinator = coordinator();
        let source_id = MonitoringSourceId(8);
        coordinator
            .add_source(source_id, profile(), MonitoringPriority::Visible)
            .unwrap();

        coordinator
            .request_interactive_promotion(source_id, &interactive_offer(), &capabilities())
            .unwrap();
        assert_eq!(
            coordinator.request_interactive_promotion(
                source_id,
                &interactive_offer(),
                &capabilities()
            ),
            Err(TeacherMonitoringPromotionError::PromotionAlreadyPending)
        );

        let _ = coordinator.poll(0).unwrap();
        assert_eq!(
            coordinator.request_interactive_promotion(
                source_id,
                &interactive_offer(),
                &capabilities()
            ),
            Err(TeacherMonitoringPromotionError::PromotionAlreadyActive)
        );
    }
}
