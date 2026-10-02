use classmesh_capture_win::{CapturedFrameMeta, DxgiFrame};
use classmesh_video::distributor::SharedEncodedFrame;
use classmesh_video::monitoring::MonitoringProfile;

use crate::presentation::{
    PresentationError, PresentationPipeline, PresentationProfile, PresentationStats,
    PresentationTarget,
};

pub const MIN_MONITORING_BITRATE_BPS: u32 = 200_000;
pub const MAX_MONITORING_BITRATE_BPS: u32 = 800_000;

#[derive(Debug)]
pub struct MonitoringPipeline {
    inner: PresentationPipeline,
}

impl MonitoringPipeline {
    pub fn from_first_frame(
        _frame: &DxgiFrame,
        _profile: MonitoringProfile,
    ) -> Result<Self, PresentationError> {
        todo!("Phase 9B RED: wrap the existing GPU-native presentation pipeline")
    }

    #[must_use]
    pub fn profile(&self) -> PresentationProfile {
        self.inner.profile()
    }

    #[must_use]
    pub fn stats(&self) -> PresentationStats {
        self.inner.stats()
    }

    pub fn process_frame(
        &mut self,
        meta: CapturedFrameMeta,
        frame: DxgiFrame,
    ) -> Result<Vec<SharedEncodedFrame>, PresentationError> {
        self.inner.process_frame(meta, frame)
    }

    pub fn finish(&mut self) -> Result<Vec<SharedEncodedFrame>, PresentationError> {
        self.inner.finish()
    }
}

fn target_for_monitoring(_profile: MonitoringProfile) -> PresentationTarget {
    todo!("Phase 9B RED: derive a bounded monitoring target")
}

fn monitoring_bitrate_bps(_profile: MonitoringProfile) -> u32 {
    todo!("Phase 9B RED: derive bounded low-cost bitrate")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbnail_profile_maps_to_low_resolution_presentation_target() {
        let profile = MonitoringProfile::for_thumbnail_at_fps(320, 180, 3).unwrap();
        let target = target_for_monitoring(profile);
        assert_eq!(target.max_width, 320);
        assert_eq!(target.max_height, 180);
        assert_eq!(target.fps, 3);
        assert!(target.bitrate_bps >= MIN_MONITORING_BITRATE_BPS);
        assert!(target.bitrate_bps <= MAX_MONITORING_BITRATE_BPS);
    }

    #[test]
    fn largest_monitoring_profile_never_requests_presentation_resolution_or_rate() {
        let profile = MonitoringProfile::for_thumbnail_at_fps(640, 360, 5).unwrap();
        let target = target_for_monitoring(profile);
        assert_eq!((target.max_width, target.max_height, target.fps), (640, 360, 5));
        assert_eq!(target.bitrate_bps, MAX_MONITORING_BITRATE_BPS);
        assert!(target.max_width < PresentationTarget::default().max_width);
        assert!(target.max_height < PresentationTarget::default().max_height);
        assert!(target.fps < PresentationTarget::default().fps);
    }

    #[test]
    fn smaller_thumbnail_uses_less_than_maximum_monitoring_bitrate() {
        let small = MonitoringProfile::for_thumbnail_at_fps(320, 180, 3).unwrap();
        let large = MonitoringProfile::for_thumbnail_at_fps(640, 360, 5).unwrap();
        assert!(monitoring_bitrate_bps(small) < monitoring_bitrate_bps(large));
    }

    #[test]
    fn monitoring_target_is_accepted_by_existing_presentation_validation() {
        for profile in [
            MonitoringProfile::for_thumbnail_at_fps(160, 90, 2).unwrap(),
            MonitoringProfile::for_thumbnail_at_fps(320, 180, 3).unwrap(),
            MonitoringProfile::for_thumbnail_at_fps(640, 360, 5).unwrap(),
        ] {
            target_for_monitoring(profile)
                .validate()
                .expect("monitoring target must reuse the existing bounded presentation pipeline");
        }
    }
}
