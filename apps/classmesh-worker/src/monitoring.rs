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
        frame: &DxgiFrame,
        profile: MonitoringProfile,
    ) -> Result<Self, PresentationError> {
        let inner = PresentationPipeline::from_first_frame_with_target(
            frame,
            target_for_monitoring(profile),
        )?;
        Ok(Self { inner })
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

fn target_for_monitoring(profile: MonitoringProfile) -> PresentationTarget {
    PresentationTarget {
        max_width: u32::from(profile.width()),
        max_height: u32::from(profile.height()),
        fps: u32::from(profile.fps()),
        bitrate_bps: monitoring_bitrate_bps(profile),
    }
}

fn monitoring_bitrate_bps(profile: MonitoringProfile) -> u32 {
    const MAX_PIXEL_RATE: u64 = 640 * 360 * 5;
    const BITRATE_SPAN_BPS: u64 = (MAX_MONITORING_BITRATE_BPS - MIN_MONITORING_BITRATE_BPS) as u64;

    let pixel_rate = u64::from(profile.width())
        .saturating_mul(u64::from(profile.height()))
        .saturating_mul(u64::from(profile.fps()));
    let scaled = pixel_rate
        .saturating_mul(BITRATE_SPAN_BPS)
        .checked_div(MAX_PIXEL_RATE)
        .unwrap_or(0);
    let bitrate = u64::from(MIN_MONITORING_BITRATE_BPS).saturating_add(scaled);
    u32::try_from(bitrate.min(u64::from(MAX_MONITORING_BITRATE_BPS)))
        .unwrap_or(MAX_MONITORING_BITRATE_BPS)
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
        assert_eq!(
            (target.max_width, target.max_height, target.fps),
            (640, 360, 5)
        );
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
