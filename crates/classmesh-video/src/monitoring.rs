pub const MIN_MONITORING_FPS: u8 = 2;
pub const DEFAULT_MONITORING_FPS: u8 = 3;
pub const MAX_MONITORING_FPS: u8 = 5;
pub const MAX_THUMBNAIL_WIDTH: u16 = 640;
pub const MAX_THUMBNAIL_HEIGHT: u16 = 360;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonitoringProfile {
    width: u16,
    height: u16,
    fps: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitoringProfileError {
    InvalidTileSize,
    InvalidFps(u8),
}

impl MonitoringProfile {
    pub fn for_thumbnail(
        tile_width: u16,
        tile_height: u16,
    ) -> Result<Self, MonitoringProfileError> {
        Self::for_thumbnail_at_fps(tile_width, tile_height, DEFAULT_MONITORING_FPS)
    }

    pub fn for_thumbnail_at_fps(
        tile_width: u16,
        tile_height: u16,
        fps: u8,
    ) -> Result<Self, MonitoringProfileError> {
        if tile_width == 0 || tile_height == 0 {
            return Err(MonitoringProfileError::InvalidTileSize);
        }
        if !(MIN_MONITORING_FPS..=MAX_MONITORING_FPS).contains(&fps) {
            return Err(MonitoringProfileError::InvalidFps(fps));
        }

        Ok(Self {
            width: tile_width.min(MAX_THUMBNAIL_WIDTH),
            height: tile_height.min(MAX_THUMBNAIL_HEIGHT),
            fps,
        })
    }

    #[must_use]
    pub const fn width(&self) -> u16 {
        self.width
    }

    #[must_use]
    pub const fn height(&self) -> u16 {
        self.height
    }

    #[must_use]
    pub const fn fps(&self) -> u8 {
        self.fps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_matches_small_tile_without_full_resolution_work() {
        let profile = MonitoringProfile::for_thumbnail(320, 180).unwrap();
        assert_eq!(profile.width(), 320);
        assert_eq!(profile.height(), 180);
        assert_eq!(profile.fps(), DEFAULT_MONITORING_FPS);
    }

    #[test]
    fn oversized_tile_is_capped_to_monitoring_bounds() {
        let profile = MonitoringProfile::for_thumbnail(1920, 1080).unwrap();
        assert_eq!(profile.width(), MAX_THUMBNAIL_WIDTH);
        assert_eq!(profile.height(), MAX_THUMBNAIL_HEIGHT);
        assert!(profile.fps() <= MAX_MONITORING_FPS);
    }

    #[test]
    fn invalid_size_and_fps_fail_closed() {
        assert_eq!(
            MonitoringProfile::for_thumbnail(0, 180),
            Err(MonitoringProfileError::InvalidTileSize)
        );
        assert_eq!(
            MonitoringProfile::for_thumbnail_at_fps(320, 180, 1),
            Err(MonitoringProfileError::InvalidFps(1))
        );
        assert_eq!(
            MonitoringProfile::for_thumbnail_at_fps(320, 180, 6),
            Err(MonitoringProfileError::InvalidFps(6))
        );
    }
}
