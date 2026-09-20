use std::error::Error;
use std::fmt;
use std::time::Duration;

use classmesh_capture_win::{CapturedFrameMeta, DxgiFrame};
use classmesh_codec_win::gpu::{GpuBgraToNv12Converter, GpuNv12Config};
use classmesh_codec_win::mf::{MfH264EncoderConfig, MfPlatform, enumerate_h264_hardware_encoders};
use classmesh_codec_win::mf_async::{MfAsyncH264Encoder, MfEncodedOutput, MfSubmitError};
use classmesh_codec_win::surface_pool::SurfacePool;
use classmesh_codec_win::{EncoderBenchmarkConfig, EncoderCandidate};
use classmesh_core::adaptation::{
    MAX_STREAM_BITRATE_KBPS, MAX_STREAM_FPS, MAX_STREAM_HEIGHT, MAX_STREAM_WIDTH,
    StreamProfile as AdaptiveStreamProfile,
};
use classmesh_video::distributor::SharedEncodedFrame;
use windows::Win32::Graphics::Direct3D11::{D3D11_TEXTURE2D_DESC, ID3D11Device, ID3D11Texture2D};

const DEFAULT_POOL_SIZE: usize = 4;
const DEFAULT_TARGET_FPS: u32 = 30;
const DEFAULT_TARGET_BITRATE_BPS: u32 = 5_000_000;
const MAX_TARGET_WIDTH: u32 = MAX_STREAM_WIDTH as u32;
const MAX_TARGET_HEIGHT: u32 = MAX_STREAM_HEIGHT as u32;
const MAX_TARGET_FPS: u32 = MAX_STREAM_FPS as u32;
const MAX_TARGET_BITRATE_BPS: u32 = MAX_STREAM_BITRATE_KBPS * 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationTarget {
    pub max_width: u32,
    pub max_height: u32,
    pub fps: u32,
    pub bitrate_bps: u32,
}

impl Default for PresentationTarget {
    fn default() -> Self {
        Self {
            max_width: MAX_TARGET_WIDTH,
            max_height: MAX_TARGET_HEIGHT,
            fps: DEFAULT_TARGET_FPS,
            bitrate_bps: DEFAULT_TARGET_BITRATE_BPS,
        }
    }
}

impl TryFrom<AdaptiveStreamProfile> for PresentationTarget {
    type Error = PresentationError;

    fn try_from(profile: AdaptiveStreamProfile) -> Result<Self, Self::Error> {
        let profile = profile
            .validate()
            .map_err(|_| PresentationError::InvalidTargetProfile)?;
        let bitrate_bps = profile
            .bitrate_kbps
            .checked_mul(1_000)
            .ok_or(PresentationError::InvalidTargetProfile)?;
        let target = Self {
            max_width: u32::from(profile.width),
            max_height: u32::from(profile.height),
            fps: u32::from(profile.fps),
            bitrate_bps,
        };
        target.validate()?;
        Ok(target)
    }
}

impl TryFrom<EncoderBenchmarkConfig> for PresentationTarget {
    type Error = PresentationError;

    fn try_from(config: EncoderBenchmarkConfig) -> Result<Self, Self::Error> {
        let bitrate_bps = config
            .bitrate_kbps
            .checked_mul(1_000)
            .ok_or(PresentationError::InvalidTargetProfile)?;
        let target = Self {
            max_width: u32::from(config.width),
            max_height: u32::from(config.height),
            fps: u32::from(config.target_fps),
            bitrate_bps,
        };
        target.validate()?;
        Ok(target)
    }
}

impl PresentationTarget {
    fn validate(self) -> Result<(), PresentationError> {
        if self.max_width < 2
            || self.max_height < 2
            || self.max_width > MAX_TARGET_WIDTH
            || self.max_height > MAX_TARGET_HEIGHT
            || !(1..=MAX_TARGET_FPS).contains(&self.fps)
            || self.bitrate_bps == 0
            || self.bitrate_bps > MAX_TARGET_BITRATE_BPS
        {
            return Err(PresentationError::InvalidTargetProfile);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationProfile {
    pub source_width: u32,
    pub source_height: u32,
    pub target_width: u32,
    pub target_height: u32,
    pub fps: u32,
    pub bitrate_bps: u32,
}

#[derive(Debug)]
pub struct PresentationEncodedOutput {
    pub frame: SharedEncodedFrame,
    pub encode_latency: Duration,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PresentationStats {
    pub captured_frames: u64,
    pub submitted_frames: u64,
    pub rate_dropped_frames: u64,
    pub pool_dropped_frames: u64,
    pub encoded_frames: u64,
    pub keyframes: u64,
    pub keyframe_requests: u64,
    pub encoded_bytes: u64,
    pub in_flight_surfaces: usize,
}

#[derive(Debug)]
pub enum PresentationError {
    Windows(windows::core::Error),
    NoHardwareEncoder,
    InvalidTargetProfile,
    SurfacePoolInvariant,
}

impl fmt::Display for PresentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows(error) => write!(f, "Windows media error: {error}"),
            Self::NoHardwareEncoder => {
                write!(f, "no hardware H.264 Media Foundation encoder found")
            }
            Self::InvalidTargetProfile => write!(f, "invalid bounded H.264 target profile"),
            Self::SurfacePoolInvariant => write!(f, "bounded NV12 surface pool invariant failed"),
        }
    }
}

impl Error for PresentationError {}

impl From<windows::core::Error> for PresentationError {
    fn from(value: windows::core::Error) -> Self {
        Self::Windows(value)
    }
}

/// Live Windows teacher-presentation media path.
///
/// The pipeline preserves GPU residency from Desktop Duplication through BGRA→NV12 conversion and
/// hardware H.264 input. NV12 surfaces are preallocated and bounded; when every surface is in-flight
/// the current capture frame is dropped rather than allowing latency or memory to grow.
pub struct PresentationPipeline {
    converter: GpuBgraToNv12Converter,
    pool: SurfacePool<ID3D11Texture2D>,
    encoder: MfAsyncH264Encoder,
    encoder_candidate: EncoderCandidate,
    profile: PresentationProfile,
    stats: PresentationStats,
    next_submit_timestamp_us: Option<u64>,
    frame_interval_us: u64,
    // Media Foundation must remain initialized until every encoder/sample COM object above drops.
    // Struct fields are dropped in declaration order, so keep the platform guard last.
    _platform: MfPlatform,
}

impl fmt::Debug for PresentationPipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PresentationPipeline")
            .field("encoder_candidate", &self.encoder_candidate)
            .field("profile", &self.profile)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl PresentationPipeline {
    /// Creates a presentation pipeline using the D3D11 device that owns the first DXGI frame.
    ///
    /// The actual Desktop Duplication texture dimensions are used instead of assuming that desktop
    /// coordinates and resource dimensions are identical; this matters for rotated displays.
    pub fn from_first_frame(frame: &DxgiFrame) -> Result<Self, PresentationError> {
        Self::from_first_frame_with_target(frame, PresentationTarget::default())
    }

    /// Creates the GPU-native H.264 pipeline for a bounded target profile.
    ///
    /// The requested dimensions are treated as maximum bounds. Source aspect ratio is preserved and
    /// smaller captures are never upscaled.
    pub fn from_first_frame_with_target(
        frame: &DxgiFrame,
        target: PresentationTarget,
    ) -> Result<Self, PresentationError> {
        let device: ID3D11Device = unsafe { frame.texture().GetDevice()? };
        let mut source_desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { frame.texture().GetDesc(&mut source_desc) };

        let profile = profile_for_source(source_desc.Width, source_desc.Height, target)?;

        let platform = MfPlatform::startup()?;
        let activations = enumerate_h264_hardware_encoders()?;
        let activation = activations
            .into_iter()
            .next()
            .ok_or(PresentationError::NoHardwareEncoder)?;
        let encoder_candidate = activation.candidate().clone();

        let gpu_config = GpuNv12Config {
            source_width: profile.source_width,
            source_height: profile.source_height,
            target_width: profile.target_width,
            target_height: profile.target_height,
            fps_numerator: profile.fps,
            fps_denominator: 1,
        };
        let converter = GpuBgraToNv12Converter::new(&device, gpu_config)?;

        let mut surfaces = Vec::with_capacity(DEFAULT_POOL_SIZE);
        for _ in 0..DEFAULT_POOL_SIZE {
            surfaces.push(converter.create_output_texture()?);
        }
        let pool = SurfacePool::from_items(surfaces);

        let encoder_config = MfH264EncoderConfig {
            width: profile.target_width,
            height: profile.target_height,
            fps_numerator: profile.fps,
            fps_denominator: 1,
            bitrate_bps: profile.bitrate_bps,
        };
        let encoder = MfAsyncH264Encoder::new(&activation, &device, encoder_config)?;
        let frame_interval_us = 1_000_000_u64 / u64::from(profile.fps.max(1));

        Ok(Self {
            converter,
            pool,
            encoder,
            encoder_candidate,
            profile,
            stats: PresentationStats::default(),
            next_submit_timestamp_us: None,
            frame_interval_us,
            _platform: platform,
        })
    }

    #[must_use]
    pub const fn profile(&self) -> PresentationProfile {
        self.profile
    }

    #[must_use]
    pub fn encoder_name(&self) -> &str {
        &self.encoder_candidate.name
    }

    #[must_use]
    pub const fn encoder_candidate(&self) -> &EncoderCandidate {
        &self.encoder_candidate
    }

    #[must_use]
    pub const fn low_latency_accepted(&self) -> bool {
        self.encoder.low_latency_accepted()
    }

    #[must_use]
    pub fn stats(&self) -> PresentationStats {
        let mut stats = self.stats;
        stats.in_flight_surfaces = self.pool.in_flight();
        stats
    }

    /// Requests that the hardware H.264 encoder make the next submitted frame a keyframe.
    ///
    /// Callers are expected to coalesce and rate-limit receiver requests before invoking this
    /// method. ClassMesh keeps that policy outside the hardware encoder so the same coordinator can
    /// serve unicast, multicast, and future QUIC control-plane feedback.
    pub fn request_keyframe(&mut self) -> Result<(), PresentationError> {
        self.encoder.force_next_keyframe()?;
        self.stats.keyframe_requests = self.stats.keyframe_requests.saturating_add(1);
        Ok(())
    }

    /// Converts and submits one captured Desktop Duplication frame.
    ///
    /// Completed H.264 access units already waiting in the encoder are returned first. A 60 Hz
    /// capture source feeding a 30 fps presentation stream is explicitly paced by capture timestamp;
    /// stale intermediate capture frames are dropped rather than queued.
    pub fn process_frame(
        &mut self,
        meta: CapturedFrameMeta,
        frame: DxgiFrame,
    ) -> Result<Vec<SharedEncodedFrame>, PresentationError> {
        Ok(self
            .process_frame_with_metrics(meta, frame)?
            .into_iter()
            .map(|output| output.frame)
            .collect())
    }

    /// Same as `process_frame` but preserves measured submission-to-output latency for bounded
    /// encoder capability validation.
    pub fn process_frame_with_metrics(
        &mut self,
        meta: CapturedFrameMeta,
        frame: DxgiFrame,
    ) -> Result<Vec<PresentationEncodedOutput>, PresentationError> {
        self.stats.captured_frames = self.stats.captured_frames.saturating_add(1);

        let mut encoded = Vec::new();
        let ready = self.encoder.poll_ready()?;
        self.consume_outputs(ready, &mut encoded)?;

        if !self.is_due(meta.capture_timestamp_us) {
            self.stats.rate_dropped_frames = self.stats.rate_dropped_frames.saturating_add(1);
            return Ok(encoded);
        }

        let Some(surface) = self.pool.try_acquire() else {
            self.stats.pool_dropped_frames = self.stats.pool_dropped_frames.saturating_add(1);
            return Ok(encoded);
        };

        if let Err(error) = self.converter.convert(frame.texture(), &surface) {
            self.release_surface(surface)?;
            return Err(error.into());
        }

        // The converter has copied the Desktop Duplication texture into its own GPU resource. Drop
        // the acquired DXGI frame before waiting on the async encoder so ReleaseFrame happens early.
        drop(frame);

        match self
            .encoder
            .encode_surface(meta.frame_id, meta.capture_timestamp_us, surface)
        {
            Ok(outputs) => {
                self.stats.submitted_frames = self.stats.submitted_frames.saturating_add(1);
                self.consume_outputs(outputs, &mut encoded)?;
            }
            Err(error) => {
                self.handle_submit_error(error)?;
            }
        }

        Ok(encoded)
    }

    /// Drains the encoder at the end of a probe/session and returns its final access units.
    pub fn finish(&mut self) -> Result<Vec<SharedEncodedFrame>, PresentationError> {
        Ok(self
            .finish_with_metrics()?
            .into_iter()
            .map(|output| output.frame)
            .collect())
    }

    /// Drains the encoder while preserving measured submission-to-output latency evidence.
    pub fn finish_with_metrics(
        &mut self,
    ) -> Result<Vec<PresentationEncodedOutput>, PresentationError> {
        let result = self.encoder.finish()?;
        let mut encoded = Vec::new();
        self.consume_outputs(result.outputs, &mut encoded)?;
        for surface in result.reclaimed_surfaces {
            self.release_surface(surface)?;
        }
        Ok(encoded)
    }

    fn is_due(&mut self, timestamp_us: u64) -> bool {
        if let Some(next_due) = self.next_submit_timestamp_us {
            if timestamp_us < next_due {
                return false;
            }
        }
        self.next_submit_timestamp_us = Some(timestamp_us.saturating_add(self.frame_interval_us));
        true
    }

    fn consume_outputs(
        &mut self,
        outputs: Vec<MfEncodedOutput>,
        encoded: &mut Vec<PresentationEncodedOutput>,
    ) -> Result<(), PresentationError> {
        for output in outputs {
            self.stats.encoded_frames = self.stats.encoded_frames.saturating_add(1);
            self.stats.encoded_bytes = self
                .stats
                .encoded_bytes
                .saturating_add(u64::try_from(output.frame.data.len()).unwrap_or(u64::MAX));
            if output.frame.meta.keyframe {
                self.stats.keyframes = self.stats.keyframes.saturating_add(1);
            }
            self.release_surface(output.recycled_surface)?;
            encoded.push(PresentationEncodedOutput {
                frame: output.frame,
                encode_latency: output.encode_latency,
            });
        }
        Ok(())
    }

    fn handle_submit_error(&mut self, error: MfSubmitError) -> Result<(), PresentationError> {
        let MfSubmitError {
            error,
            rejected_surface,
        } = error;

        if let Some(surface) = rejected_surface {
            self.release_surface(surface)?;
        } else if let Ok(reclaimed) = self.encoder.abort_and_reclaim() {
            for surface in reclaimed {
                self.release_surface(surface)?;
            }
        }

        Err(PresentationError::Windows(error))
    }

    fn release_surface(&mut self, surface: ID3D11Texture2D) -> Result<(), PresentationError> {
        self.pool
            .release(surface)
            .map_err(|_| PresentationError::SurfacePoolInvariant)
    }
}

fn profile_for_source(
    source_width: u32,
    source_height: u32,
    target: PresentationTarget,
) -> Result<PresentationProfile, PresentationError> {
    target.validate()?;
    let (target_width, target_height) = bounded_even_size(
        source_width,
        source_height,
        target.max_width,
        target.max_height,
    );
    Ok(PresentationProfile {
        source_width,
        source_height,
        target_width,
        target_height,
        fps: target.fps,
        bitrate_bps: target.bitrate_bps,
    })
}

fn bounded_even_size(width: u32, height: u32, max_width: u32, max_height: u32) -> (u32, u32) {
    let width = width.max(2);
    let height = height.max(2);
    let max_width = max_width.max(2);
    let max_height = max_height.max(2);

    let (scaled_width, scaled_height) = if width <= max_width && height <= max_height {
        (width, height)
    } else if u64::from(max_width) * u64::from(height) <= u64::from(max_height) * u64::from(width) {
        let scaled_height = (u64::from(height) * u64::from(max_width) / u64::from(width)) as u32;
        (max_width, scaled_height)
    } else {
        let scaled_width = (u64::from(width) * u64::from(max_height) / u64::from(height)) as u32;
        (scaled_width, max_height)
    };

    (even_floor(scaled_width), even_floor(scaled_height))
}

const fn even_floor(value: u32) -> u32 {
    let even = value & !1;
    if even < 2 { 2 } else { even }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_target_matches_existing_presentation_profile() {
        let target = PresentationTarget::default();
        assert_eq!(target.max_width, 1920);
        assert_eq!(target.max_height, 1080);
        assert_eq!(target.fps, 30);
        assert_eq!(target.bitrate_bps, 5_000_000);
    }

    #[test]
    fn adaptive_stream_profile_converts_kbps_to_encoder_bps() {
        let target = PresentationTarget::try_from(AdaptiveStreamProfile::new(960, 540, 30, 1_500))
            .expect("focused profile should convert");
        assert_eq!(target.max_width, 960);
        assert_eq!(target.max_height, 540);
        assert_eq!(target.fps, 30);
        assert_eq!(target.bitrate_bps, 1_500_000);
    }

    #[test]
    fn benchmark_config_converts_to_the_same_bounded_presentation_target() {
        let target = PresentationTarget::try_from(EncoderBenchmarkConfig::compatibility_720p30())
            .expect("benchmark target");
        assert_eq!(
            target,
            PresentationTarget {
                max_width: 1280,
                max_height: 720,
                fps: 30,
                bitrate_bps: 2_500_000,
            }
        );
    }

    #[test]
    fn focused_target_resolves_without_upscale_or_aspect_distortion() {
        let target = PresentationTarget {
            max_width: 960,
            max_height: 540,
            fps: 30,
            bitrate_bps: 1_500_000,
        };
        let profile = profile_for_source(1920, 1200, target).expect("valid target");
        assert_eq!((profile.target_width, profile.target_height), (864, 540));
        assert_eq!(profile.fps, 30);
        assert_eq!(profile.bitrate_bps, 1_500_000);

        let smaller = profile_for_source(640, 360, target).expect("valid target");
        assert_eq!((smaller.target_width, smaller.target_height), (640, 360));
    }

    #[test]
    fn target_profile_rejects_unbounded_or_zero_values() {
        for target in [
            PresentationTarget {
                max_width: 0,
                ..PresentationTarget::default()
            },
            PresentationTarget {
                max_width: 3840,
                ..PresentationTarget::default()
            },
            PresentationTarget {
                fps: 0,
                ..PresentationTarget::default()
            },
            PresentationTarget {
                fps: 61,
                ..PresentationTarget::default()
            },
            PresentationTarget {
                bitrate_bps: 0,
                ..PresentationTarget::default()
            },
            PresentationTarget {
                bitrate_bps: 50_000_001,
                ..PresentationTarget::default()
            },
        ] {
            assert!(matches!(
                profile_for_source(1920, 1080, target),
                Err(PresentationError::InvalidTargetProfile)
            ));
        }
    }

    #[test]
    fn profile_caps_1440p_at_1080p_without_aspect_distortion() {
        assert_eq!(bounded_even_size(2560, 1440, 1920, 1080), (1920, 1080));
    }

    #[test]
    fn profile_preserves_sixteen_by_ten_inside_1080_height() {
        assert_eq!(bounded_even_size(1920, 1200, 1920, 1080), (1728, 1080));
    }

    #[test]
    fn profile_never_upscales_smaller_capture() {
        assert_eq!(bounded_even_size(1366, 768, 1920, 1080), (1366, 768));
    }

    #[test]
    fn nv12_geometry_is_forced_even() {
        assert_eq!(bounded_even_size(1365, 767, 1920, 1080), (1364, 766));
    }
}
