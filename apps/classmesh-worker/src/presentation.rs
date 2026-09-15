use std::error::Error;
use std::fmt;

use classmesh_capture_win::{CapturedFrameMeta, DxgiFrame};
use classmesh_codec_win::gpu::{GpuBgraToNv12Converter, GpuNv12Config};
use classmesh_codec_win::mf::{
    MfH264EncoderConfig, MfPlatform, enumerate_h264_hardware_encoders,
};
use classmesh_codec_win::mf_async::{MfAsyncH264Encoder, MfEncodedOutput, MfSubmitError};
use classmesh_codec_win::surface_pool::SurfacePool;
use classmesh_video::distributor::SharedEncodedFrame;
use windows::Win32::Graphics::Direct3D11::{D3D11_TEXTURE2D_DESC, ID3D11Device, ID3D11Texture2D};

const DEFAULT_POOL_SIZE: usize = 4;
const TARGET_FPS: u32 = 30;
const TARGET_BITRATE_BPS: u32 = 5_000_000;
const MAX_WIDTH: u32 = 1920;
const MAX_HEIGHT: u32 = 1080;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationProfile {
    pub source_width: u32,
    pub source_height: u32,
    pub target_width: u32,
    pub target_height: u32,
    pub fps: u32,
    pub bitrate_bps: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PresentationStats {
    pub captured_frames: u64,
    pub submitted_frames: u64,
    pub rate_dropped_frames: u64,
    pub pool_dropped_frames: u64,
    pub encoded_frames: u64,
    pub keyframes: u64,
    pub encoded_bytes: u64,
    pub in_flight_surfaces: usize,
}

#[derive(Debug)]
pub enum PresentationError {
    Windows(windows::core::Error),
    NoHardwareEncoder,
    SurfacePoolInvariant,
}

impl fmt::Display for PresentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows(error) => write!(f, "Windows media error: {error}"),
            Self::NoHardwareEncoder => write!(f, "no hardware H.264 Media Foundation encoder found"),
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
    encoder_name: String,
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
            .field("encoder_name", &self.encoder_name)
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
        let device: ID3D11Device = unsafe { frame.texture().GetDevice()? };
        let mut source_desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { frame.texture().GetDesc(&mut source_desc) };

        let (target_width, target_height) = bounded_even_size(
            source_desc.Width,
            source_desc.Height,
            MAX_WIDTH,
            MAX_HEIGHT,
        );
        let profile = PresentationProfile {
            source_width: source_desc.Width,
            source_height: source_desc.Height,
            target_width,
            target_height,
            fps: TARGET_FPS,
            bitrate_bps: TARGET_BITRATE_BPS,
        };

        let platform = MfPlatform::startup()?;
        let activations = enumerate_h264_hardware_encoders()?;
        let activation = activations
            .into_iter()
            .next()
            .ok_or(PresentationError::NoHardwareEncoder)?;
        let encoder_name = activation.candidate().name.clone();

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
            encoder_name,
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
        &self.encoder_name
    }

    #[must_use]
    pub fn stats(&self) -> PresentationStats {
        let mut stats = self.stats;
        stats.in_flight_surfaces = self.pool.in_flight();
        stats
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
        let result = self.encoder.finish()?;
        let mut encoded = Vec::new();
        self.consume_outputs(result.outputs, &mut encoded)?;
        for surface in result.reclaimed_surfaces {
            self.release_surface(surface)?;
        }
        Ok(encoded)
    }

    fn is_due(&mut self, timestamp_us: u64) -> bool {
        if let Some(next_due) = self.next_submit_timestamp_us
            && timestamp_us < next_due
        {
            return false;
        }
        self.next_submit_timestamp_us = Some(timestamp_us.saturating_add(self.frame_interval_us));
        true
    }

    fn consume_outputs(
        &mut self,
        outputs: Vec<MfEncodedOutput>,
        encoded: &mut Vec<SharedEncodedFrame>,
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
            encoded.push(output.frame);
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

fn bounded_even_size(width: u32, height: u32, max_width: u32, max_height: u32) -> (u32, u32) {
    let width = width.max(2);
    let height = height.max(2);
    let max_width = max_width.max(2);
    let max_height = max_height.max(2);

    let (scaled_width, scaled_height) = if width <= max_width && height <= max_height {
        (width, height)
    } else if u64::from(max_width) * u64::from(height)
        <= u64::from(max_height) * u64::from(width)
    {
        let scaled_height =
            (u64::from(height) * u64::from(max_width) / u64::from(width)) as u32;
        (max_width, scaled_height)
    } else {
        let scaled_width =
            (u64::from(width) * u64::from(max_height) / u64::from(height)) as u32;
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
