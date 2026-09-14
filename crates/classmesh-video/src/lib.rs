#![forbid(unsafe_code)]

pub mod distributor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    Bgra8,
    Nv12,
    P010,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    H264,
    Hevc,
    Av1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoFormat {
    pub width: u16,
    pub height: u16,
    pub fps: u8,
    pub pixel_format: PixelFormat,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EncoderProbeResult {
    pub backend: String,
    pub codec: Codec,
    pub advertised_hardware: bool,
    pub gpu_native_input: bool,
    pub low_latency_accepted: bool,
    pub sustained_fps: f32,
    pub p50_encode_ms: f32,
    pub p95_encode_ms: f32,
    pub reset_ok: bool,
    pub dynamic_bitrate_ok: bool,
    pub keyframe_request_ok: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EncoderClass {
    Unsupported,
    Compatibility,
    Presentation1080p30,
    Presentation1080p60,
}

impl EncoderProbeResult {
    #[must_use]
    pub fn classify(&self) -> EncoderClass {
        if self.codec != Codec::H264
            || !self.reset_ok
            || !self.keyframe_request_ok
            || self.p95_encode_ms <= 0.0
        {
            return EncoderClass::Unsupported;
        }

        if self.sustained_fps >= 58.0
            && self.p95_encode_ms <= 12.0
            && self.gpu_native_input
            && self.advertised_hardware
        {
            return EncoderClass::Presentation1080p60;
        }

        if self.sustained_fps >= 29.0
            && self.p95_encode_ms <= 25.0
            && self.gpu_native_input
            && self.advertised_hardware
        {
            return EncoderClass::Presentation1080p30;
        }

        if self.sustained_fps >= 15.0 && self.p95_encode_ms <= 60.0 {
            EncoderClass::Compatibility
        } else {
            EncoderClass::Unsupported
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedFrameMeta {
    pub frame_id: u64,
    pub timestamp_us: u64,
    pub keyframe: bool,
}

/// Coalesces many receiver keyframe requests into a single encoder request.
#[derive(Debug)]
pub struct KeyframeCoordinator {
    min_interval_us: u64,
    last_issued_us: Option<u64>,
    pending_requests: u32,
}

impl KeyframeCoordinator {
    #[must_use]
    pub const fn new(min_interval_us: u64) -> Self {
        Self {
            min_interval_us,
            last_issued_us: None,
            pending_requests: 0,
        }
    }

    pub fn request(&mut self) {
        self.pending_requests = self.pending_requests.saturating_add(1);
    }

    #[must_use]
    pub const fn pending_requests(&self) -> u32 {
        self.pending_requests
    }

    /// Returns true when the encoder should produce one new keyframe now.
    pub fn poll(&mut self, now_us: u64) -> bool {
        if self.pending_requests == 0 {
            return false;
        }

        let allowed = self
            .last_issued_us
            .is_none_or(|last| now_us.saturating_sub(last) >= self.min_interval_us);
        if !allowed {
            return false;
        }

        self.last_issued_us = Some(now_us);
        self.pending_requests = 0;
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramePacer {
    frame_interval_us: u64,
    next_due_us: Option<u64>,
}

impl FramePacer {
    /// # Panics
    /// Panics if `fps` is zero.
    #[must_use]
    pub fn new(fps: u32) -> Self {
        assert!(fps > 0, "fps must be non-zero");
        Self {
            frame_interval_us: 1_000_000 / u64::from(fps),
            next_due_us: None,
        }
    }

    /// Returns whether a frame should be emitted at `now_us` and advances the pacing clock.
    pub fn should_emit(&mut self, now_us: u64) -> bool {
        let Some(next_due) = self.next_due_us else {
            self.next_due_us = Some(now_us.saturating_add(self.frame_interval_us));
            return true;
        };

        if now_us < next_due {
            return false;
        }

        // Do not replay missed frames. Move the deadline forward from "now" to avoid bursts.
        self.next_due_us = Some(now_us.saturating_add(self.frame_interval_us));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe() -> EncoderProbeResult {
        EncoderProbeResult {
            backend: "test".into(),
            codec: Codec::H264,
            advertised_hardware: true,
            gpu_native_input: true,
            low_latency_accepted: true,
            sustained_fps: 30.5,
            p50_encode_ms: 4.0,
            p95_encode_ms: 8.0,
            reset_ok: true,
            dynamic_bitrate_ok: true,
            keyframe_request_ok: true,
        }
    }

    #[test]
    fn encoder_classification_requires_measured_performance() {
        assert_eq!(probe().classify(), EncoderClass::Presentation1080p30);
        let mut slow = probe();
        slow.sustained_fps = 12.0;
        assert_eq!(slow.classify(), EncoderClass::Unsupported);
    }

    #[test]
    fn many_keyframe_requests_are_coalesced() {
        let mut coordinator = KeyframeCoordinator::new(500_000);
        coordinator.request();
        coordinator.request();
        coordinator.request();
        assert_eq!(coordinator.pending_requests(), 3);
        assert!(coordinator.poll(1_000_000));
        assert_eq!(coordinator.pending_requests(), 0);
        coordinator.request();
        assert!(!coordinator.poll(1_200_000));
        assert!(coordinator.poll(1_500_000));
    }

    #[test]
    fn pacer_never_bursts_missed_frames() {
        let mut pacer = FramePacer::new(30);
        assert!(pacer.should_emit(0));
        assert!(!pacer.should_emit(1_000));
        assert!(pacer.should_emit(50_000));
        assert!(!pacer.should_emit(50_001));
    }
}
