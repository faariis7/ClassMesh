use std::fmt;
use std::time::Instant;

use classmesh_capture_win::{AdapterCapabilityIdentity, CapturedFrameMeta, DxgiFrame};
use classmesh_codec_win::{
    BenchmarkCapabilities, BoundedEncoderBenchmark, EncoderBenchmarkConfig, EncoderBenchmarkResult,
    EncoderCandidate, EncoderCapabilityCacheKey, summarize_benchmark,
};
use classmesh_video::{Codec, EncoderClass};

use crate::presentation::{PresentationPipeline, PresentationProfile, PresentationTarget};

const KEYFRAME_AFTER_SUBMISSIONS: usize = 30;
const RESET_MAX_SUBMISSIONS: usize = 30;

#[derive(Debug)]
pub enum RuntimeEncoderBenchmarkError {
    Presentation(crate::presentation::PresentationError),
    InvalidAccumulator(classmesh_codec_win::BenchmarkAccumulatorError),
    InvalidSummary(classmesh_codec_win::BenchmarkError),
    InvalidProfile,
    ResetMismatch,
}

impl fmt::Display for RuntimeEncoderBenchmarkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Presentation(error) => write!(f, "presentation benchmark failed: {error}"),
            Self::InvalidAccumulator(error) => {
                write!(f, "encoder benchmark accumulation failed: {error:?}")
            }
            Self::InvalidSummary(error) => {
                write!(f, "encoder benchmark summary failed: {error:?}")
            }
            Self::InvalidProfile => write!(f, "encoder benchmark target is not representable"),
            Self::ResetMismatch => write!(f, "encoder benchmark reset/recreate target changed"),
        }
    }
}

impl std::error::Error for RuntimeEncoderBenchmarkError {}

impl From<crate::presentation::PresentationError> for RuntimeEncoderBenchmarkError {
    fn from(value: crate::presentation::PresentationError) -> Self {
        Self::Presentation(value)
    }
}

impl From<classmesh_codec_win::BenchmarkAccumulatorError> for RuntimeEncoderBenchmarkError {
    fn from(value: classmesh_codec_win::BenchmarkAccumulatorError) -> Self {
        Self::InvalidAccumulator(value)
    }
}

impl From<classmesh_codec_win::BenchmarkError> for RuntimeEncoderBenchmarkError {
    fn from(value: classmesh_codec_win::BenchmarkError) -> Self {
        Self::InvalidSummary(value)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MeasuredEncoderEvidence {
    pub key: EncoderCapabilityCacheKey,
    pub result: EncoderBenchmarkResult,
}

#[derive(Debug)]
struct PendingReset {
    result: EncoderBenchmarkResult,
    candidate: EncoderCandidate,
    profile: PresentationProfile,
    key: EncoderCapabilityCacheKey,
    submissions: usize,
    output_observed: bool,
}

#[derive(Debug)]
pub struct RuntimeEncoderBenchmark {
    adapter: AdapterCapabilityIdentity,
    config: EncoderBenchmarkConfig,
    accumulator: Option<BoundedEncoderBenchmark>,
    pipeline: Option<PresentationPipeline>,
    started: Option<Instant>,
    non_keyframe_observed: bool,
    keyframe_request_attempted: bool,
    keyframe_request_pending: bool,
    keyframe_request_frame: Option<u64>,
    keyframe_observed: bool,
    pending_reset: Option<PendingReset>,
    completed: bool,
}

impl RuntimeEncoderBenchmark {
    pub fn compatibility_720p30(
        adapter: AdapterCapabilityIdentity,
    ) -> Result<Self, RuntimeEncoderBenchmarkError> {
        let config = EncoderBenchmarkConfig::compatibility_720p30();
        Ok(Self {
            adapter,
            config,
            accumulator: Some(BoundedEncoderBenchmark::from_config(config)?),
            pipeline: None,
            started: None,
            non_keyframe_observed: false,
            keyframe_request_attempted: false,
            keyframe_request_pending: false,
            keyframe_request_frame: None,
            keyframe_observed: false,
            pending_reset: None,
            completed: false,
        })
    }

    #[must_use]
    pub const fn is_completed(&self) -> bool {
        self.completed
    }

    pub fn process_frame(
        &mut self,
        meta: CapturedFrameMeta,
        frame: DxgiFrame,
    ) -> Result<Option<MeasuredEncoderEvidence>, RuntimeEncoderBenchmarkError> {
        if self.completed {
            drop(frame);
            return Ok(None);
        }

        if self.pipeline.is_none() {
            let target = PresentationTarget::try_from(self.config)?;
            let created = PresentationPipeline::from_first_frame_with_target(&frame, target)?;
            if let Some(pending) = self.pending_reset.as_ref() {
                if created.encoder_candidate() != &pending.candidate
                    || !same_target(created.profile(), pending.profile)
                {
                    self.completed = true;
                    drop(frame);
                    return Err(RuntimeEncoderBenchmarkError::ResetMismatch);
                }
            } else if self.started.is_none() {
                self.started = Some(Instant::now());
            }
            self.pipeline = Some(created);
        }

        let active = self
            .pipeline
            .as_mut()
            .expect("benchmark pipeline initialized");

        if self.pending_reset.is_none()
            && self
                .accumulator
                .as_ref()
                .is_some_and(|benchmark| benchmark.submitted() >= KEYFRAME_AFTER_SUBMISSIONS)
            && self.non_keyframe_observed
            && !self.keyframe_request_attempted
        {
            self.keyframe_request_attempted = true;
            self.keyframe_request_pending = active.request_keyframe().is_ok();
        }

        let submitted_before = active.stats().submitted_frames;
        let outputs = active.process_frame_with_metrics(meta, frame)?;
        let submitted_after = active.stats().submitted_frames;

        if self.keyframe_request_pending && submitted_after > submitted_before {
            self.keyframe_request_frame = Some(meta.frame_id);
            self.keyframe_request_pending = false;
        }

        if let Some(accumulator) = self.accumulator.as_mut() {
            for _ in submitted_before..submitted_after {
                if !accumulator.record_submission() {
                    break;
                }
            }
        }

        if let Some(pending) = self.pending_reset.as_mut() {
            pending.submissions = pending.submissions.saturating_add(
                usize::try_from(submitted_after.saturating_sub(submitted_before))
                    .unwrap_or(usize::MAX),
            );
        }

        for output in outputs {
            if let Some(accumulator) = self.accumulator.as_mut() {
                accumulator.record_output(output.encode_latency)?;
            }
            if let Some(pending) = self.pending_reset.as_mut() {
                pending.output_observed = true;
            }
            self.non_keyframe_observed |= !output.frame.meta.keyframe;
            self.keyframe_observed |= self.keyframe_request_frame.is_some_and(|frame_id| {
                frame_id == output.frame.meta.frame_id && output.frame.meta.keyframe
            });
        }

        if self.pending_reset.as_ref().is_some_and(|pending| {
            pending.output_observed || pending.submissions >= RESET_MAX_SUBMISSIONS
        }) {
            let tail = active.finish_with_metrics()?;
            if let Some(pending) = self.pending_reset.as_mut() {
                pending.output_observed |= !tail.is_empty();
            }
            let mut pending = self.pending_reset.take().expect("pending reset exists");
            pending.result.probe.reset_ok = pending.output_observed;
            pending.result.class =
                class_for_actual_target(pending.result.probe.classify(), pending.profile);
            self.pipeline = None;
            self.completed = true;
            return Ok(Some(MeasuredEncoderEvidence {
                key: pending.key,
                result: pending.result,
            }));
        }

        if self
            .accumulator
            .as_ref()
            .is_some_and(BoundedEncoderBenchmark::is_submission_complete)
        {
            let candidate = active.encoder_candidate().clone();
            let profile = active.profile();
            let low_latency_accepted = active.low_latency_accepted();
            let tail = active.finish_with_metrics()?;
            if let Some(accumulator) = self.accumulator.as_mut() {
                for output in tail {
                    accumulator.record_output(output.encode_latency)?;
                    self.non_keyframe_observed |= !output.frame.meta.keyframe;
                    self.keyframe_observed |= self.keyframe_request_frame.is_some_and(|frame_id| {
                        frame_id == output.frame.meta.frame_id && output.frame.meta.keyframe
                    });
                }
            }

            let accumulator = self
                .accumulator
                .as_mut()
                .expect("submission-complete accumulator exists");
            accumulator.finalize_missing(
                classmesh_codec_win::mf_async::MfAsyncWaitConfig::default().drain_timeout,
            )?;
            let elapsed_seconds = self
                .started
                .expect("benchmark starts with its first pipeline")
                .elapsed()
                .as_secs_f32();
            let mut result = summarize_benchmark(
                &candidate,
                Codec::H264,
                accumulator.samples(),
                elapsed_seconds,
                BenchmarkCapabilities {
                    gpu_native_input: true,
                    low_latency_accepted,
                    reset_ok: false,
                    dynamic_bitrate_ok: false,
                    keyframe_request_ok: self.keyframe_request_frame.is_some()
                        && self.keyframe_observed,
                },
            )?;
            result.class = class_for_actual_target(result.class, profile);
            let key = benchmark_cache_key(&self.adapter, &candidate, profile)?;
            self.pending_reset = Some(PendingReset {
                result,
                candidate,
                profile,
                key,
                submissions: 0,
                output_observed: false,
            });
            self.accumulator = None;
            self.pipeline = None;
        }

        Ok(None)
    }
}

fn benchmark_cache_key(
    adapter: &AdapterCapabilityIdentity,
    candidate: &EncoderCandidate,
    profile: PresentationProfile,
) -> Result<EncoderCapabilityCacheKey, RuntimeEncoderBenchmarkError> {
    Ok(EncoderCapabilityCacheKey {
        adapter_identity: adapter.adapter_identity(),
        driver_version: adapter.driver_version.clone(),
        encoder_clsid: candidate.clsid.clone(),
        width: u16::try_from(profile.target_width)
            .map_err(|_| RuntimeEncoderBenchmarkError::InvalidProfile)?,
        height: u16::try_from(profile.target_height)
            .map_err(|_| RuntimeEncoderBenchmarkError::InvalidProfile)?,
        target_fps: u16::try_from(profile.fps)
            .map_err(|_| RuntimeEncoderBenchmarkError::InvalidProfile)?,
        bitrate_bps: profile.bitrate_bps,
    })
}

fn same_target(left: PresentationProfile, right: PresentationProfile) -> bool {
    left.target_width == right.target_width
        && left.target_height == right.target_height
        && left.fps == right.fps
        && left.bitrate_bps == right.bitrate_bps
}

fn class_for_actual_target(class: EncoderClass, profile: PresentationProfile) -> EncoderClass {
    if profile.target_width < 1920 || profile.target_height < 1080 || profile.fps < 30 {
        return class.min(EncoderClass::Compatibility);
    }
    if profile.fps < 60 {
        return class.min(EncoderClass::Presentation1080p30);
    }
    class
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(width: u32, height: u32, fps: u32) -> PresentationProfile {
        PresentationProfile {
            source_width: width,
            source_height: height,
            target_width: width,
            target_height: height,
            fps,
            bitrate_bps: 2_500_000,
        }
    }

    #[test]
    fn runtime_cache_key_binds_adapter_driver_encoder_and_profile() {
        let adapter = AdapterCapabilityIdentity {
            adapter_luid_low: 0x1122_3344,
            adapter_luid_high: 0x5566_7788,
            driver_version: "31.0.15.5123".into(),
        };
        let candidate = EncoderCandidate {
            name: "test".into(),
            clsid: "{encoder-clsid}".into(),
            vendor: classmesh_codec_win::EncoderVendor::Nvidia,
            advertised_hardware: true,
            advertised_async: true,
        };
        let key =
            benchmark_cache_key(&adapter, &candidate, profile(1280, 720, 30)).expect("cache key");
        assert_eq!(key.adapter_identity, "55667788:11223344");
        assert_eq!(key.driver_version, "31.0.15.5123");
        assert_eq!(key.encoder_clsid, "{encoder-clsid}");
        assert_eq!((key.width, key.height, key.target_fps), (1280, 720, 30));
        assert_eq!(key.bitrate_bps, 2_500_000);
    }

    #[test]
    fn runtime_class_is_capped_by_actual_target() {
        assert_eq!(
            class_for_actual_target(EncoderClass::Presentation1080p60, profile(1280, 720, 30)),
            EncoderClass::Compatibility
        );
        assert_eq!(
            class_for_actual_target(EncoderClass::Presentation1080p60, profile(1920, 1080, 30)),
            EncoderClass::Presentation1080p30
        );
    }
}
