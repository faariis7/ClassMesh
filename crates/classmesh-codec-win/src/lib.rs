#![deny(unsafe_code)]

use std::time::Duration;

use classmesh_video::{Codec, EncoderClass, EncoderProbeResult};

#[cfg(windows)]
pub mod d3d11;
#[cfg(windows)]
pub mod gpu;
#[cfg(windows)]
pub mod mf;
#[cfg(windows)]
pub mod mf_async;
#[cfg(windows)]
pub mod mf_decoder;
pub mod selection;
pub mod surface_pool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncoderVendor {
    Microsoft,
    Intel,
    Nvidia,
    Amd,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncoderCandidate {
    pub name: String,
    pub clsid: String,
    pub vendor: EncoderVendor,
    pub advertised_hardware: bool,
    pub advertised_async: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderBenchmarkConfig {
    pub width: u16,
    pub height: u16,
    pub target_fps: u16,
    pub sample_frames: u16,
    pub bitrate_kbps: u32,
}

impl EncoderBenchmarkConfig {
    #[must_use]
    pub const fn presentation_1080p30() -> Self {
        Self {
            width: 1920,
            height: 1080,
            target_fps: 30,
            sample_frames: 180,
            bitrate_kbps: 5_000,
        }
    }

    #[must_use]
    pub const fn compatibility_720p30() -> Self {
        Self {
            width: 1280,
            height: 720,
            target_fps: 30,
            sample_frames: 120,
            bitrate_kbps: 2_500,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EncodeSample {
    pub encode_ms: f32,
    pub produced_output: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchmarkAccumulatorError {
    InvalidTarget,
    OutputWithoutSubmission,
    InvalidLatency,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BoundedEncoderBenchmark {
    target_samples: usize,
    submitted: usize,
    samples: Vec<EncodeSample>,
}

impl BoundedEncoderBenchmark {
    pub fn from_config(
        config: EncoderBenchmarkConfig,
    ) -> Result<Self, BenchmarkAccumulatorError> {
        let target_samples = usize::from(config.sample_frames);
        if target_samples == 0 {
            return Err(BenchmarkAccumulatorError::InvalidTarget);
        }
        Ok(Self {
            target_samples,
            submitted: 0,
            samples: Vec::with_capacity(target_samples),
        })
    }

    #[must_use]
    pub const fn submitted(&self) -> usize {
        self.submitted
    }

    #[must_use]
    pub fn outputs(&self) -> usize {
        self.samples
            .iter()
            .filter(|sample| sample.produced_output)
            .count()
    }

    #[must_use]
    pub fn is_submission_complete(&self) -> bool {
        self.submitted >= self.target_samples
    }

    #[must_use]
    pub fn samples(&self) -> &[EncodeSample] {
        &self.samples
    }

    pub fn record_submission(&mut self) -> bool {
        if self.is_submission_complete() {
            return false;
        }
        self.submitted += 1;
        true
    }

    pub fn record_output(
        &mut self,
        latency: Duration,
    ) -> Result<(), BenchmarkAccumulatorError> {
        if self.samples.len() >= self.submitted {
            return Err(BenchmarkAccumulatorError::OutputWithoutSubmission);
        }
        let encode_ms = latency.as_secs_f32() * 1_000.0;
        if !encode_ms.is_finite() || encode_ms <= 0.0 {
            return Err(BenchmarkAccumulatorError::InvalidLatency);
        }
        self.samples.push(EncodeSample {
            encode_ms,
            produced_output: true,
        });
        Ok(())
    }

    pub fn finalize_missing(
        &mut self,
        timeout_latency: Duration,
    ) -> Result<(), BenchmarkAccumulatorError> {
        let encode_ms = timeout_latency.as_secs_f32() * 1_000.0;
        if !encode_ms.is_finite() || encode_ms <= 0.0 {
            return Err(BenchmarkAccumulatorError::InvalidLatency);
        }
        while self.samples.len() < self.submitted {
            self.samples.push(EncodeSample {
                encode_ms,
                produced_output: false,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchmarkCapabilities {
    pub gpu_native_input: bool,
    pub low_latency_accepted: bool,
    pub reset_ok: bool,
    pub dynamic_bitrate_ok: bool,
    pub keyframe_request_ok: bool,
}

impl BenchmarkCapabilities {
    #[must_use]
    pub const fn fully_supported() -> Self {
        Self {
            gpu_native_input: true,
            low_latency_accepted: true,
            reset_ok: true,
            dynamic_bitrate_ok: true,
            keyframe_request_ok: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncoderCapabilityCacheKey {
    pub adapter_identity: String,
    pub driver_version: String,
    pub encoder_clsid: String,
    pub width: u16,
    pub height: u16,
    pub target_fps: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EncoderBenchmarkResult {
    pub probe: EncoderProbeResult,
    pub class: EncoderClass,
    pub output_frames: usize,
    pub dropped_or_missing: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchmarkError {
    EmptySamples,
    InvalidSample,
}

pub fn summarize_benchmark(
    candidate: &EncoderCandidate,
    codec: Codec,
    samples: &[EncodeSample],
    elapsed_seconds: f32,
    capabilities: BenchmarkCapabilities,
) -> Result<EncoderBenchmarkResult, BenchmarkError> {
    if samples.is_empty() || elapsed_seconds <= 0.0 {
        return Err(BenchmarkError::EmptySamples);
    }
    if samples
        .iter()
        .any(|sample| !sample.encode_ms.is_finite() || sample.encode_ms <= 0.0)
    {
        return Err(BenchmarkError::InvalidSample);
    }

    let mut latencies: Vec<f32> = samples.iter().map(|sample| sample.encode_ms).collect();
    latencies.sort_by(f32::total_cmp);
    let p50 = percentile(&latencies, 50);
    let p95 = percentile(&latencies, 95);
    let output_frames = samples
        .iter()
        .filter(|sample| sample.produced_output)
        .count();
    let dropped_or_missing = samples.len().saturating_sub(output_frames);
    let sustained_fps = output_frames as f32 / elapsed_seconds;

    let probe = EncoderProbeResult {
        backend: candidate.name.clone(),
        codec,
        advertised_hardware: candidate.advertised_hardware,
        gpu_native_input: capabilities.gpu_native_input,
        low_latency_accepted: capabilities.low_latency_accepted,
        sustained_fps,
        p50_encode_ms: p50,
        p95_encode_ms: p95,
        reset_ok: capabilities.reset_ok,
        dynamic_bitrate_ok: capabilities.dynamic_bitrate_ok,
        keyframe_request_ok: capabilities.keyframe_request_ok,
    };
    let class = probe.classify();

    Ok(EncoderBenchmarkResult {
        probe,
        class,
        output_frames,
        dropped_or_missing,
    })
}

fn percentile(sorted: &[f32], percentile: usize) -> f32 {
    let last = sorted.len().saturating_sub(1);
    let index = last.saturating_mul(percentile).div_ceil(100).min(last);
    sorted[index]
}

/// Configuration intent for the Media Foundation backend. Platform code should attempt every
/// supported control and report unsupported controls as capability data rather than fatal errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LowLatencyIntent {
    pub mf_low_latency: bool,
    pub codec_api_low_latency: bool,
    pub disable_b_frames: bool,
    pub real_time_rate_control: bool,
}

impl Default for LowLatencyIntent {
    fn default() -> Self {
        Self {
            mf_low_latency: true,
            codec_api_low_latency: true,
            disable_b_frames: true,
            real_time_rate_control: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> EncoderCandidate {
        EncoderCandidate {
            name: "Mock Hardware H.264 MFT".into(),
            clsid: "mock".into(),
            vendor: EncoderVendor::Intel,
            advertised_hardware: true,
            advertised_async: true,
        }
    }

    #[test]
    fn bounded_benchmark_never_accepts_more_than_configured_submissions() {
        let mut benchmark =
            BoundedEncoderBenchmark::from_config(EncoderBenchmarkConfig {
                sample_frames: 2,
                ..EncoderBenchmarkConfig::compatibility_720p30()
            })
            .expect("valid benchmark");
        assert!(benchmark.record_submission());
        assert!(benchmark.record_submission());
        assert!(!benchmark.record_submission());
        assert_eq!(benchmark.submitted(), 2);
    }

    #[test]
    fn bounded_benchmark_requires_submission_before_output_and_records_latency() {
        let mut benchmark =
            BoundedEncoderBenchmark::from_config(EncoderBenchmarkConfig::compatibility_720p30())
                .expect("valid benchmark");
        assert_eq!(
            benchmark.record_output(Duration::from_millis(5)),
            Err(BenchmarkAccumulatorError::OutputWithoutSubmission)
        );
        assert!(benchmark.record_submission());
        benchmark
            .record_output(Duration::from_millis(5))
            .expect("matching output");
        assert_eq!(benchmark.outputs(), 1);
        assert_eq!(benchmark.samples()[0].encode_ms, 5.0);
    }

    #[test]
    fn bounded_benchmark_marks_unreturned_submissions_as_missing() {
        let mut benchmark =
            BoundedEncoderBenchmark::from_config(EncoderBenchmarkConfig {
                sample_frames: 2,
                ..EncoderBenchmarkConfig::compatibility_720p30()
            })
            .expect("valid benchmark");
        assert!(benchmark.record_submission());
        assert!(benchmark.record_submission());
        benchmark
            .record_output(Duration::from_millis(4))
            .expect("first output");
        benchmark
            .finalize_missing(Duration::from_millis(250))
            .expect("bounded timeout");
        assert_eq!(benchmark.samples().len(), 2);
        assert_eq!(benchmark.outputs(), 1);
        assert!(!benchmark.samples()[1].produced_output);
        assert_eq!(benchmark.samples()[1].encode_ms, 250.0);
    }

    #[test]
    fn advertised_hardware_still_requires_real_benchmark() {
        let samples = vec![
            EncodeSample {
                encode_ms: 5.0,
                produced_output: true,
            };
            60
        ];
        let result = summarize_benchmark(
            &candidate(),
            Codec::H264,
            &samples,
            2.0,
            BenchmarkCapabilities::fully_supported(),
        )
        .expect("benchmark should summarize");
        assert_eq!(result.class, EncoderClass::Presentation1080p30);
    }

    #[test]
    fn slow_hardware_candidate_is_downgraded() {
        let samples = vec![
            EncodeSample {
                encode_ms: 50.0,
                produced_output: true,
            };
            30
        ];
        let result = summarize_benchmark(
            &candidate(),
            Codec::H264,
            &samples,
            2.0,
            BenchmarkCapabilities::fully_supported(),
        )
        .expect("benchmark should summarize");
        assert_eq!(result.class, EncoderClass::Compatibility);
    }

    #[test]
    fn malformed_latency_sample_is_rejected() {
        let samples = [EncodeSample {
            encode_ms: f32::NAN,
            produced_output: true,
        }];
        assert_eq!(
            summarize_benchmark(
                &candidate(),
                Codec::H264,
                &samples,
                1.0,
                BenchmarkCapabilities::fully_supported(),
            ),
            Err(BenchmarkError::InvalidSample)
        );
    }
}
