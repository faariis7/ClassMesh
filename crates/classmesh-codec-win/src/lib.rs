#![deny(unsafe_code)]

use classmesh_video::{Codec, EncoderClass, EncoderProbeResult};

#[cfg(windows)]
pub mod gpu;
#[cfg(windows)]
pub mod mf;
#[cfg(windows)]
pub mod mf_async;
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
