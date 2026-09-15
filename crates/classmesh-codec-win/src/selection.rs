use classmesh_video::EncoderClass;

use crate::{EncoderBenchmarkResult, EncoderCandidate};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EncoderSelectionPolicy {
    /// Production presentation should normally require a measured candidate. Hardware qualification
    /// tools may temporarily allow an unmeasured hardware MFT so it can be benchmarked.
    pub allow_unmeasured_hardware: bool,
}

impl EncoderSelectionPolicy {
    #[must_use]
    pub const fn qualification() -> Self {
        Self {
            allow_unmeasured_hardware: true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EncoderSelectionCandidate<'a> {
    pub candidate: &'a EncoderCandidate,
    pub benchmark: Option<&'a EncoderBenchmarkResult>,
    /// True when this encoder is known to belong to the same adapter/vendor lineage as the D3D11
    /// capture device. This is intentionally supplied by platform discovery rather than guessed
    /// from the MFT display name.
    pub adapter_affinity: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncoderSelectionReason {
    Measured(EncoderClass),
    ProvisionalHardware,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderSelection {
    pub index: usize,
    pub reason: EncoderSelectionReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SelectionScore {
    class_rank: u8,
    measured: bool,
    adapter_affinity: bool,
    async_transform: bool,
}

/// Selects the best encoder candidate without trusting enumeration order.
///
/// A measured unsupported encoder is never selected. In production mode, unmeasured encoders are
/// excluded entirely. Qualification mode can select an advertised hardware MFT provisionally so a
/// real benchmark can be collected and persisted before production use.
#[must_use]
pub fn select_encoder(
    candidates: &[EncoderSelectionCandidate<'_>],
    policy: EncoderSelectionPolicy,
) -> Option<EncoderSelection> {
    candidates
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            score(entry, policy).map(|(score, reason)| (index, score, reason))
        })
        .max_by_key(|(index, score, _)| (*score, std::cmp::Reverse(*index)))
        .map(|(index, _, reason)| EncoderSelection { index, reason })
}

fn score(
    entry: &EncoderSelectionCandidate<'_>,
    policy: EncoderSelectionPolicy,
) -> Option<(SelectionScore, EncoderSelectionReason)> {
    if !entry.candidate.advertised_hardware {
        return None;
    }

    let (class_rank, measured, reason) = match entry.benchmark {
        Some(result) => {
            let rank = class_rank(result.class)?;
            (rank, true, EncoderSelectionReason::Measured(result.class))
        }
        None if policy.allow_unmeasured_hardware => {
            (1, false, EncoderSelectionReason::ProvisionalHardware)
        }
        None => return None,
    };

    Some((
        SelectionScore {
            class_rank,
            measured,
            adapter_affinity: entry.adapter_affinity,
            async_transform: entry.candidate.advertised_async,
        },
        reason,
    ))
}

const fn class_rank(class: EncoderClass) -> Option<u8> {
    match class {
        EncoderClass::Presentation1080p60 => Some(4),
        EncoderClass::Presentation1080p30 => Some(3),
        EncoderClass::Compatibility => Some(2),
        EncoderClass::Unsupported => None,
    }
}

#[cfg(test)]
mod tests {
    use classmesh_video::{Codec, EncoderProbeResult};

    use super::*;
    use crate::EncoderVendor;

    fn candidate(name: &str, async_transform: bool) -> EncoderCandidate {
        EncoderCandidate {
            name: name.into(),
            clsid: format!("clsid-{name}"),
            vendor: EncoderVendor::Intel,
            advertised_hardware: true,
            advertised_async: async_transform,
        }
    }

    fn benchmark(class: EncoderClass) -> EncoderBenchmarkResult {
        EncoderBenchmarkResult {
            probe: EncoderProbeResult {
                backend: "test".into(),
                codec: Codec::H264,
                advertised_hardware: true,
                gpu_native_input: true,
                low_latency_accepted: true,
                sustained_fps: 30.0,
                p50_encode_ms: 5.0,
                p95_encode_ms: 8.0,
                reset_ok: true,
                dynamic_bitrate_ok: true,
                keyframe_request_ok: true,
            },
            class,
            output_frames: 180,
            dropped_or_missing: 0,
        }
    }

    #[test]
    fn production_refuses_unmeasured_hardware() {
        let intel = candidate("Intel", true);
        let entries = [EncoderSelectionCandidate {
            candidate: &intel,
            benchmark: None,
            adapter_affinity: true,
        }];
        assert_eq!(
            select_encoder(&entries, EncoderSelectionPolicy::default()),
            None
        );
    }

    #[test]
    fn qualification_can_choose_unmeasured_hardware() {
        let intel = candidate("Intel", true);
        let entries = [EncoderSelectionCandidate {
            candidate: &intel,
            benchmark: None,
            adapter_affinity: true,
        }];
        assert_eq!(
            select_encoder(&entries, EncoderSelectionPolicy::qualification()),
            Some(EncoderSelection {
                index: 0,
                reason: EncoderSelectionReason::ProvisionalHardware,
            })
        );
    }

    #[test]
    fn measured_capability_beats_provisional_enumeration_order() {
        let provisional = candidate("first-enumerated", true);
        let measured = candidate("measured", true);
        let measured_result = benchmark(EncoderClass::Presentation1080p30);
        let entries = [
            EncoderSelectionCandidate {
                candidate: &provisional,
                benchmark: None,
                adapter_affinity: true,
            },
            EncoderSelectionCandidate {
                candidate: &measured,
                benchmark: Some(&measured_result),
                adapter_affinity: false,
            },
        ];
        assert_eq!(
            select_encoder(&entries, EncoderSelectionPolicy::qualification()),
            Some(EncoderSelection {
                index: 1,
                reason: EncoderSelectionReason::Measured(EncoderClass::Presentation1080p30),
            })
        );
    }

    #[test]
    fn adapter_affinity_breaks_equal_measured_ties() {
        let first = candidate("first", true);
        let matching = candidate("matching", true);
        let first_result = benchmark(EncoderClass::Presentation1080p30);
        let matching_result = benchmark(EncoderClass::Presentation1080p30);
        let entries = [
            EncoderSelectionCandidate {
                candidate: &first,
                benchmark: Some(&first_result),
                adapter_affinity: false,
            },
            EncoderSelectionCandidate {
                candidate: &matching,
                benchmark: Some(&matching_result),
                adapter_affinity: true,
            },
        ];
        assert_eq!(
            select_encoder(&entries, EncoderSelectionPolicy::default())
                .expect("one candidate must be selected")
                .index,
            1
        );
    }

    #[test]
    fn measured_unsupported_candidate_is_never_selected() {
        let broken = candidate("broken", true);
        let broken_result = benchmark(EncoderClass::Unsupported);
        let entries = [EncoderSelectionCandidate {
            candidate: &broken,
            benchmark: Some(&broken_result),
            adapter_affinity: true,
        }];
        assert_eq!(
            select_encoder(&entries, EncoderSelectionPolicy::qualification()),
            None
        );
    }
}
