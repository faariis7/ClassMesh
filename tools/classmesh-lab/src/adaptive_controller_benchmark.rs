use classmesh_core::adaptation::{AdaptationPolicy, HysteresisConfig, QualityTier};
use classmesh_core::cohort::{CohortKey, CohortKind, ReceiverId};
use classmesh_core::quality_sample::{
    RECEIVER_QUALITY_SAMPLE_VERSION, ReceiverCapabilityHealth, ReceiverQualitySample,
};
use classmesh_core::receiver_cohort::{ReceiverCohortPlanner, ReceiverCohortPlannerConfig};
use classmesh_core::receiver_quality::{ReceiverQualityPolicy, ReceiverQualitySampleStatus};
use classmesh_core::rendition_sfu::{
    RenditionSfuBlockReason, RenditionSfuCandidate, RenditionSfuCandidateStatus,
    RenditionSfuCapabilities, RenditionSfuEvidence, evaluate_rendition_sfu_candidate,
};
use classmesh_core::transport_topology::{
    MediaPath, MediaPathCandidateStatus, MediaTopology, PhysicalGateStatus,
    TransportTopologyController, TransportTopologyEvidence, TransportTopologyHysteresis,
};
use classmesh_core::{MediaTransport, NetworkMetrics, StreamKind};

pub const ADAPTIVE_SCALE_POINTS: [usize; 4] = [5, 10, 20, 30];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdaptiveControllerBenchmarkConfig {
    pub receivers: usize,
    pub rounds: u32,
}

impl Default for AdaptiveControllerBenchmarkConfig {
    fn default() -> Self {
        Self {
            receivers: 30,
            rounds: 30,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptiveControllerBenchmarkReport {
    pub receivers: usize,
    pub rounds: u32,
    pub healthy_high_after_weak_degrade: usize,
    pub weak_degraded_tier: QualityTier,
    pub weak_recovered_tier: QualityTier,
    pub noisy_receiver_tier_changes: u32,
    pub max_routed_receivers: usize,
    pub unresolved_transport_blocked: bool,
    pub qualified_switch_required_hysteresis: bool,
    pub unresolved_rendition_blocked: bool,
    pub reliable_fallback_eligible_without_default_selection: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdaptiveControllerBenchmarkError {
    UnsupportedReceiverCount(usize),
    InvalidRounds,
    Invariant(&'static str),
}

pub fn run_adaptive_controller_benchmark(
    config: AdaptiveControllerBenchmarkConfig,
) -> Result<AdaptiveControllerBenchmarkReport, AdaptiveControllerBenchmarkError> {
    if !ADAPTIVE_SCALE_POINTS.contains(&config.receivers) {
        return Err(AdaptiveControllerBenchmarkError::UnsupportedReceiverCount(
            config.receivers,
        ));
    }
    if config.rounds == 0 {
        return Err(AdaptiveControllerBenchmarkError::InvalidRounds);
    }

    let hysteresis = HysteresisConfig {
        degrade_samples: 2,
        recover_samples: 3,
        transport_samples: 3,
    };
    let quality_policy = ReceiverQualityPolicy::default();
    let mut planner = ReceiverCohortPlanner::new(
        StreamKind::TeacherPresentation,
        AdaptationPolicy::default(),
        hysteresis,
        quality_policy,
        ReceiverCohortPlannerConfig {
            max_receivers: config.receivers,
        },
    )
    .map_err(|_| AdaptiveControllerBenchmarkError::Invariant("invalid static cohort config"))?;

    for receiver in 1..=config.receivers {
        let receiver = ReceiverId(receiver as u64);
        planner
            .register(receiver, MediaTransport::UdpUnicast)
            .map_err(|_| AdaptiveControllerBenchmarkError::Invariant("receiver registration"))?;
        planner
            .observe(receiver, healthy_sample(1, 1_000_000), 1_000_000)
            .map_err(|_| AdaptiveControllerBenchmarkError::Invariant("initial receiver sample"))?;
    }

    let high = CohortKey {
        kind: CohortKind::DirectUnicast,
        tier: QualityTier::High,
    };
    let max_routed_receivers = planner.routed_count();
    if max_routed_receivers != config.receivers || planner.members(high).len() != config.receivers {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "initial cohort routing",
        ));
    }

    let noisy_id = ReceiverId(1);
    let mut noisy_receiver_tier_changes = 0_u32;
    for round in 0..config.rounds {
        let sequence = u64::from(round).saturating_add(2);
        let observed_at_us = 1_100_000_u64.saturating_add(u64::from(round) * 100_000);
        let mut sample = healthy_sample(sequence, observed_at_us);
        if round % 2 == 0 {
            sample.queue_depth = quality_policy.degraded_queue_depth;
        }
        let observed = planner
            .observe(noisy_id, sample, observed_at_us)
            .map_err(|_| AdaptiveControllerBenchmarkError::Invariant("noisy receiver sample"))?;
        if observed.quality.decision.changed {
            noisy_receiver_tier_changes = noisy_receiver_tier_changes.saturating_add(1);
        }
    }

    let weak_id = ReceiverId(config.receivers as u64);
    let weak_sequence_base = u64::from(config.rounds).saturating_add(2);
    let weak_time_base =
        1_100_000_u64.saturating_add(u64::from(config.rounds).saturating_mul(100_000));

    let mut weak = healthy_sample(weak_sequence_base, weak_time_base);
    weak.queue_drop_rate = quality_policy.severe_queue_drop_rate;
    planner
        .observe(weak_id, weak, weak_time_base)
        .map_err(|_| AdaptiveControllerBenchmarkError::Invariant("weak degrade sample one"))?;

    weak.sample_sequence = weak.sample_sequence.saturating_add(1);
    weak.observed_at_us = weak.observed_at_us.saturating_add(100_000);
    let degraded = planner
        .observe(weak_id, weak, weak.observed_at_us)
        .map_err(|_| AdaptiveControllerBenchmarkError::Invariant("weak degrade sample two"))?;
    let weak_degraded_tier = degraded.quality.decision.tier;
    if weak_degraded_tier != QualityTier::Emergency {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "weak receiver did not degrade",
        ));
    }

    let healthy_high_after_weak_degrade = planner.members(high).len();
    if healthy_high_after_weak_degrade != config.receivers.saturating_sub(1) {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "weak receiver downgraded healthy peers",
        ));
    }

    let mut weak_recovered_tier = weak_degraded_tier;
    for offset in 1..=hysteresis.recover_samples {
        let sequence = weak.sample_sequence.saturating_add(u64::from(offset));
        let observed_at_us = weak
            .observed_at_us
            .saturating_add(u64::from(offset).saturating_mul(100_000));
        let recovered = planner
            .observe(
                weak_id,
                healthy_sample(sequence, observed_at_us),
                observed_at_us,
            )
            .map_err(|_| AdaptiveControllerBenchmarkError::Invariant("weak recovery sample"))?;
        weak_recovered_tier = recovered.quality.decision.tier;
    }
    if weak_recovered_tier != QualityTier::High {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "weak receiver did not recover",
        ));
    }

    let replay = planner
        .observe(
            weak_id,
            healthy_sample(
                weak.sample_sequence
                    .saturating_add(u64::from(hysteresis.recover_samples)),
                weak.observed_at_us.saturating_add(999_999),
            ),
            weak.observed_at_us.saturating_add(999_999),
        )
        .map_err(|_| AdaptiveControllerBenchmarkError::Invariant("replay sample"))?;
    if replay.quality.status != ReceiverQualitySampleStatus::NonMonotonicSequence {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "replayed sample was not rejected",
        ));
    }

    let fallback = MediaPath {
        transport: MediaTransport::ReliableFallback,
        topology: MediaTopology::Direct,
    };
    let direct_udp = MediaPath {
        transport: MediaTransport::UdpUnicast,
        topology: MediaTopology::Direct,
    };
    let mut topology =
        TransportTopologyController::new(fallback, TransportTopologyHysteresis::default())
            .map_err(|_| AdaptiveControllerBenchmarkError::Invariant("static topology config"))?;

    let unresolved = topology.observe(direct_udp, TransportTopologyEvidence::default());
    let unresolved_transport_blocked = matches!(
        unresolved.status,
        MediaPathCandidateStatus::Blocked {
            evidence: PhysicalGateStatus::Pending,
            ..
        }
    );
    if !unresolved_transport_blocked {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "unresolved transport was not blocked",
        ));
    }

    let qualified = qualified_transport_evidence();
    let first = topology.observe(direct_udp, qualified);
    let second = topology.observe(direct_udp, qualified);
    let third = topology.observe(direct_udp, qualified);
    let qualified_switch_required_hysteresis = first.status
        == MediaPathCandidateStatus::PendingHysteresis
        && second.status == MediaPathCandidateStatus::PendingHysteresis
        && third.status == MediaPathCandidateStatus::Applied
        && third.changed
        && third.active == direct_udp;
    if !qualified_switch_required_hysteresis {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "transport hysteresis invariant",
        ));
    }

    let rendition_capabilities = RenditionSfuCapabilities {
        hardware_encoder_slots: 3,
        measured_max_renditions: 3,
        measured_max_relay_receivers: config.receivers,
    };
    let unresolved_rendition = evaluate_rendition_sfu_candidate(
        RenditionSfuCandidate {
            path: direct_udp,
            max_renditions: 2,
        },
        config.receivers,
        rendition_capabilities,
        RenditionSfuEvidence {
            transport_topology: qualified_transport_evidence(),
            multi_rendition: PhysicalGateStatus::Pending,
        },
    )
    .map_err(|_| AdaptiveControllerBenchmarkError::Invariant("rendition capabilities"))?;
    let unresolved_rendition_blocked = matches!(
        unresolved_rendition,
        RenditionSfuCandidateStatus::Blocked(RenditionSfuBlockReason::MultiRenditionGate(
            PhysicalGateStatus::Pending
        ))
    );
    if !unresolved_rendition_blocked {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "unresolved rendition was eligible",
        ));
    }

    let reliable_fallback = evaluate_rendition_sfu_candidate(
        RenditionSfuCandidate {
            path: fallback,
            max_renditions: 1,
        },
        1,
        RenditionSfuCapabilities {
            hardware_encoder_slots: 1,
            measured_max_renditions: 1,
            measured_max_relay_receivers: 0,
        },
        RenditionSfuEvidence::default(),
    )
    .map_err(|_| AdaptiveControllerBenchmarkError::Invariant("fallback capabilities"))?;
    let reliable_fallback_eligible_without_default_selection =
        reliable_fallback == RenditionSfuCandidateStatus::Eligible;

    Ok(AdaptiveControllerBenchmarkReport {
        receivers: config.receivers,
        rounds: config.rounds,
        healthy_high_after_weak_degrade,
        weak_degraded_tier,
        weak_recovered_tier,
        noisy_receiver_tier_changes,
        max_routed_receivers,
        unresolved_transport_blocked,
        qualified_switch_required_hysteresis,
        unresolved_rendition_blocked,
        reliable_fallback_eligible_without_default_selection,
    })
}

fn healthy_sample(sequence: u64, observed_at_us: u64) -> ReceiverQualitySample {
    ReceiverQualitySample {
        schema_version: RECEIVER_QUALITY_SAMPLE_VERSION,
        sample_sequence: sequence,
        observed_at_us,
        network: NetworkMetrics {
            rtt_ms: 10.0,
            packet_loss: 0.001,
            jitter_ms: 1.0,
            decode_fps: 30.0,
            queue_delay_ms: 3.0,
            estimated_mbps: 100.0,
            multicast_viable: true,
            wireless: false,
        },
        reordered_packet_rate: 0.001,
        decode_delay_ms: 4.0,
        render_delay_ms: 3.0,
        queue_depth: 1,
        queue_drop_rate: 0.0,
        capability: ReceiverCapabilityHealth {
            hardware_decode_available: true,
            profile_supported: true,
            decoder_healthy: true,
            renderer_healthy: true,
        },
    }
}

fn qualified_transport_evidence() -> TransportTopologyEvidence {
    TransportTopologyEvidence {
        udp_unicast: PhysicalGateStatus::Qualified,
        quic_datagram: PhysicalGateStatus::Qualified,
        wired_multicast: PhysicalGateStatus::Qualified,
        web_rtc: PhysicalGateStatus::Qualified,
        relay_topology: PhysicalGateStatus::Qualified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_scale_points_preserve_per_receiver_isolation() {
        for receivers in ADAPTIVE_SCALE_POINTS {
            let report = run_adaptive_controller_benchmark(AdaptiveControllerBenchmarkConfig {
                receivers,
                rounds: 30,
            })
            .unwrap();
            assert_eq!(report.receivers, receivers);
            assert_eq!(
                report.healthy_high_after_weak_degrade,
                receivers.saturating_sub(1)
            );
            assert_eq!(report.weak_degraded_tier, QualityTier::Emergency);
            assert_eq!(report.weak_recovered_tier, QualityTier::High);
            assert_eq!(report.max_routed_receivers, receivers);
        }
    }

    #[test]
    fn noisy_samples_do_not_flap_tier_without_hysteresis_evidence() {
        let report =
            run_adaptive_controller_benchmark(AdaptiveControllerBenchmarkConfig::default())
                .unwrap();
        assert_eq!(report.noisy_receiver_tier_changes, 0);
    }

    #[test]
    fn unresolved_physical_and_rendition_candidates_remain_blocked() {
        let report =
            run_adaptive_controller_benchmark(AdaptiveControllerBenchmarkConfig::default())
                .unwrap();
        assert!(report.unresolved_transport_blocked);
        assert!(report.unresolved_rendition_blocked);
        assert!(report.qualified_switch_required_hysteresis);
        assert!(report.reliable_fallback_eligible_without_default_selection);
    }

    #[test]
    fn unsupported_scale_and_empty_rounds_fail_closed() {
        assert_eq!(
            run_adaptive_controller_benchmark(AdaptiveControllerBenchmarkConfig {
                receivers: 3,
                rounds: 30,
            }),
            Err(AdaptiveControllerBenchmarkError::UnsupportedReceiverCount(
                3
            ))
        );
        assert_eq!(
            run_adaptive_controller_benchmark(AdaptiveControllerBenchmarkConfig {
                receivers: 5,
                rounds: 0,
            }),
            Err(AdaptiveControllerBenchmarkError::InvalidRounds)
        );
    }
}
