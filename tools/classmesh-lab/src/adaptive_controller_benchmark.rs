use classmesh_core::adaptation::{AdaptationPolicy, HysteresisConfig, QualityTier};
use classmesh_core::cohort::ReceiverId;
use classmesh_core::quality_sample::{
    RECEIVER_QUALITY_SAMPLE_VERSION, ReceiverCapabilityHealth, ReceiverQualitySample,
};
use classmesh_core::receiver_cohort::{
    ReceiverCohortPlanner, ReceiverCohortPlannerConfig, ReceiverCohortPlannerError,
};
use classmesh_core::receiver_quality::ReceiverQualityPolicy;
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

const DIRECT_UDP: MediaPath = MediaPath {
    transport: MediaTransport::UdpUnicast,
    topology: MediaTopology::Direct,
};
const DIRECT_QUIC: MediaPath = MediaPath {
    transport: MediaTransport::QuicDatagram,
    topology: MediaTopology::Direct,
};
const RELIABLE_FALLBACK: MediaPath = MediaPath {
    transport: MediaTransport::ReliableFallback,
    topology: MediaTopology::Direct,
};

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
    Planner(ReceiverCohortPlannerError),
    Invariant(&'static str),
}

impl From<ReceiverCohortPlannerError> for AdaptiveControllerBenchmarkError {
    fn from(value: ReceiverCohortPlannerError) -> Self {
        Self::Planner(value)
    }
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
    let mut planner = ReceiverCohortPlanner::new(
        StreamKind::TeacherPresentation,
        AdaptationPolicy::default(),
        hysteresis,
        ReceiverQualityPolicy::default(),
        ReceiverCohortPlannerConfig {
            max_receivers: config.receivers,
        },
    )?;

    let mut max_routed_receivers = 0;
    for id in 1..=config.receivers {
        let receiver = ReceiverId(u64::try_from(id).unwrap_or(u64::MAX));
        planner.register(receiver, MediaTransport::UdpUnicast)?;
        planner.observe(receiver, sample(1, 1_000_000, false), 1_000_000)?;
        max_routed_receivers = max_routed_receivers.max(planner.routed_count());
    }

    let noisy = ReceiverId(1);
    let mut noisy_sequence = 2_u64;
    let mut noisy_time = 1_100_000_u64;
    let mut noisy_receiver_tier_changes = 0_u32;
    let mut noisy_previous = planner
        .route(noisy)
        .ok_or(AdaptiveControllerBenchmarkError::Invariant(
            "noisy receiver missing initial route",
        ))?
        .tier;

    for round in 0..config.rounds {
        let severe = round % 2 == 0;
        let observed = planner.observe(
            noisy,
            sample(noisy_sequence, noisy_time, severe),
            noisy_time,
        )?;
        if observed.quality.decision.tier != noisy_previous {
            noisy_receiver_tier_changes = noisy_receiver_tier_changes.saturating_add(1);
            noisy_previous = observed.quality.decision.tier;
        }
        noisy_sequence = noisy_sequence.saturating_add(1);
        noisy_time = noisy_time.saturating_add(100_000);
    }

    let weak = ReceiverId(u64::try_from(config.receivers).unwrap_or(u64::MAX));
    let weak_first = planner.observe(weak, sample(2, 1_100_000, true), 1_100_000)?;
    if weak_first.quality.decision.tier != QualityTier::High {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "weak receiver degraded before hysteresis threshold",
        ));
    }
    let weak_degraded = planner.observe(weak, sample(3, 1_200_000, true), 1_200_000)?;
    let weak_degraded_tier = weak_degraded.quality.decision.tier;

    let healthy_high_after_weak_degrade = (1..config.receivers)
        .filter(|id| {
            planner
                .route(ReceiverId(u64::try_from(*id).unwrap_or(u64::MAX)))
                .is_some_and(|route| route.tier == QualityTier::High)
        })
        .count();

    let mut weak_recovered_tier = weak_degraded_tier;
    for (sequence, observed_at_us) in [(4, 1_300_000), (5, 1_400_000), (6, 1_500_000)] {
        weak_recovered_tier = planner
            .observe(weak, sample(sequence, observed_at_us, false), observed_at_us)?
            .quality
            .decision
            .tier;
    }

    let unresolved_transport_blocked = {
        let mut controller =
            TransportTopologyController::new(DIRECT_UDP, TransportTopologyHysteresis::default())
                .map_err(|_| {
                    AdaptiveControllerBenchmarkError::Invariant(
                        "default topology hysteresis was invalid",
                    )
                })?;
        matches!(
            controller
                .observe(DIRECT_QUIC, TransportTopologyEvidence::default())
                .status,
            MediaPathCandidateStatus::Blocked {
                evidence: PhysicalGateStatus::Pending,
                ..
            }
        )
    };

    let qualified_switch_required_hysteresis = {
        let mut controller =
            TransportTopologyController::new(DIRECT_UDP, TransportTopologyHysteresis::default())
                .map_err(|_| {
                    AdaptiveControllerBenchmarkError::Invariant(
                        "default topology hysteresis was invalid",
                    )
                })?;
        let evidence = qualified_transport_evidence();
        let first = controller.observe(DIRECT_QUIC, evidence);
        let second = controller.observe(DIRECT_QUIC, evidence);
        let third = controller.observe(DIRECT_QUIC, evidence);
        first.status == MediaPathCandidateStatus::PendingHysteresis
            && second.status == MediaPathCandidateStatus::PendingHysteresis
            && third.status == MediaPathCandidateStatus::Applied
            && third.changed
    };

    let capabilities = RenditionSfuCapabilities {
        hardware_encoder_slots: 3,
        measured_max_renditions: 3,
        measured_max_relay_receivers: config.receivers,
    };
    let unresolved_rendition_blocked = matches!(
        evaluate_rendition_sfu_candidate(
            RenditionSfuCandidate {
                path: DIRECT_UDP,
                max_renditions: 2,
            },
            config.receivers,
            capabilities,
            RenditionSfuEvidence {
                transport_topology: TransportTopologyEvidence {
                    udp_unicast: PhysicalGateStatus::Qualified,
                    ..TransportTopologyEvidence::default()
                },
                multi_rendition: PhysicalGateStatus::Pending,
            },
        )
        .map_err(|_| {
            AdaptiveControllerBenchmarkError::Invariant(
                "synthetic rendition capabilities were invalid",
            )
        })?,
        RenditionSfuCandidateStatus::Blocked(RenditionSfuBlockReason::MultiRenditionGate(
            PhysicalGateStatus::Pending
        ))
    );

    let reliable_fallback_eligible_without_default_selection = matches!(
        evaluate_rendition_sfu_candidate(
            RenditionSfuCandidate {
                path: RELIABLE_FALLBACK,
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
        .map_err(|_| {
            AdaptiveControllerBenchmarkError::Invariant(
                "fallback rendition capabilities were invalid",
            )
        })?,
        RenditionSfuCandidateStatus::Eligible
    );

    if healthy_high_after_weak_degrade != config.receivers.saturating_sub(1) {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "weak receiver degraded a healthy peer",
        ));
    }
    if weak_degraded_tier != QualityTier::Emergency {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "weak receiver did not degrade after repeated severe samples",
        ));
    }
    if weak_recovered_tier != QualityTier::High {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "weak receiver did not recover after required healthy samples",
        ));
    }
    if noisy_receiver_tier_changes != 0 {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "alternating noise bypassed tier hysteresis",
        ));
    }
    if max_routed_receivers > config.receivers {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "routed receiver count exceeded configured capacity",
        ));
    }
    if !unresolved_transport_blocked
        || !qualified_switch_required_hysteresis
        || !unresolved_rendition_blocked
        || !reliable_fallback_eligible_without_default_selection
    {
        return Err(AdaptiveControllerBenchmarkError::Invariant(
            "physical/evidence gate invariant failed",
        ));
    }

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

fn sample(sequence: u64, observed_at_us: u64, severe: bool) -> ReceiverQualitySample {
    ReceiverQualitySample {
        schema_version: RECEIVER_QUALITY_SAMPLE_VERSION,
        sample_sequence: sequence,
        observed_at_us,
        network: NetworkMetrics {
            rtt_ms: 10.0,
            packet_loss: 0.001,
            jitter_ms: 1.0,
            decode_fps: 30.0,
            queue_delay_ms: 4.0,
            estimated_mbps: 100.0,
            multicast_viable: false,
            wireless: false,
        },
        reordered_packet_rate: if severe { 0.08 } else { 0.001 },
        decode_delay_ms: if severe { 140.0 } else { 4.0 },
        render_delay_ms: if severe { 140.0 } else { 3.0 },
        queue_depth: if severe { 12 } else { 1 },
        queue_drop_rate: if severe { 0.08 } else { 0.0 },
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
            Err(AdaptiveControllerBenchmarkError::UnsupportedReceiverCount(3))
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
