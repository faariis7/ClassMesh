use crate::transport_topology::{
    MediaPath, MediaTopology, PhysicalGateStatus, PhysicalPathGate, TransportTopologyEvidence,
    media_path_blocking_gate,
};

pub const MAX_OPTIONAL_RENDITIONS: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenditionSfuCandidate {
    pub path: MediaPath,
    pub max_renditions: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenditionSfuCapabilities {
    pub hardware_encoder_slots: u8,
    pub measured_max_renditions: u8,
    pub measured_max_relay_receivers: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenditionSfuEvidence {
    pub transport_topology: TransportTopologyEvidence,
    pub multi_rendition: PhysicalGateStatus,
}

impl Default for RenditionSfuEvidence {
    fn default() -> Self {
        Self {
            transport_topology: TransportTopologyEvidence::default(),
            multi_rendition: PhysicalGateStatus::Pending,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenditionSfuCapabilityError {
    NoHardwareEncoderSlots,
    NoMeasuredRenditionCapacity,
    MeasuredRenditionsExceedHardwareSlots,
}

impl RenditionSfuCapabilities {
    pub fn validate(self) -> Result<Self, RenditionSfuCapabilityError> {
        if self.hardware_encoder_slots == 0 {
            return Err(RenditionSfuCapabilityError::NoHardwareEncoderSlots);
        }
        if self.measured_max_renditions == 0 {
            return Err(RenditionSfuCapabilityError::NoMeasuredRenditionCapacity);
        }
        if self.measured_max_renditions > self.hardware_encoder_slots {
            return Err(
                RenditionSfuCapabilityError::MeasuredRenditionsExceedHardwareSlots,
            );
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenditionSfuBlockReason {
    InvalidReceiverCount,
    InvalidRenditionCount,
    TransportTopologyGate {
        gate: PhysicalPathGate,
        evidence: PhysicalGateStatus,
    },
    MultiRenditionGate(PhysicalGateStatus),
    InsufficientEncoderSlots {
        requested: u8,
        available: u8,
    },
    ExceedsMeasuredRenditions {
        requested: u8,
        measured: u8,
    },
    ExceedsMeasuredRelayReceivers {
        requested: usize,
        measured: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenditionSfuCandidateStatus {
    Eligible,
    Blocked(RenditionSfuBlockReason),
}

pub fn evaluate_rendition_sfu_candidate(
    candidate: RenditionSfuCandidate,
    receiver_count: usize,
    capabilities: RenditionSfuCapabilities,
    evidence: RenditionSfuEvidence,
) -> Result<RenditionSfuCandidateStatus, RenditionSfuCapabilityError> {
    let capabilities = capabilities.validate()?;

    if receiver_count == 0 {
        return Ok(RenditionSfuCandidateStatus::Blocked(
            RenditionSfuBlockReason::InvalidReceiverCount,
        ));
    }
    if candidate.max_renditions == 0 || candidate.max_renditions > MAX_OPTIONAL_RENDITIONS {
        return Ok(RenditionSfuCandidateStatus::Blocked(
            RenditionSfuBlockReason::InvalidRenditionCount,
        ));
    }

    if let Some((gate, gate_evidence)) =
        media_path_blocking_gate(candidate.path, evidence.transport_topology)
    {
        return Ok(RenditionSfuCandidateStatus::Blocked(
            RenditionSfuBlockReason::TransportTopologyGate {
                gate,
                evidence: gate_evidence,
            },
        ));
    }

    if candidate.max_renditions > 1 {
        if evidence.multi_rendition != PhysicalGateStatus::Qualified {
            return Ok(RenditionSfuCandidateStatus::Blocked(
                RenditionSfuBlockReason::MultiRenditionGate(evidence.multi_rendition),
            ));
        }
        if candidate.max_renditions > capabilities.hardware_encoder_slots {
            return Ok(RenditionSfuCandidateStatus::Blocked(
                RenditionSfuBlockReason::InsufficientEncoderSlots {
                    requested: candidate.max_renditions,
                    available: capabilities.hardware_encoder_slots,
                },
            ));
        }
        if candidate.max_renditions > capabilities.measured_max_renditions {
            return Ok(RenditionSfuCandidateStatus::Blocked(
                RenditionSfuBlockReason::ExceedsMeasuredRenditions {
                    requested: candidate.max_renditions,
                    measured: capabilities.measured_max_renditions,
                },
            ));
        }
    }

    if candidate.path.topology == MediaTopology::Relay
        && receiver_count > capabilities.measured_max_relay_receivers
    {
        return Ok(RenditionSfuCandidateStatus::Blocked(
            RenditionSfuBlockReason::ExceedsMeasuredRelayReceivers {
                requested: receiver_count,
                measured: capabilities.measured_max_relay_receivers,
            },
        ));
    }

    Ok(RenditionSfuCandidateStatus::Eligible)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MediaTransport;
    use crate::transport_topology::{MediaTopology, PhysicalGateStatus};

    const DIRECT_UDP: MediaPath = MediaPath {
        transport: MediaTransport::UdpUnicast,
        topology: MediaTopology::Direct,
    };
    const RELAY_WEBRTC: MediaPath = MediaPath {
        transport: MediaTransport::WebRtc,
        topology: MediaTopology::Relay,
    };
    const FALLBACK: MediaPath = MediaPath {
        transport: MediaTransport::ReliableFallback,
        topology: MediaTopology::Direct,
    };

    fn capabilities() -> RenditionSfuCapabilities {
        RenditionSfuCapabilities {
            hardware_encoder_slots: 3,
            measured_max_renditions: 3,
            measured_max_relay_receivers: 20,
        }
    }

    fn qualified_evidence() -> RenditionSfuEvidence {
        RenditionSfuEvidence {
            transport_topology: TransportTopologyEvidence {
                udp_unicast: PhysicalGateStatus::Qualified,
                quic_datagram: PhysicalGateStatus::Qualified,
                wired_multicast: PhysicalGateStatus::Qualified,
                web_rtc: PhysicalGateStatus::Qualified,
                relay_topology: PhysicalGateStatus::Qualified,
            },
            multi_rendition: PhysicalGateStatus::Qualified,
        }
    }

    #[test]
    fn default_evidence_cannot_enable_unresolved_direct_or_sfu_candidate() {
        for candidate in [
            RenditionSfuCandidate {
                path: DIRECT_UDP,
                max_renditions: 1,
            },
            RenditionSfuCandidate {
                path: RELAY_WEBRTC,
                max_renditions: 1,
            },
        ] {
            let status = evaluate_rendition_sfu_candidate(
                candidate,
                5,
                capabilities(),
                RenditionSfuEvidence::default(),
            )
            .unwrap();
            assert!(matches!(
                status,
                RenditionSfuCandidateStatus::Blocked(
                    RenditionSfuBlockReason::TransportTopologyGate { .. }
                )
            ));
        }
    }

    #[test]
    fn extra_rendition_requires_gate_slots_and_measured_capacity() {
        let candidate = RenditionSfuCandidate {
            path: DIRECT_UDP,
            max_renditions: 2,
        };
        let mut evidence = qualified_evidence();
        evidence.multi_rendition = PhysicalGateStatus::Pending;

        assert_eq!(
            evaluate_rendition_sfu_candidate(candidate, 10, capabilities(), evidence).unwrap(),
            RenditionSfuCandidateStatus::Blocked(
                RenditionSfuBlockReason::MultiRenditionGate(PhysicalGateStatus::Pending)
            )
        );

        let mut limited = capabilities();
        limited.hardware_encoder_slots = 1;
        limited.measured_max_renditions = 1;
        assert_eq!(
            evaluate_rendition_sfu_candidate(
                candidate,
                10,
                limited,
                qualified_evidence(),
            )
            .unwrap(),
            RenditionSfuCandidateStatus::Blocked(
                RenditionSfuBlockReason::InsufficientEncoderSlots {
                    requested: 2,
                    available: 1,
                }
            )
        );

        let measured = RenditionSfuCapabilities {
            hardware_encoder_slots: 3,
            measured_max_renditions: 1,
            measured_max_relay_receivers: 20,
        };
        assert_eq!(
            evaluate_rendition_sfu_candidate(
                candidate,
                10,
                measured,
                qualified_evidence(),
            )
            .unwrap(),
            RenditionSfuCandidateStatus::Blocked(
                RenditionSfuBlockReason::ExceedsMeasuredRenditions {
                    requested: 2,
                    measured: 1,
                }
            )
        );
    }

    #[test]
    fn relay_candidate_requires_retained_scale_evidence() {
        let candidate = RenditionSfuCandidate {
            path: RELAY_WEBRTC,
            max_renditions: 1,
        };
        let limited = RenditionSfuCapabilities {
            hardware_encoder_slots: 1,
            measured_max_renditions: 1,
            measured_max_relay_receivers: 5,
        };

        assert_eq!(
            evaluate_rendition_sfu_candidate(
                candidate,
                10,
                limited,
                qualified_evidence(),
            )
            .unwrap(),
            RenditionSfuCandidateStatus::Blocked(
                RenditionSfuBlockReason::ExceedsMeasuredRelayReceivers {
                    requested: 10,
                    measured: 5,
                }
            )
        );
    }

    #[test]
    fn fully_qualified_candidate_is_only_marked_eligible_not_selected() {
        let candidate = RenditionSfuCandidate {
            path: RELAY_WEBRTC,
            max_renditions: 2,
        };
        assert_eq!(
            evaluate_rendition_sfu_candidate(
                candidate,
                20,
                capabilities(),
                qualified_evidence(),
            )
            .unwrap(),
            RenditionSfuCandidateStatus::Eligible
        );
    }

    #[test]
    fn reliable_fallback_single_rendition_remains_eligible_without_physical_default_selection() {
        assert_eq!(
            evaluate_rendition_sfu_candidate(
                RenditionSfuCandidate {
                    path: FALLBACK,
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
            .unwrap(),
            RenditionSfuCandidateStatus::Eligible
        );
    }

    #[test]
    fn invalid_counts_fail_closed() {
        assert_eq!(
            evaluate_rendition_sfu_candidate(
                RenditionSfuCandidate {
                    path: DIRECT_UDP,
                    max_renditions: 0,
                },
                5,
                capabilities(),
                qualified_evidence(),
            )
            .unwrap(),
            RenditionSfuCandidateStatus::Blocked(
                RenditionSfuBlockReason::InvalidRenditionCount
            )
        );
        assert_eq!(
            evaluate_rendition_sfu_candidate(
                RenditionSfuCandidate {
                    path: DIRECT_UDP,
                    max_renditions: MAX_OPTIONAL_RENDITIONS + 1,
                },
                5,
                capabilities(),
                qualified_evidence(),
            )
            .unwrap(),
            RenditionSfuCandidateStatus::Blocked(
                RenditionSfuBlockReason::InvalidRenditionCount
            )
        );
        assert_eq!(
            evaluate_rendition_sfu_candidate(
                RenditionSfuCandidate {
                    path: DIRECT_UDP,
                    max_renditions: 1,
                },
                0,
                capabilities(),
                qualified_evidence(),
            )
            .unwrap(),
            RenditionSfuCandidateStatus::Blocked(
                RenditionSfuBlockReason::InvalidReceiverCount
            )
        );
    }
}
