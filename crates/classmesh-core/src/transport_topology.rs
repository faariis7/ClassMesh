use crate::MediaTransport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaTopology {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaPath {
    pub transport: MediaTransport,
    pub topology: MediaTopology,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalGateStatus {
    Pending,
    Qualified,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalPathGate {
    Phase4UdpUnicast,
    Phase4QuicDatagram,
    Phase7WiredMulticast,
    WebRtc,
    Phase8RelayTopology,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportTopologyEvidence {
    pub udp_unicast: PhysicalGateStatus,
    pub quic_datagram: PhysicalGateStatus,
    pub wired_multicast: PhysicalGateStatus,
    pub web_rtc: PhysicalGateStatus,
    pub relay_topology: PhysicalGateStatus,
}

impl Default for TransportTopologyEvidence {
    fn default() -> Self {
        Self {
            udp_unicast: PhysicalGateStatus::Pending,
            quic_datagram: PhysicalGateStatus::Pending,
            wired_multicast: PhysicalGateStatus::Pending,
            web_rtc: PhysicalGateStatus::Pending,
            relay_topology: PhysicalGateStatus::Pending,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportTopologyHysteresis {
    pub switch_samples: u8,
    pub fallback_samples: u8,
}

impl Default for TransportTopologyHysteresis {
    fn default() -> Self {
        Self {
            switch_samples: 3,
            fallback_samples: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportTopologyConfigError {
    InvalidSwitchSamples,
    InvalidFallbackSamples,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaPathCandidateStatus {
    Current,
    PendingHysteresis,
    Applied,
    Blocked {
        gate: PhysicalPathGate,
        evidence: PhysicalGateStatus,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MediaPathObservation {
    pub active: MediaPath,
    pub changed: bool,
    pub status: MediaPathCandidateStatus,
    pub pending_samples: u8,
}

#[derive(Debug)]
pub struct TransportTopologyController {
    active: MediaPath,
    hysteresis: TransportTopologyHysteresis,
    pending: Option<MediaPath>,
    pending_samples: u8,
}

impl TransportTopologyController {
    pub fn new(
        initial: MediaPath,
        hysteresis: TransportTopologyHysteresis,
    ) -> Result<Self, TransportTopologyConfigError> {
        if hysteresis.switch_samples == 0 {
            return Err(TransportTopologyConfigError::InvalidSwitchSamples);
        }
        if hysteresis.fallback_samples == 0 {
            return Err(TransportTopologyConfigError::InvalidFallbackSamples);
        }

        Ok(Self {
            active: initial,
            hysteresis,
            pending: None,
            pending_samples: 0,
        })
    }

    #[must_use]
    pub const fn current(&self) -> MediaPath {
        self.active
    }

    #[must_use]
    pub const fn pending(&self) -> Option<MediaPath> {
        self.pending
    }

    pub fn observe(
        &mut self,
        candidate: MediaPath,
        evidence: TransportTopologyEvidence,
    ) -> MediaPathObservation {
        if candidate == self.active {
            self.clear_pending();
            return self.observation(false, MediaPathCandidateStatus::Current);
        }

        if let Some((gate, gate_status)) = media_path_blocking_gate(candidate, evidence) {
            self.clear_pending();
            return self.observation(
                false,
                MediaPathCandidateStatus::Blocked {
                    gate,
                    evidence: gate_status,
                },
            );
        }

        if self.pending == Some(candidate) {
            self.pending_samples = self.pending_samples.saturating_add(1);
        } else {
            self.pending = Some(candidate);
            self.pending_samples = 1;
        }

        let required = if candidate.transport == MediaTransport::ReliableFallback {
            self.hysteresis.fallback_samples
        } else {
            self.hysteresis.switch_samples
        };

        if self.pending_samples >= required {
            self.active = candidate;
            self.clear_pending();
            self.observation(true, MediaPathCandidateStatus::Applied)
        } else {
            self.observation(false, MediaPathCandidateStatus::PendingHysteresis)
        }
    }

    fn clear_pending(&mut self) {
        self.pending = None;
        self.pending_samples = 0;
    }

    fn observation(&self, changed: bool, status: MediaPathCandidateStatus) -> MediaPathObservation {
        MediaPathObservation {
            active: self.active,
            changed,
            status,
            pending_samples: self.pending_samples,
        }
    }
}

pub fn media_path_blocking_gate(
    candidate: MediaPath,
    evidence: TransportTopologyEvidence,
) -> Option<(PhysicalPathGate, PhysicalGateStatus)> {
    let transport_gate = match candidate.transport {
        MediaTransport::UdpMulticast => Some((
            PhysicalPathGate::Phase7WiredMulticast,
            evidence.wired_multicast,
        )),
        MediaTransport::UdpUnicast => {
            Some((PhysicalPathGate::Phase4UdpUnicast, evidence.udp_unicast))
        }
        MediaTransport::QuicDatagram => {
            Some((PhysicalPathGate::Phase4QuicDatagram, evidence.quic_datagram))
        }
        MediaTransport::WebRtc => Some((PhysicalPathGate::WebRtc, evidence.web_rtc)),
        MediaTransport::ReliableFallback => None,
    };

    if let Some((gate, status)) = transport_gate {
        if status != PhysicalGateStatus::Qualified {
            return Some((gate, status));
        }
    }

    if candidate.topology == MediaTopology::Relay
        && evidence.relay_topology != PhysicalGateStatus::Qualified
    {
        return Some((
            PhysicalPathGate::Phase8RelayTopology,
            evidence.relay_topology,
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIRECT_UDP: MediaPath = MediaPath {
        transport: MediaTransport::UdpUnicast,
        topology: MediaTopology::Direct,
    };
    const DIRECT_QUIC: MediaPath = MediaPath {
        transport: MediaTransport::QuicDatagram,
        topology: MediaTopology::Direct,
    };
    const WIRED_MULTICAST: MediaPath = MediaPath {
        transport: MediaTransport::UdpMulticast,
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

    fn qualified() -> TransportTopologyEvidence {
        TransportTopologyEvidence {
            udp_unicast: PhysicalGateStatus::Qualified,
            quic_datagram: PhysicalGateStatus::Qualified,
            wired_multicast: PhysicalGateStatus::Qualified,
            web_rtc: PhysicalGateStatus::Qualified,
            relay_topology: PhysicalGateStatus::Qualified,
        }
    }

    #[test]
    fn default_evidence_selects_no_unresolved_transport_or_topology() {
        let mut controller =
            TransportTopologyController::new(DIRECT_UDP, TransportTopologyHysteresis::default())
                .unwrap();

        for candidate in [DIRECT_QUIC, WIRED_MULTICAST, RELAY_WEBRTC] {
            let observed = controller.observe(candidate, TransportTopologyEvidence::default());
            assert_eq!(observed.active, DIRECT_UDP);
            assert!(!observed.changed);
            assert!(matches!(
                observed.status,
                MediaPathCandidateStatus::Blocked {
                    evidence: PhysicalGateStatus::Pending,
                    ..
                }
            ));
            assert_eq!(controller.pending(), None);
        }
    }

    #[test]
    fn qualified_path_requires_repeated_observations_before_switching() {
        let mut controller =
            TransportTopologyController::new(DIRECT_UDP, TransportTopologyHysteresis::default())
                .unwrap();

        for expected_pending in [1, 2] {
            let observed = controller.observe(DIRECT_QUIC, qualified());
            assert_eq!(observed.active, DIRECT_UDP);
            assert_eq!(observed.status, MediaPathCandidateStatus::PendingHysteresis);
            assert_eq!(observed.pending_samples, expected_pending);
        }

        let applied = controller.observe(DIRECT_QUIC, qualified());
        assert_eq!(applied.active, DIRECT_QUIC);
        assert!(applied.changed);
        assert_eq!(applied.status, MediaPathCandidateStatus::Applied);
        assert_eq!(applied.pending_samples, 0);
    }

    #[test]
    fn candidate_flapping_resets_hysteresis_progress() {
        let mut controller =
            TransportTopologyController::new(DIRECT_UDP, TransportTopologyHysteresis::default())
                .unwrap();

        assert_eq!(
            controller.observe(DIRECT_QUIC, qualified()).pending_samples,
            1
        );
        assert_eq!(
            controller
                .observe(WIRED_MULTICAST, qualified())
                .pending_samples,
            1
        );
        assert_eq!(
            controller.observe(DIRECT_QUIC, qualified()).pending_samples,
            1
        );
        assert_eq!(controller.current(), DIRECT_UDP);
    }

    #[test]
    fn relay_requires_both_transport_and_topology_evidence() {
        let mut controller =
            TransportTopologyController::new(DIRECT_UDP, TransportTopologyHysteresis::default())
                .unwrap();
        let mut evidence = qualified();
        evidence.relay_topology = PhysicalGateStatus::Pending;

        let blocked = controller.observe(RELAY_WEBRTC, evidence);
        assert_eq!(
            blocked.status,
            MediaPathCandidateStatus::Blocked {
                gate: PhysicalPathGate::Phase8RelayTopology,
                evidence: PhysicalGateStatus::Pending,
            }
        );

        evidence.relay_topology = PhysicalGateStatus::Qualified;
        evidence.web_rtc = PhysicalGateStatus::Rejected;
        let blocked_transport = controller.observe(RELAY_WEBRTC, evidence);
        assert_eq!(
            blocked_transport.status,
            MediaPathCandidateStatus::Blocked {
                gate: PhysicalPathGate::WebRtc,
                evidence: PhysicalGateStatus::Rejected,
            }
        );
    }

    #[test]
    fn reliable_fallback_has_explicit_fast_hysteresis_without_physical_default_selection() {
        let mut controller = TransportTopologyController::new(
            DIRECT_UDP,
            TransportTopologyHysteresis {
                switch_samples: 3,
                fallback_samples: 1,
            },
        )
        .unwrap();

        let observed = controller.observe(FALLBACK, TransportTopologyEvidence::default());
        assert_eq!(observed.active, FALLBACK);
        assert!(observed.changed);
        assert_eq!(observed.status, MediaPathCandidateStatus::Applied);
    }

    #[test]
    fn returning_to_current_path_clears_pending_switch() {
        let mut controller =
            TransportTopologyController::new(DIRECT_UDP, TransportTopologyHysteresis::default())
                .unwrap();

        assert_eq!(
            controller.observe(DIRECT_QUIC, qualified()).pending_samples,
            1
        );
        let current = controller.observe(DIRECT_UDP, TransportTopologyEvidence::default());
        assert_eq!(current.status, MediaPathCandidateStatus::Current);
        assert_eq!(current.pending_samples, 0);
        assert_eq!(controller.pending(), None);
    }

    #[test]
    fn zero_hysteresis_configuration_is_rejected() {
        assert_eq!(
            TransportTopologyController::new(
                DIRECT_UDP,
                TransportTopologyHysteresis {
                    switch_samples: 0,
                    fallback_samples: 1,
                },
            )
            .unwrap_err(),
            TransportTopologyConfigError::InvalidSwitchSamples
        );
        assert_eq!(
            TransportTopologyController::new(
                DIRECT_UDP,
                TransportTopologyHysteresis {
                    switch_samples: 3,
                    fallback_samples: 0,
                },
            )
            .unwrap_err(),
            TransportTopologyConfigError::InvalidFallbackSamples
        );
    }
}
