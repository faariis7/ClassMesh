use classmesh_core::StreamKind;
use classmesh_core::adaptation::{QualityTier, StreamProfile, profile_for};
use classmesh_core::presence::DeviceHealth;
use classmesh_core::quality_sample::{ReceiverQualitySample, ReceiverQualitySampleError};
use classmesh_core::transport_topology::{
    MediaPath, PhysicalGateStatus, PhysicalPathGate, TransportTopologyEvidence,
    media_path_blocking_gate,
};
use classmesh_video::monitoring_scheduler::MonitoringSourceId;

use crate::classroom_view::ClassroomDeviceRow;

pub const DEFAULT_MAX_DIAGNOSTIC_CODES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceDiagnosticsConfig {
    pub max_diagnostic_codes: usize,
}

impl Default for DeviceDiagnosticsConfig {
    fn default() -> Self {
        Self {
            max_diagnostic_codes: DEFAULT_MAX_DIAGNOSTIC_CODES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceDiagnosticsError {
    InvalidMaxDiagnosticCodes,
    TooManyDiagnosticCodes,
    InvalidDiagnosticCode,
    InvalidQualitySample(ReceiverQualitySampleError),
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceDiagnosticsSnapshot<'a> {
    pub device: &'a ClassroomDeviceRow,
    pub quality_sample: Option<ReceiverQualitySample>,
    pub active_path: Option<MediaPath>,
    pub topology_evidence: TransportTopologyEvidence,
    pub diagnostic_codes: &'a [&'static str],
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceDiagnosticsView {
    pub source_id: MonitoringSourceId,
    pub display_name: String,
    pub health: DeviceHealth,
    pub quality_tier: Option<QualityTier>,
    pub quality_sample: Option<ReceiverQualitySample>,
    pub active_path: Option<MediaPath>,
    pub topology_evidence: TransportTopologyEvidence,
    pub diagnostic_codes: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TroubleshootingOverrideRequest {
    Automatic,
    Quality {
        stream_kind: StreamKind,
        tier: QualityTier,
    },
    MediaPath(MediaPath),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatedTroubleshootingOverride {
    Automatic,
    Quality {
        stream_kind: StreamKind,
        tier: QualityTier,
        profile: StreamProfile,
    },
    MediaPath(MediaPath),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TroubleshootingOverrideError {
    BlockedMediaPath {
        gate: PhysicalPathGate,
        evidence: PhysicalGateStatus,
    },
}

#[derive(Debug)]
pub struct TeacherDeviceDiagnosticsViewModel {
    config: DeviceDiagnosticsConfig,
}

impl TeacherDeviceDiagnosticsViewModel {
    pub fn new(config: DeviceDiagnosticsConfig) -> Result<Self, DeviceDiagnosticsError> {
        if config.max_diagnostic_codes == 0 {
            return Err(DeviceDiagnosticsError::InvalidMaxDiagnosticCodes);
        }
        Ok(Self { config })
    }

    pub fn project(
        &self,
        snapshot: DeviceDiagnosticsSnapshot<'_>,
    ) -> Result<DeviceDiagnosticsView, DeviceDiagnosticsError> {
        if snapshot.diagnostic_codes.len() > self.config.max_diagnostic_codes {
            return Err(DeviceDiagnosticsError::TooManyDiagnosticCodes);
        }
        if snapshot
            .diagnostic_codes
            .iter()
            .any(|code| code.trim().is_empty())
        {
            return Err(DeviceDiagnosticsError::InvalidDiagnosticCode);
        }

        let quality_sample = match snapshot.quality_sample {
            Some(sample) => Some(
                sample
                    .validate()
                    .map_err(DeviceDiagnosticsError::InvalidQualitySample)?,
            ),
            None => None,
        };

        let mut diagnostic_codes = Vec::with_capacity(snapshot.diagnostic_codes.len());
        for code in snapshot.diagnostic_codes {
            if !diagnostic_codes.contains(code) {
                diagnostic_codes.push(*code);
            }
        }

        Ok(DeviceDiagnosticsView {
            source_id: snapshot.device.source_id,
            display_name: snapshot.device.display_name.clone(),
            health: snapshot.device.health,
            quality_tier: snapshot.device.quality_tier,
            quality_sample,
            active_path: snapshot.active_path,
            topology_evidence: snapshot.topology_evidence,
            diagnostic_codes,
        })
    }

    pub fn validate_override(
        &self,
        request: TroubleshootingOverrideRequest,
        evidence: TransportTopologyEvidence,
    ) -> Result<ValidatedTroubleshootingOverride, TroubleshootingOverrideError> {
        match request {
            TroubleshootingOverrideRequest::Automatic => {
                Ok(ValidatedTroubleshootingOverride::Automatic)
            }
            TroubleshootingOverrideRequest::Quality { stream_kind, tier } => {
                Ok(ValidatedTroubleshootingOverride::Quality {
                    stream_kind,
                    tier,
                    profile: profile_for(stream_kind, tier),
                })
            }
            TroubleshootingOverrideRequest::MediaPath(path) => {
                if let Some((gate, gate_evidence)) = media_path_blocking_gate(path, evidence) {
                    return Err(TroubleshootingOverrideError::BlockedMediaPath {
                        gate,
                        evidence: gate_evidence,
                    });
                }
                Ok(ValidatedTroubleshootingOverride::MediaPath(path))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use classmesh_core::MediaState;
    use classmesh_core::MediaTransport;
    use classmesh_core::NetworkMetrics;
    use classmesh_core::adaptation::profile_for;
    use classmesh_core::presence::PresenceState;
    use classmesh_core::quality_sample::{
        RECEIVER_QUALITY_SAMPLE_VERSION, ReceiverCapabilityHealth,
    };
    use classmesh_core::transport_topology::{MediaTopology, PhysicalGateStatus};

    use super::*;

    fn row() -> ClassroomDeviceRow {
        ClassroomDeviceRow {
            source_id: MonitoringSourceId(7),
            display_name: "Student 07".into(),
            health: DeviceHealth {
                presence: PresenceState::Online,
                media: MediaState::Recovering,
                worker_ready: true,
                service_ready: true,
            },
            quality_tier: Some(QualityTier::Low),
            thumbnail_available: true,
            interactive_active: false,
            selected: true,
        }
    }

    fn healthy_sample() -> ReceiverQualitySample {
        ReceiverQualitySample {
            schema_version: RECEIVER_QUALITY_SAMPLE_VERSION,
            sample_sequence: 9,
            observed_at_us: 1_000_000,
            network: NetworkMetrics {
                rtt_ms: 12.0,
                packet_loss: 0.002,
                jitter_ms: 1.0,
                decode_fps: 30.0,
                queue_delay_ms: 4.0,
                estimated_mbps: 80.0,
                multicast_viable: false,
                wireless: false,
            },
            reordered_packet_rate: 0.001,
            decode_delay_ms: 5.0,
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

    fn direct_udp() -> MediaPath {
        MediaPath {
            transport: MediaTransport::UdpUnicast,
            topology: MediaTopology::Direct,
        }
    }

    #[test]
    fn diagnostics_projection_preserves_control_and_media_health_independently() {
        let model =
            TeacherDeviceDiagnosticsViewModel::new(DeviceDiagnosticsConfig::default()).unwrap();
        let row = row();
        let codes = [
            "control.transport.timeout",
            "control.stream.invalid_profile",
        ];
        let view = model
            .project(DeviceDiagnosticsSnapshot {
                device: &row,
                quality_sample: Some(healthy_sample()),
                active_path: Some(direct_udp()),
                topology_evidence: TransportTopologyEvidence::default(),
                diagnostic_codes: &codes,
            })
            .unwrap();

        assert_eq!(view.health.presence, PresenceState::Online);
        assert_eq!(view.health.media, MediaState::Recovering);
        assert_eq!(view.quality_tier, Some(QualityTier::Low));
        assert_eq!(view.quality_sample, Some(healthy_sample()));
        assert_eq!(view.diagnostic_codes, codes);
    }

    #[test]
    fn malformed_quality_sample_fails_closed() {
        let model =
            TeacherDeviceDiagnosticsViewModel::new(DeviceDiagnosticsConfig::default()).unwrap();
        let row = row();
        let mut sample = healthy_sample();
        sample.schema_version += 1;

        assert!(matches!(
            model.project(DeviceDiagnosticsSnapshot {
                device: &row,
                quality_sample: Some(sample),
                active_path: None,
                topology_evidence: TransportTopologyEvidence::default(),
                diagnostic_codes: &[],
            }),
            Err(DeviceDiagnosticsError::InvalidQualitySample(_))
        ));
    }

    #[test]
    fn diagnostic_codes_are_bounded_nonempty_and_deduplicated() {
        let model = TeacherDeviceDiagnosticsViewModel::new(DeviceDiagnosticsConfig {
            max_diagnostic_codes: 2,
        })
        .unwrap();
        let row = row();

        let deduped = model
            .project(DeviceDiagnosticsSnapshot {
                device: &row,
                quality_sample: None,
                active_path: None,
                topology_evidence: TransportTopologyEvidence::default(),
                diagnostic_codes: &["control.transport.timeout", "control.transport.timeout"],
            })
            .unwrap();
        assert_eq!(deduped.diagnostic_codes, vec!["control.transport.timeout"]);

        assert_eq!(
            model.project(DeviceDiagnosticsSnapshot {
                device: &row,
                quality_sample: None,
                active_path: None,
                topology_evidence: TransportTopologyEvidence::default(),
                diagnostic_codes: &["a", "b", "c"],
            }),
            Err(DeviceDiagnosticsError::TooManyDiagnosticCodes)
        );

        assert_eq!(
            model.project(DeviceDiagnosticsSnapshot {
                device: &row,
                quality_sample: None,
                active_path: None,
                topology_evidence: TransportTopologyEvidence::default(),
                diagnostic_codes: &[""],
            }),
            Err(DeviceDiagnosticsError::InvalidDiagnosticCode)
        );
    }

    #[test]
    fn quality_override_uses_existing_engine_profile() {
        let model =
            TeacherDeviceDiagnosticsViewModel::new(DeviceDiagnosticsConfig::default()).unwrap();
        let validated = model
            .validate_override(
                TroubleshootingOverrideRequest::Quality {
                    stream_kind: StreamKind::Interactive,
                    tier: QualityTier::Low,
                },
                TransportTopologyEvidence::default(),
            )
            .unwrap();

        assert_eq!(
            validated,
            ValidatedTroubleshootingOverride::Quality {
                stream_kind: StreamKind::Interactive,
                tier: QualityTier::Low,
                profile: profile_for(StreamKind::Interactive, QualityTier::Low),
            }
        );
    }

    #[test]
    fn unresolved_transport_gate_blocks_typed_path_override() {
        let model =
            TeacherDeviceDiagnosticsViewModel::new(DeviceDiagnosticsConfig::default()).unwrap();
        assert_eq!(
            model.validate_override(
                TroubleshootingOverrideRequest::MediaPath(direct_udp()),
                TransportTopologyEvidence::default(),
            ),
            Err(TroubleshootingOverrideError::BlockedMediaPath {
                gate: PhysicalPathGate::Phase4UdpUnicast,
                evidence: PhysicalGateStatus::Pending,
            })
        );
    }

    #[test]
    fn qualified_path_and_reliable_fallback_can_be_validated_without_selecting_defaults() {
        let model =
            TeacherDeviceDiagnosticsViewModel::new(DeviceDiagnosticsConfig::default()).unwrap();
        let evidence = TransportTopologyEvidence {
            udp_unicast: PhysicalGateStatus::Qualified,
            ..TransportTopologyEvidence::default()
        };

        assert_eq!(
            model
                .validate_override(
                    TroubleshootingOverrideRequest::MediaPath(direct_udp()),
                    evidence,
                )
                .unwrap(),
            ValidatedTroubleshootingOverride::MediaPath(direct_udp())
        );

        let fallback = MediaPath {
            transport: MediaTransport::ReliableFallback,
            topology: MediaTopology::Direct,
        };
        assert_eq!(
            model
                .validate_override(
                    TroubleshootingOverrideRequest::MediaPath(fallback),
                    TransportTopologyEvidence::default(),
                )
                .unwrap(),
            ValidatedTroubleshootingOverride::MediaPath(fallback)
        );
    }

    #[test]
    fn automatic_override_preserves_engine_ownership() {
        let model =
            TeacherDeviceDiagnosticsViewModel::new(DeviceDiagnosticsConfig::default()).unwrap();
        assert_eq!(
            model
                .validate_override(
                    TroubleshootingOverrideRequest::Automatic,
                    TransportTopologyEvidence::default(),
                )
                .unwrap(),
            ValidatedTroubleshootingOverride::Automatic
        );
    }

    #[test]
    fn relay_override_remains_blocked_by_relay_topology_gate() {
        let model =
            TeacherDeviceDiagnosticsViewModel::new(DeviceDiagnosticsConfig::default()).unwrap();
        let relay = MediaPath {
            transport: MediaTransport::ReliableFallback,
            topology: MediaTopology::Relay,
        };

        assert_eq!(
            model.validate_override(
                TroubleshootingOverrideRequest::MediaPath(relay),
                TransportTopologyEvidence::default(),
            ),
            Err(TroubleshootingOverrideError::BlockedMediaPath {
                gate: PhysicalPathGate::Phase8RelayTopology,
                evidence: PhysicalGateStatus::Pending,
            })
        );
    }

    #[test]
    fn invalid_zero_diagnostic_capacity_is_rejected() {
        assert!(matches!(
            TeacherDeviceDiagnosticsViewModel::new(DeviceDiagnosticsConfig {
                max_diagnostic_codes: 0,
            }),
            Err(DeviceDiagnosticsError::InvalidMaxDiagnosticCodes)
        ));
    }
}
