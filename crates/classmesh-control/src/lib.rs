#![forbid(unsafe_code)]

pub mod bootstrap;
pub mod enrollment;
pub mod enrollment_result;
pub mod framing;
pub mod issuance;
pub mod handshake;
pub mod quic;

use std::collections::BTreeSet;
use std::time::Duration;

use classmesh_protocol::{Capability, ControlRole, MediaHealth, ProtocolVersion};
use classmesh_security::PrincipalId;

pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);
pub const DEFAULT_SUSPECT_AFTER: Duration = Duration::from_secs(6);
pub const DEFAULT_OFFLINE_AFTER: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlHello {
    pub principal_id: PrincipalId,
    pub role: ControlRole,
    pub version: ProtocolVersion,
    pub capabilities: BTreeSet<Capability>,
    pub hostname: String,
    pub app_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedHello {
    pub principal_id: PrincipalId,
    pub role: ControlRole,
    pub version: ProtocolVersion,
    pub capabilities: BTreeSet<Capability>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationError {
    IncompatibleProtocol {
        local: ProtocolVersion,
        peer: ProtocolVersion,
    },
}

pub fn negotiate_hello(
    local_version: ProtocolVersion,
    local_capabilities: &BTreeSet<Capability>,
    peer: &ControlHello,
) -> Result<NegotiatedHello, NegotiationError> {
    let Some(version) = local_version.negotiate(peer.version) else {
        return Err(NegotiationError::IncompatibleProtocol {
            local: local_version,
            peer: peer.version,
        });
    };

    let capabilities = local_capabilities
        .intersection(&peer.capabilities)
        .copied()
        .collect();

    Ok(NegotiatedHello {
        principal_id: peer.principal_id,
        role: peer.role,
        version,
        capabilities,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatPolicy {
    pub interval: Duration,
    pub suspect_after: Duration,
    pub offline_after: Duration,
}

impl Default for HeartbeatPolicy {
    fn default() -> Self {
        Self {
            interval: DEFAULT_HEARTBEAT_INTERVAL,
            suspect_after: DEFAULT_SUSPECT_AFTER,
            offline_after: DEFAULT_OFFLINE_AFTER,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatPolicyError {
    ZeroInterval,
    SuspectBeforeInterval,
    OfflineNotAfterSuspect,
}

impl HeartbeatPolicy {
    pub fn validate(self) -> Result<(), HeartbeatPolicyError> {
        if self.interval.is_zero() {
            return Err(HeartbeatPolicyError::ZeroInterval);
        }
        if self.suspect_after < self.interval {
            return Err(HeartbeatPolicyError::SuspectBeforeInterval);
        }
        if self.offline_after <= self.suspect_after {
            return Err(HeartbeatPolicyError::OfflineNotAfterSuspect);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatSample {
    pub control_session_id: u64,
    pub sequence: u64,
    pub media_health: MediaHealth,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatError {
    SessionMismatch { expected: u64, received: u64 },
    NonIncreasingSequence { previous: u64, received: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerLiveness {
    WaitingForFirstHeartbeat,
    Online,
    Suspect,
    Offline,
}

#[derive(Debug, Clone)]
pub struct HeartbeatTracker {
    control_session_id: u64,
    last_sequence: Option<u64>,
    last_seen_at: Option<Duration>,
    media_health: MediaHealth,
}

impl HeartbeatTracker {
    #[must_use]
    pub const fn new(control_session_id: u64, initial_media_health: MediaHealth) -> Self {
        Self {
            control_session_id,
            last_sequence: None,
            last_seen_at: None,
            media_health: initial_media_health,
        }
    }

    pub fn observe(
        &mut self,
        now: Duration,
        sample: HeartbeatSample,
    ) -> Result<(), HeartbeatError> {
        if sample.control_session_id != self.control_session_id {
            return Err(HeartbeatError::SessionMismatch {
                expected: self.control_session_id,
                received: sample.control_session_id,
            });
        }

        if let Some(previous) = self.last_sequence {
            if sample.sequence <= previous {
                return Err(HeartbeatError::NonIncreasingSequence {
                    previous,
                    received: sample.sequence,
                });
            }
        }

        self.last_sequence = Some(sample.sequence);
        self.last_seen_at = Some(now);
        self.media_health = sample.media_health;
        Ok(())
    }

    #[must_use]
    pub fn liveness(&self, now: Duration, policy: HeartbeatPolicy) -> PeerLiveness {
        let Some(last_seen_at) = self.last_seen_at else {
            return PeerLiveness::WaitingForFirstHeartbeat;
        };

        let elapsed = now.saturating_sub(last_seen_at);
        if elapsed >= policy.offline_after {
            PeerLiveness::Offline
        } else if elapsed >= policy.suspect_after {
            PeerLiveness::Suspect
        } else {
            PeerLiveness::Online
        }
    }

    #[must_use]
    pub const fn media_health(&self) -> MediaHealth {
        self.media_health
    }

    #[must_use]
    pub const fn last_sequence(&self) -> Option<u64> {
        self.last_sequence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    fn caps(values: &[Capability]) -> BTreeSet<Capability> {
        values.iter().copied().collect()
    }

    #[test]
    fn hello_negotiates_minor_version_and_capability_intersection() {
        let local = caps(&[
            Capability::DxgiCapture,
            Capability::H264HardwareEncode,
            Capability::UdpUnicast,
        ]);
        let peer = ControlHello {
            principal_id: id(7),
            role: ControlRole::StudentDevice,
            version: ProtocolVersion { major: 1, minor: 2 },
            capabilities: caps(&[
                Capability::DxgiCapture,
                Capability::H264HardwareDecode,
                Capability::UdpUnicast,
            ]),
            hostname: "student-07".to_owned(),
            app_version: "0.0.1".to_owned(),
        };

        let negotiated = negotiate_hello(ProtocolVersion { major: 1, minor: 5 }, &local, &peer)
            .expect("same major version should negotiate");

        assert_eq!(negotiated.version, ProtocolVersion { major: 1, minor: 2 });
        assert_eq!(
            negotiated.capabilities,
            caps(&[Capability::DxgiCapture, Capability::UdpUnicast])
        );
        assert_eq!(negotiated.principal_id, id(7));
    }

    #[test]
    fn hello_rejects_protocol_major_mismatch_explicitly() {
        let peer = ControlHello {
            principal_id: id(1),
            role: ControlRole::Teacher,
            version: ProtocolVersion { major: 2, minor: 0 },
            capabilities: BTreeSet::new(),
            hostname: "teacher".to_owned(),
            app_version: "0.0.1".to_owned(),
        };

        assert_eq!(
            negotiate_hello(
                ProtocolVersion { major: 1, minor: 9 },
                &BTreeSet::new(),
                &peer
            ),
            Err(NegotiationError::IncompatibleProtocol {
                local: ProtocolVersion { major: 1, minor: 9 },
                peer: ProtocolVersion { major: 2, minor: 0 },
            })
        );
    }

    #[test]
    fn heartbeat_keeps_control_liveness_independent_from_media_health() {
        let policy = HeartbeatPolicy::default();
        let mut tracker = HeartbeatTracker::new(55, MediaHealth::Idle);

        tracker
            .observe(
                Duration::from_secs(1),
                HeartbeatSample {
                    control_session_id: 55,
                    sequence: 1,
                    media_health: MediaHealth::Recovering,
                },
            )
            .expect("heartbeat should be accepted");

        assert_eq!(
            tracker.liveness(Duration::from_secs(5), policy),
            PeerLiveness::Online
        );
        assert_eq!(tracker.media_health(), MediaHealth::Recovering);
        assert_eq!(
            tracker.liveness(Duration::from_secs(7), policy),
            PeerLiveness::Suspect
        );
        assert_eq!(
            tracker.liveness(Duration::from_secs(11), policy),
            PeerLiveness::Offline
        );
    }

    #[test]
    fn heartbeat_rejects_wrong_session_and_replayed_sequence() {
        let mut tracker = HeartbeatTracker::new(10, MediaHealth::Idle);

        assert_eq!(
            tracker.observe(
                Duration::from_secs(1),
                HeartbeatSample {
                    control_session_id: 11,
                    sequence: 1,
                    media_health: MediaHealth::Idle,
                },
            ),
            Err(HeartbeatError::SessionMismatch {
                expected: 10,
                received: 11,
            })
        );

        tracker
            .observe(
                Duration::from_secs(2),
                HeartbeatSample {
                    control_session_id: 10,
                    sequence: 7,
                    media_health: MediaHealth::Streaming,
                },
            )
            .expect("first in-session heartbeat should be accepted");

        assert_eq!(
            tracker.observe(
                Duration::from_secs(3),
                HeartbeatSample {
                    control_session_id: 10,
                    sequence: 7,
                    media_health: MediaHealth::Streaming,
                },
            ),
            Err(HeartbeatError::NonIncreasingSequence {
                previous: 7,
                received: 7,
            })
        );
    }

    #[test]
    fn heartbeat_policy_requires_ordered_timeouts() {
        assert_eq!(
            HeartbeatPolicy {
                interval: Duration::ZERO,
                suspect_after: Duration::from_secs(6),
                offline_after: Duration::from_secs(10),
            }
            .validate(),
            Err(HeartbeatPolicyError::ZeroInterval)
        );

        assert_eq!(
            HeartbeatPolicy {
                interval: Duration::from_secs(5),
                suspect_after: Duration::from_secs(4),
                offline_after: Duration::from_secs(10),
            }
            .validate(),
            Err(HeartbeatPolicyError::SuspectBeforeInterval)
        );

        assert_eq!(
            HeartbeatPolicy {
                interval: Duration::from_secs(2),
                suspect_after: Duration::from_secs(6),
                offline_after: Duration::from_secs(6),
            }
            .validate(),
            Err(HeartbeatPolicyError::OfflineNotAfterSuspect)
        );
    }
}
