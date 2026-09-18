#![forbid(unsafe_code)]

pub mod feedback;
pub mod media;

/// Generated Protocol Buffers types for the reliable control plane.
pub mod control_wire {
    include!(concat!(env!("OUT_DIR"), "/classmesh.control.v1.rs"));
}

pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 1 };

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    #[must_use]
    pub const fn is_compatible_with(self, other: Self) -> bool {
        self.major == other.major
    }

    /// Negotiates the newest mutually compatible protocol version.
    ///
    /// Minor versions are additive within a major version. A major-version
    /// mismatch is explicit incompatibility rather than an implicit fallback.
    #[must_use]
    pub const fn negotiate(self, other: Self) -> Option<Self> {
        if self.major != other.major {
            return None;
        }

        Some(Self {
            major: self.major,
            minor: if self.minor < other.minor {
                self.minor
            } else {
                other.minor
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    ServiceSessionWorker,
    DxgiCapture,
    WindowsGraphicsCapture,
    H264HardwareEncode,
    H264HardwareDecode,
    UdpMulticast,
    UdpUnicast,
    QuicDatagram,
    WebRtc,
    LocalSfu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRole {
    Teacher,
    StudentDevice,
    Administrator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaHealth {
    Idle,
    Starting,
    Streaming,
    Degraded,
    Recovering,
    Suspended,
    Failed,
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;

    #[test]
    fn compatibility_requires_same_major_version() {
        assert!(
            ProtocolVersion { major: 1, minor: 0 }
                .is_compatible_with(ProtocolVersion { major: 1, minor: 8 })
        );
        assert!(
            !ProtocolVersion { major: 1, minor: 0 }
                .is_compatible_with(ProtocolVersion { major: 2, minor: 0 })
        );
    }

    #[test]
    fn negotiation_selects_lower_minor_within_same_major() {
        assert_eq!(
            ProtocolVersion { major: 2, minor: 7 }
                .negotiate(ProtocolVersion { major: 2, minor: 3 }),
            Some(ProtocolVersion { major: 2, minor: 3 })
        );
        assert_eq!(
            ProtocolVersion { major: 2, minor: 7 }
                .negotiate(ProtocolVersion { major: 3, minor: 0 }),
            None
        );
    }

    #[test]
    fn generated_control_envelope_round_trips() {
        let envelope = control_wire::ControlEnvelope {
            control_session_id: 44,
            sequence: 7,
            protocol_version: Some(control_wire::ProtocolVersion { major: 0, minor: 1 }),
            request_id: 0,
            payload: Some(control_wire::control_envelope::Payload::Heartbeat(
                control_wire::Heartbeat {
                    monotonic_time_us: 123_000,
                    control_session_id: 44,
                    media: control_wire::MediaHealth::Streaming as i32,
                },
            )),
        };

        let encoded = envelope.encode_to_vec();
        let decoded = control_wire::ControlEnvelope::decode(encoded.as_slice())
            .expect("generated control envelope should decode");

        assert_eq!(decoded.control_session_id, 44);
        assert_eq!(decoded.sequence, 7);
        assert!(matches!(
            decoded.payload,
            Some(control_wire::control_envelope::Payload::Heartbeat(_))
        ));
    }
}
