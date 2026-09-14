#![forbid(unsafe_code)]

pub mod media;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_requires_same_major_version() {
        assert!(ProtocolVersion { major: 1, minor: 0 }
            .is_compatible_with(ProtocolVersion { major: 1, minor: 8 }));
        assert!(!ProtocolVersion { major: 1, minor: 0 }
            .is_compatible_with(ProtocolVersion { major: 2, minor: 0 }));
    }
}
