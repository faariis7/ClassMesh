use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

use classmesh_protocol::control_wire::{
    ControlEnvelope, Hello, HelloAck, ProtocolVersion as WireProtocolVersion, control_envelope,
};
use classmesh_protocol::{Capability, ControlRole, ProtocolVersion};
use classmesh_security::PrincipalId;

use crate::quic::{ControlChannel, ControlTransportError};
use crate::{ControlHello, NegotiatedHello, NegotiationError, negotiate_hello};

const HELLO_REQUEST_ID: u64 = 1;
const FIRST_SEQUENCE: u64 = 1;
const REJECT_INCOMPATIBLE_PROTOCOL: i32 = 1;

#[derive(Debug)]
pub enum HandshakeError {
    Transport(ControlTransportError),
    MissingProtocolVersion,
    VersionOutOfRange,
    InvalidPrincipalIdLength { length: usize },
    UnsupportedRole { value: i32 },
    UnexpectedPayload,
    Rejected { reason: i32, diagnostic: String },
    InvalidSessionId,
    Negotiation(NegotiationError),
}

impl Display for HandshakeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(error) => Display::fmt(error, formatter),
            Self::MissingProtocolVersion => write!(formatter, "hello is missing protocol version"),
            Self::VersionOutOfRange => write!(formatter, "protocol version exceeds ClassMesh range"),
            Self::InvalidPrincipalIdLength { length } => {
                write!(formatter, "principal id must be 32 bytes; received {length}")
            }
            Self::UnsupportedRole { value } => write!(formatter, "unsupported control role {value}"),
            Self::UnexpectedPayload => write!(formatter, "unexpected control handshake payload"),
            Self::Rejected { reason, diagnostic } => {
                write!(formatter, "control hello rejected ({reason}): {diagnostic}")
            }
            Self::InvalidSessionId => write!(formatter, "server returned invalid control session id"),
            Self::Negotiation(error) => write!(formatter, "control negotiation failed: {error:?}"),
        }
    }
}

impl Error for HandshakeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ControlTransportError> for HandshakeError {
    fn from(error: ControlTransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<NegotiationError> for HandshakeError {
    fn from(error: NegotiationError) -> Self {
        Self::Negotiation(error)
    }
}

#[derive(Debug, Clone)]
pub struct ServerHelloConfig {
    pub local_version: ProtocolVersion,
    pub local_capabilities: BTreeSet<Capability>,
    pub control_session_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishedControlSession {
    pub control_session_id: u64,
    pub negotiated: NegotiatedHello,
}

pub async fn client_hello(
    channel: &mut ControlChannel,
    hello: &ControlHello,
) -> Result<EstablishedControlSession, HandshakeError> {
    let envelope = ControlEnvelope {
        control_session_id: 0,
        sequence: FIRST_SEQUENCE,
        protocol_version: Some(version_to_wire(hello.version)),
        request_id: HELLO_REQUEST_ID,
        payload: Some(control_envelope::Payload::Hello(hello_to_wire(hello))),
    };
    channel.send(&envelope).await?;

    let response = channel.receive().await?;
    let Some(control_envelope::Payload::HelloAck(ack)) = response.payload else {
        return Err(HandshakeError::UnexpectedPayload);
    };
    established_from_ack(hello, ack)
}

pub async fn server_hello(
    channel: &mut ControlChannel,
    config: &ServerHelloConfig,
) -> Result<EstablishedControlSession, HandshakeError> {
    if config.control_session_id == 0 {
        return Err(HandshakeError::InvalidSessionId);
    }

    let request = channel.receive().await?;
    let Some(control_envelope::Payload::Hello(hello_wire)) = request.payload else {
        return Err(HandshakeError::UnexpectedPayload);
    };
    let hello = hello_from_wire(hello_wire)?;

    let negotiated = match negotiate_hello(
        config.local_version,
        &config.local_capabilities,
        &hello,
    ) {
        Ok(negotiated) => negotiated,
        Err(error) => {
            let ack = ControlEnvelope {
                control_session_id: 0,
                sequence: FIRST_SEQUENCE,
                protocol_version: Some(version_to_wire(config.local_version)),
                request_id: request.request_id,
                payload: Some(control_envelope::Payload::HelloAck(HelloAck {
                    accepted: false,
                    negotiated_version: None,
                    control_session_id: 0,
                    negotiated_capabilities: Vec::new(),
                    reject_reason: REJECT_INCOMPATIBLE_PROTOCOL,
                    diagnostic: "protocol major versions are incompatible".to_owned(),
                })),
            };
            channel.send(&ack).await?;
            return Err(error.into());
        }
    };

    let ack = ControlEnvelope {
        control_session_id: config.control_session_id,
        sequence: FIRST_SEQUENCE,
        protocol_version: Some(version_to_wire(negotiated.version)),
        request_id: request.request_id,
        payload: Some(control_envelope::Payload::HelloAck(HelloAck {
            accepted: true,
            negotiated_version: Some(version_to_wire(negotiated.version)),
            control_session_id: config.control_session_id,
            negotiated_capabilities: negotiated
                .capabilities
                .iter()
                .copied()
                .map(capability_to_wire)
                .collect(),
            reject_reason: 0,
            diagnostic: String::new(),
        })),
    };
    channel.send(&ack).await?;

    Ok(EstablishedControlSession {
        control_session_id: config.control_session_id,
        negotiated,
    })
}

fn established_from_ack(
    hello: &ControlHello,
    ack: HelloAck,
) -> Result<EstablishedControlSession, HandshakeError> {
    if !ack.accepted {
        return Err(HandshakeError::Rejected {
            reason: ack.reject_reason,
            diagnostic: ack.diagnostic,
        });
    }
    if ack.control_session_id == 0 {
        return Err(HandshakeError::InvalidSessionId);
    }

    let version = version_from_wire(
        ack.negotiated_version
            .ok_or(HandshakeError::MissingProtocolVersion)?,
    )?;
    if !hello.version.is_compatible_with(version) || version.minor > hello.version.minor {
        return Err(HandshakeError::Negotiation(
            NegotiationError::IncompatibleProtocol {
                local: hello.version,
                peer: version,
            },
        ));
    }

    let capabilities = ack
        .negotiated_capabilities
        .into_iter()
        .filter_map(capability_from_wire)
        .filter(|capability| hello.capabilities.contains(capability))
        .collect();

    Ok(EstablishedControlSession {
        control_session_id: ack.control_session_id,
        negotiated: NegotiatedHello {
            principal_id: hello.principal_id,
            role: hello.role,
            version,
            capabilities,
        },
    })
}

fn hello_to_wire(hello: &ControlHello) -> Hello {
    Hello {
        version: Some(version_to_wire(hello.version)),
        device_id: hello.principal_id.0.to_vec(),
        hostname: hello.hostname.clone(),
        capabilities: hello
            .capabilities
            .iter()
            .copied()
            .map(capability_to_wire)
            .collect(),
        app_version: hello.app_version.clone(),
        role: role_to_wire(hello.role),
        credential_fingerprint_sha256: Vec::new(),
    }
}

fn hello_from_wire(hello: Hello) -> Result<ControlHello, HandshakeError> {
    let version = version_from_wire(
        hello
            .version
            .ok_or(HandshakeError::MissingProtocolVersion)?,
    )?;
    let principal_id = principal_id_from_bytes(&hello.device_id)?;
    let role = role_from_wire(hello.role)?;

    Ok(ControlHello {
        principal_id,
        role,
        version,
        capabilities: hello
            .capabilities
            .into_iter()
            .filter_map(capability_from_wire)
            .collect(),
        hostname: hello.hostname,
        app_version: hello.app_version,
    })
}

fn principal_id_from_bytes(bytes: &[u8]) -> Result<PrincipalId, HandshakeError> {
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| HandshakeError::InvalidPrincipalIdLength {
            length: bytes.len(),
        })?;
    Ok(PrincipalId(value))
}

fn version_to_wire(version: ProtocolVersion) -> WireProtocolVersion {
    WireProtocolVersion {
        major: u32::from(version.major),
        minor: u32::from(version.minor),
    }
}

fn version_from_wire(version: WireProtocolVersion) -> Result<ProtocolVersion, HandshakeError> {
    Ok(ProtocolVersion {
        major: u16::try_from(version.major).map_err(|_| HandshakeError::VersionOutOfRange)?,
        minor: u16::try_from(version.minor).map_err(|_| HandshakeError::VersionOutOfRange)?,
    })
}

fn role_to_wire(role: ControlRole) -> i32 {
    match role {
        ControlRole::Teacher => 1,
        ControlRole::StudentDevice => 2,
        ControlRole::Administrator => 3,
    }
}

fn role_from_wire(value: i32) -> Result<ControlRole, HandshakeError> {
    match value {
        1 => Ok(ControlRole::Teacher),
        2 => Ok(ControlRole::StudentDevice),
        3 => Ok(ControlRole::Administrator),
        _ => Err(HandshakeError::UnsupportedRole { value }),
    }
}

fn capability_to_wire(capability: Capability) -> i32 {
    match capability {
        Capability::ServiceSessionWorker => 1,
        Capability::DxgiCapture => 2,
        Capability::WindowsGraphicsCapture => 3,
        Capability::H264HardwareEncode => 4,
        Capability::H264HardwareDecode => 5,
        Capability::UdpMulticast => 6,
        Capability::UdpUnicast => 7,
        Capability::QuicDatagram => 8,
        Capability::WebRtc => 9,
        Capability::LocalSfu => 10,
    }
}

fn capability_from_wire(value: i32) -> Option<Capability> {
    match value {
        1 => Some(Capability::ServiceSessionWorker),
        2 => Some(Capability::DxgiCapture),
        3 => Some(Capability::WindowsGraphicsCapture),
        4 => Some(Capability::H264HardwareEncode),
        5 => Some(Capability::H264HardwareDecode),
        6 => Some(Capability::UdpMulticast),
        7 => Some(Capability::UdpUnicast),
        8 => Some(Capability::QuicDatagram),
        9 => Some(Capability::WebRtc),
        10 => Some(Capability::LocalSfu),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    fn capabilities(values: &[Capability]) -> BTreeSet<Capability> {
        values.iter().copied().collect()
    }

    #[test]
    fn hello_wire_conversion_validates_identity_and_role() {
        let hello = ControlHello {
            principal_id: id(5),
            role: ControlRole::StudentDevice,
            version: ProtocolVersion { major: 0, minor: 1 },
            capabilities: capabilities(&[
                Capability::H264HardwareDecode,
                Capability::UdpUnicast,
            ]),
            hostname: "student-05".to_owned(),
            app_version: "0.0.1".to_owned(),
        };

        let decoded = hello_from_wire(hello_to_wire(&hello)).expect("hello should round trip");
        assert_eq!(decoded, hello);

        let mut invalid = hello_to_wire(&hello);
        invalid.device_id.pop();
        assert!(matches!(
            hello_from_wire(invalid),
            Err(HandshakeError::InvalidPrincipalIdLength { .. })
        ));
    }

    #[test]
    fn accepted_ack_cannot_enable_unoffered_capability() {
        let hello = ControlHello {
            principal_id: id(9),
            role: ControlRole::Teacher,
            version: ProtocolVersion { major: 1, minor: 4 },
            capabilities: capabilities(&[Capability::UdpUnicast]),
            hostname: "teacher".to_owned(),
            app_version: "0.0.1".to_owned(),
        };

        let session = established_from_ack(
            &hello,
            HelloAck {
                accepted: true,
                negotiated_version: Some(WireProtocolVersion { major: 1, minor: 2 }),
                control_session_id: 88,
                negotiated_capabilities: vec![
                    capability_to_wire(Capability::UdpUnicast),
                    capability_to_wire(Capability::QuicDatagram),
                ],
                reject_reason: 0,
                diagnostic: String::new(),
            },
        )
        .expect("ack should be accepted");

        assert_eq!(session.control_session_id, 88);
        assert_eq!(
            session.negotiated.capabilities,
            capabilities(&[Capability::UdpUnicast])
        );
    }

    #[test]
    fn rejected_ack_is_explicit() {
        let hello = ControlHello {
            principal_id: id(1),
            role: ControlRole::Teacher,
            version: ProtocolVersion { major: 1, minor: 0 },
            capabilities: BTreeSet::new(),
            hostname: "teacher".to_owned(),
            app_version: "0.0.1".to_owned(),
        };

        assert!(matches!(
            established_from_ack(
                &hello,
                HelloAck {
                    accepted: false,
                    negotiated_version: None,
                    control_session_id: 0,
                    negotiated_capabilities: Vec::new(),
                    reject_reason: REJECT_INCOMPATIBLE_PROTOCOL,
                    diagnostic: "no".to_owned(),
                }
            ),
            Err(HandshakeError::Rejected { .. })
        ));
    }
}
