use crate::authorization::CommandAuthorizationError;
use crate::handshake::HandshakeError;
use crate::quic::ControlTransportError;

/// Stable, non-sensitive diagnostic code for logs/telemetry.
///
/// These codes deliberately omit peer-provided values, session identifiers,
/// request identifiers and free-form diagnostics. Detailed error values may
/// still be retained in local debug contexts with an explicit policy.
#[must_use]
pub const fn transport_diagnostic_code(error: &ControlTransportError) -> &'static str {
    match error {
        ControlTransportError::Frame(_) => "control.transport.frame",
        ControlTransportError::Timeout { .. } => "control.transport.timeout",
        ControlTransportError::Configuration(_) => "control.transport.configuration",
        ControlTransportError::Transport(_) => "control.transport.failure",
        ControlTransportError::EndpointClosed => "control.transport.endpoint_closed",
    }
}

#[must_use]
pub const fn handshake_diagnostic_code(error: &HandshakeError) -> &'static str {
    match error {
        HandshakeError::Transport(error) => transport_diagnostic_code(error),
        HandshakeError::MissingProtocolVersion => "control.handshake.missing_version",
        HandshakeError::VersionOutOfRange => "control.handshake.version_out_of_range",
        HandshakeError::InvalidPrincipalIdLength { .. } => "control.handshake.invalid_principal_id",
        HandshakeError::UnsupportedRole { .. } => "control.handshake.unsupported_role",
        HandshakeError::UnexpectedPayload => "control.handshake.unexpected_payload",
        HandshakeError::InvalidHelloEnvelope { .. } => "control.handshake.invalid_hello_envelope",
        HandshakeError::HelloVersionMismatch { .. } => "control.handshake.hello_version_mismatch",
        HandshakeError::Rejected { .. } => "control.handshake.rejected",
        HandshakeError::InvalidSessionId => "control.handshake.invalid_session",
        HandshakeError::InvalidHelloAckEnvelope { .. } => {
            "control.handshake.invalid_hello_ack_envelope"
        }
        HandshakeError::HelloAckVersionMismatch => "control.handshake.hello_ack_version_mismatch",
        HandshakeError::IdentityMismatch { .. } => "control.handshake.identity_mismatch",
        HandshakeError::PeerIdentity(_) => "control.handshake.peer_identity",
        HandshakeError::Negotiation(_) => "control.handshake.negotiation",
    }
}

#[must_use]
pub const fn command_authorization_diagnostic_code(
    error: &CommandAuthorizationError,
) -> &'static str {
    match error {
        CommandAuthorizationError::MissingPayload => "control.command.missing_payload",
        CommandAuthorizationError::HandshakePayloadAfterEstablishment => {
            "control.command.handshake_payload_after_establishment"
        }
        CommandAuthorizationError::MissingProtocolVersion => "control.command.missing_version",
        CommandAuthorizationError::ProtocolVersionOutOfRange => {
            "control.command.version_out_of_range"
        }
        CommandAuthorizationError::WrongProtocolVersion { .. } => "control.command.wrong_version",
        CommandAuthorizationError::WrongSession { .. } => "control.command.wrong_session",
        CommandAuthorizationError::NonIncreasingSequence { .. } => {
            "control.command.replayed_sequence"
        }
        CommandAuthorizationError::Unauthorized { .. } => "control.command.unauthorized",
    }
}

#[cfg(test)]
mod tests {
    use classmesh_protocol::ProtocolVersion;
    use classmesh_security::Permission;

    use super::*;

    #[test]
    fn command_codes_do_not_embed_peer_values() {
        let wrong_session = CommandAuthorizationError::WrongSession {
            expected: 123,
            received: 999,
        };
        assert_eq!(
            command_authorization_diagnostic_code(&wrong_session),
            "control.command.wrong_session"
        );

        let wrong_version = CommandAuthorizationError::WrongProtocolVersion {
            expected: ProtocolVersion { major: 0, minor: 2 },
            received: ProtocolVersion {
                major: 65_535,
                minor: 65_535,
            },
        };
        assert_eq!(
            command_authorization_diagnostic_code(&wrong_version),
            "control.command.wrong_version"
        );

        let unauthorized = CommandAuthorizationError::Unauthorized {
            permission: Permission::ShutdownDevice,
        };
        assert_eq!(
            command_authorization_diagnostic_code(&unauthorized),
            "control.command.unauthorized"
        );
    }

    #[test]
    fn transport_timeout_collapses_operation_detail_to_stable_code() {
        let error = HandshakeError::Transport(ControlTransportError::Timeout {
            operation: "peer supplied context should not become a metric label",
        });
        assert_eq!(
            handshake_diagnostic_code(&error),
            "control.transport.timeout"
        );
    }
}
