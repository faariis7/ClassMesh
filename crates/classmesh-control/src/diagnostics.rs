use crate::HeartbeatError;
use crate::authorization::CommandAuthorizationError;
use crate::dispatch::PrivilegedDispatchError;
use crate::handshake::HandshakeError;
use crate::quic::ControlTransportError;
use crate::stream::StreamOfferError;

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

#[must_use]
pub const fn heartbeat_diagnostic_code(error: &HeartbeatError) -> &'static str {
    match error {
        HeartbeatError::SessionMismatch { .. } => "control.heartbeat.wrong_session",
        HeartbeatError::NonIncreasingSequence { .. } => "control.heartbeat.replayed_sequence",
    }
}

#[must_use]
pub const fn stream_offer_diagnostic_code(error: &StreamOfferError) -> &'static str {
    match error {
        StreamOfferError::InvalidStreamId => "control.stream.invalid_stream",
        StreamOfferError::UnsupportedKind => "control.stream.unsupported_kind",
        StreamOfferError::MissingProfile => "control.stream.missing_profile",
        StreamOfferError::UnsupportedCodec => "control.stream.unsupported_codec",
        StreamOfferError::ProfileValueOutOfRange | StreamOfferError::InvalidProfile(_) => {
            "control.stream.invalid_profile"
        }
        StreamOfferError::UnsupportedTransport => "control.stream.unsupported_transport",
        StreamOfferError::TransportCapabilityNotNegotiated => {
            "control.stream.transport_not_negotiated"
        }
        StreamOfferError::TransportParametersTooLarge => {
            "control.stream.transport_parameters_too_large"
        }
    }
}

#[must_use]
pub const fn privileged_dispatch_diagnostic_code(error: &PrivilegedDispatchError) -> &'static str {
    match error {
        PrivilegedDispatchError::UnsupportedPayload => "control.command.unsupported_payload",
        PrivilegedDispatchError::MalformedInputEvent => "control.command.malformed_input",
        PrivilegedDispatchError::InputSequenceMismatch { .. } => {
            "control.command.input_sequence_mismatch"
        }
        PrivilegedDispatchError::ClipboardReadRequestMissingId => {
            "control.command.clipboard_missing_request_id"
        }
        PrivilegedDispatchError::InvalidClipboardText(_) => {
            "control.command.clipboard_text_too_large"
        }
        PrivilegedDispatchError::Authorization(error) => {
            command_authorization_diagnostic_code(error)
        }
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
    fn stream_offer_codes_are_stable_and_non_sensitive() {
        assert_eq!(
            stream_offer_diagnostic_code(&StreamOfferError::InvalidStreamId),
            "control.stream.invalid_stream"
        );
        assert_eq!(
            stream_offer_diagnostic_code(&StreamOfferError::TransportCapabilityNotNegotiated),
            "control.stream.transport_not_negotiated"
        );
        assert_eq!(
            stream_offer_diagnostic_code(&StreamOfferError::InvalidProfile(
                classmesh_core::adaptation::StreamProfileError::InvalidGeometry
            )),
            "control.stream.invalid_profile"
        );
    }

    #[test]
    fn clipboard_request_id_code_is_stable() {
        assert_eq!(
            privileged_dispatch_diagnostic_code(
                &PrivilegedDispatchError::ClipboardReadRequestMissingId
            ),
            "control.command.clipboard_missing_request_id"
        );
    }

    #[test]
    fn clipboard_bound_code_does_not_embed_payload_size() {
        let error = PrivilegedDispatchError::InvalidClipboardText(
            classmesh_protocol::clipboard::ClipboardTextError::TooLarge {
                bytes: usize::MAX,
                maximum: 64 * 1024,
            },
        );
        assert_eq!(
            privileged_dispatch_diagnostic_code(&error),
            "control.command.clipboard_text_too_large"
        );
    }

    #[test]
    fn heartbeat_codes_do_not_embed_session_or_sequence_values() {
        assert_eq!(
            heartbeat_diagnostic_code(&HeartbeatError::SessionMismatch {
                expected: 7,
                received: 999,
            }),
            "control.heartbeat.wrong_session"
        );
        assert_eq!(
            heartbeat_diagnostic_code(&HeartbeatError::NonIncreasingSequence {
                previous: 55,
                received: 55,
            }),
            "control.heartbeat.replayed_sequence"
        );
    }

    #[test]
    fn privileged_dispatch_codes_remain_value_free() {
        assert_eq!(
            privileged_dispatch_diagnostic_code(&PrivilegedDispatchError::InputSequenceMismatch {
                envelope: 7,
                input: 999,
            },),
            "control.command.input_sequence_mismatch"
        );
        assert_eq!(
            privileged_dispatch_diagnostic_code(&PrivilegedDispatchError::MalformedInputEvent),
            "control.command.malformed_input"
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
