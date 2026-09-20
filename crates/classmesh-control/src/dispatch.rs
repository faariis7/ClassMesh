use classmesh_protocol::clipboard::{ClipboardTextError, validate_text};
use classmesh_protocol::control_wire::{
    ClipboardReadRequest, ClipboardWrite, ControlEnvelope, InputEvent, control_envelope,
};
use classmesh_security::{AuthorizationStore, Permission};

use crate::authorization::{AuthenticatedControlGuard, CommandAuthorizationError};

#[derive(Debug, Clone, PartialEq)]
pub enum PrivilegedControlCommand {
    InputEvent(InputEvent),
    ClipboardReadRequest(ClipboardReadRequest),
    ClipboardWrite(ClipboardWrite),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedDispatchError {
    UnsupportedPayload,
    MalformedInputEvent,
    InputSequenceMismatch { envelope: u64, input: u64 },
    ClipboardReadRequestMissingId,
    InvalidClipboardText(ClipboardTextError),
    Authorization(CommandAuthorizationError),
}

impl From<CommandAuthorizationError> for PrivilegedDispatchError {
    fn from(value: CommandAuthorizationError) -> Self {
        Self::Authorization(value)
    }
}

/// Classifies and authorizes privileged post-handshake commands.
///
/// Only wire payloads with a defined production permission mapping belong here.
/// New privileged payloads must be added explicitly instead of inheriting a
/// permission implicitly from connection-level authentication.
pub fn dispatch_privileged_command(
    guard: &mut AuthenticatedControlGuard,
    authorization: &AuthorizationStore,
    envelope: &ControlEnvelope,
    now_unix_ms: u64,
) -> Result<PrivilegedControlCommand, PrivilegedDispatchError> {
    let Some(payload) = envelope.payload.as_ref() else {
        return Err(CommandAuthorizationError::MissingPayload.into());
    };

    match payload {
        control_envelope::Payload::InputEvent(input) => {
            if input.event.is_none() {
                return Err(PrivilegedDispatchError::MalformedInputEvent);
            }
            if input.sequence != envelope.sequence {
                return Err(PrivilegedDispatchError::InputSequenceMismatch {
                    envelope: envelope.sequence,
                    input: input.sequence,
                });
            }

            guard.authorize(
                authorization,
                envelope,
                Permission::ControlInput,
                now_unix_ms,
            )?;
            Ok(PrivilegedControlCommand::InputEvent(*input))
        }
        control_envelope::Payload::ClipboardReadRequest(request) => {
            if envelope.request_id == 0 {
                return Err(PrivilegedDispatchError::ClipboardReadRequestMissingId);
            }
            guard.authorize(
                authorization,
                envelope,
                Permission::ReadClipboard,
                now_unix_ms,
            )?;
            Ok(PrivilegedControlCommand::ClipboardReadRequest(
                request.clone(),
            ))
        }
        control_envelope::Payload::ClipboardWrite(write) => {
            validate_text(&write.text_utf8)
                .map_err(PrivilegedDispatchError::InvalidClipboardText)?;
            guard.authorize(
                authorization,
                envelope,
                Permission::WriteClipboard,
                now_unix_ms,
            )?;
            Ok(PrivilegedControlCommand::ClipboardWrite(write.clone()))
        }
        _ => Err(PrivilegedDispatchError::UnsupportedPayload),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use classmesh_protocol::ProtocolVersion;
    use classmesh_protocol::clipboard::MAX_CLIPBOARD_TEXT_BYTES;
    use classmesh_protocol::control_wire::{
        ClipboardReadRequest, ClipboardWrite, Heartbeat, ProtocolVersion as WireProtocolVersion,
        ReleaseAllInput, input_event,
    };
    use classmesh_security::{
        CredentialFingerprint, CredentialRecord, Principal, PrincipalId, PrincipalKind,
    };

    use super::*;
    use crate::peer_identity::AuthenticatedPeerIdentity;

    const VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 2 };

    fn identity() -> AuthenticatedPeerIdentity {
        AuthenticatedPeerIdentity {
            principal_id: PrincipalId([7; 32]),
            credential_fingerprint: CredentialFingerprint([9; 32]),
        }
    }

    fn store(permissions: BTreeSet<Permission>) -> AuthorizationStore {
        let peer = identity();
        let mut credentials = BTreeMap::new();
        credentials.insert(
            peer.credential_fingerprint,
            CredentialRecord::active(peer.credential_fingerprint, 100),
        );
        let mut store = AuthorizationStore::default();
        store
            .upsert(Principal {
                id: peer.principal_id,
                kind: PrincipalKind::Teacher,
                enabled: true,
                permissions,
                credentials,
            })
            .expect("principal should register");
        store
    }

    fn input_envelope(sequence: u64) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: 77,
            sequence,
            protocol_version: Some(WireProtocolVersion {
                major: u32::from(VERSION.major),
                minor: u32::from(VERSION.minor),
            }),
            request_id: 0,
            payload: Some(control_envelope::Payload::InputEvent(InputEvent {
                sequence,
                timestamp_us: 123,
                event: Some(input_event::Event::ReleaseAll(ReleaseAllInput {})),
            })),
        }
    }

    fn clipboard_read_envelope(sequence: u64) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: 77,
            sequence,
            protocol_version: Some(WireProtocolVersion {
                major: u32::from(VERSION.major),
                minor: u32::from(VERSION.minor),
            }),
            request_id: 91,
            payload: Some(control_envelope::Payload::ClipboardReadRequest(
                ClipboardReadRequest {},
            )),
        }
    }

    fn clipboard_write_envelope(sequence: u64, text_utf8: String) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: 77,
            sequence,
            protocol_version: Some(WireProtocolVersion {
                major: u32::from(VERSION.major),
                minor: u32::from(VERSION.minor),
            }),
            request_id: 0,
            payload: Some(control_envelope::Payload::ClipboardWrite(ClipboardWrite {
                text_utf8,
            })),
        }
    }

    #[test]
    fn authorized_input_dispatches_and_consumes_sequence() {
        let authorization = store(BTreeSet::from([Permission::ControlInput]));
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);

        let command =
            dispatch_privileged_command(&mut guard, &authorization, &input_envelope(2), 150)
                .expect("authorized input should dispatch");

        assert!(matches!(command, PrivilegedControlCommand::InputEvent(_)));
        assert_eq!(guard.last_sequence(), 2);
    }

    #[test]
    fn malformed_input_is_rejected_before_sequence_consumption() {
        let authorization = store(BTreeSet::from([Permission::ControlInput]));
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);

        let mut missing_event = input_envelope(2);
        let Some(control_envelope::Payload::InputEvent(input)) = missing_event.payload.as_mut()
        else {
            panic!("expected input event");
        };
        input.event = None;
        assert_eq!(
            dispatch_privileged_command(&mut guard, &authorization, &missing_event, 150),
            Err(PrivilegedDispatchError::MalformedInputEvent)
        );
        assert_eq!(guard.last_sequence(), 1);

        let mut mismatched = input_envelope(2);
        let Some(control_envelope::Payload::InputEvent(input)) = mismatched.payload.as_mut() else {
            panic!("expected input event");
        };
        input.sequence = 99;
        assert_eq!(
            dispatch_privileged_command(&mut guard, &authorization, &mismatched, 150),
            Err(PrivilegedDispatchError::InputSequenceMismatch {
                envelope: 2,
                input: 99,
            })
        );
        assert_eq!(guard.last_sequence(), 1);
    }

    #[test]
    fn unsupported_payload_does_not_consume_privileged_sequence() {
        let authorization = store(BTreeSet::from([Permission::ControlInput]));
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);
        let mut envelope = input_envelope(2);
        envelope.payload = Some(control_envelope::Payload::Heartbeat(Heartbeat {
            monotonic_time_us: 100,
            control_session_id: 77,
            media: 1,
        }));

        assert_eq!(
            dispatch_privileged_command(&mut guard, &authorization, &envelope, 150),
            Err(PrivilegedDispatchError::UnsupportedPayload)
        );
        assert_eq!(guard.last_sequence(), 1);
    }

    #[test]
    fn clipboard_read_requires_request_id_before_sequence_consumption() {
        let authorization = store(BTreeSet::from([Permission::ReadClipboard]));
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);
        let mut envelope = clipboard_read_envelope(2);
        envelope.request_id = 0;

        assert_eq!(
            dispatch_privileged_command(&mut guard, &authorization, &envelope, 150),
            Err(PrivilegedDispatchError::ClipboardReadRequestMissingId)
        );
        assert_eq!(guard.last_sequence(), 1);
    }

    #[test]
    fn clipboard_permissions_are_explicit_and_separate() {
        let input_only = store(BTreeSet::from([Permission::ControlInput]));
        let mut input_guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);
        assert_eq!(
            dispatch_privileged_command(
                &mut input_guard,
                &input_only,
                &clipboard_read_envelope(2),
                150,
            ),
            Err(PrivilegedDispatchError::Authorization(
                CommandAuthorizationError::Unauthorized {
                    permission: Permission::ReadClipboard,
                }
            ))
        );

        let read_only = store(BTreeSet::from([Permission::ReadClipboard]));
        let mut read_guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);
        assert!(matches!(
            dispatch_privileged_command(
                &mut read_guard,
                &read_only,
                &clipboard_read_envelope(2),
                150,
            ),
            Ok(PrivilegedControlCommand::ClipboardReadRequest(_))
        ));

        let mut write_guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);
        assert_eq!(
            dispatch_privileged_command(
                &mut write_guard,
                &read_only,
                &clipboard_write_envelope(2, "hello".to_owned()),
                150,
            ),
            Err(PrivilegedDispatchError::Authorization(
                CommandAuthorizationError::Unauthorized {
                    permission: Permission::WriteClipboard,
                }
            ))
        );
    }

    #[test]
    fn oversized_clipboard_write_is_rejected_before_sequence_consumption() {
        let authorization = store(BTreeSet::from([Permission::WriteClipboard]));
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);
        let envelope = clipboard_write_envelope(2, "a".repeat(MAX_CLIPBOARD_TEXT_BYTES + 1));

        assert!(matches!(
            dispatch_privileged_command(&mut guard, &authorization, &envelope, 150),
            Err(PrivilegedDispatchError::InvalidClipboardText(
                ClipboardTextError::TooLarge { .. }
            ))
        ));
        assert_eq!(guard.last_sequence(), 1);
    }

    #[test]
    fn authorized_clipboard_write_dispatches_and_consumes_sequence() {
        let authorization = store(BTreeSet::from([Permission::WriteClipboard]));
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);
        let envelope = clipboard_write_envelope(2, "bounded clipboard".to_owned());

        assert!(matches!(
            dispatch_privileged_command(&mut guard, &authorization, &envelope, 150),
            Ok(PrivilegedControlCommand::ClipboardWrite(_))
        ));
        assert_eq!(guard.last_sequence(), 2);
    }

    #[test]
    fn denied_input_sequence_is_consumed_by_authorization_guard() {
        let authorization = store(BTreeSet::new());
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);

        assert_eq!(
            dispatch_privileged_command(&mut guard, &authorization, &input_envelope(2), 150),
            Err(PrivilegedDispatchError::Authorization(
                CommandAuthorizationError::Unauthorized {
                    permission: Permission::ControlInput,
                }
            ))
        );
        assert_eq!(guard.last_sequence(), 2);
    }
}
