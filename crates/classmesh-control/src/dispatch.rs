use classmesh_protocol::control_wire::{ControlEnvelope, InputEvent, control_envelope};
use classmesh_security::{AuthorizationStore, Permission};

use crate::authorization::{AuthenticatedControlGuard, CommandAuthorizationError};

#[derive(Debug, Clone, PartialEq)]
pub enum PrivilegedControlCommand {
    InputEvent(InputEvent),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedDispatchError {
    UnsupportedPayload,
    MalformedInputEvent,
    InputSequenceMismatch {
        envelope: u64,
        input: u64,
    },
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
            Ok(PrivilegedControlCommand::InputEvent(input.clone()))
        }
        _ => Err(PrivilegedDispatchError::UnsupportedPayload),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use classmesh_protocol::ProtocolVersion;
    use classmesh_protocol::control_wire::{
        Heartbeat, ProtocolVersion as WireProtocolVersion, ReleaseAllInput, input_event,
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
