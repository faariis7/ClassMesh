use classmesh_protocol::clipboard::{ClipboardTextError, validate_text};
use classmesh_protocol::control_wire::{
    ClipboardReadRequest, ClipboardWrite, ControlEnvelope, InputEvent, PresentationStart,
    PresentationStop, SystemAction, control_envelope,
};
use classmesh_protocol::presentation::{
    PresentationControlError, validate_start as validate_presentation_start,
    validate_stop as validate_presentation_stop,
};
use classmesh_protocol::system_action::{
    SYSTEM_ACTION_MIN_VERSION, SystemActionControlError, system_action,
};
use classmesh_security::{AuthorizationStore, Permission};

use crate::authorization::{AuthenticatedControlGuard, CommandAuthorizationError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizedSystemAction {
    action: SystemAction,
}

impl AuthorizedSystemAction {
    #[must_use]
    pub const fn action(self) -> SystemAction {
        self.action
    }

    pub(crate) const fn from_validated(
        action: SystemAction,
    ) -> Result<Self, SystemActionControlError> {
        match action {
            SystemAction::Lock | SystemAction::Restart | SystemAction::Shutdown => {
                Ok(Self { action })
            }
            SystemAction::Unspecified => Err(SystemActionControlError::InvalidAction),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PrivilegedControlCommand {
    InputEvent(InputEvent),
    ClipboardReadRequest(ClipboardReadRequest),
    ClipboardWrite(ClipboardWrite),
    PresentationStart(PresentationStart),
    PresentationStop(PresentationStop),
    SystemAction(AuthorizedSystemAction),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedDispatchError {
    UnsupportedPayload,
    MalformedInputEvent,
    InputSequenceMismatch { envelope: u64, input: u64 },
    ClipboardReadRequestMissingId,
    InvalidClipboardText(ClipboardTextError),
    PresentationRequestMissingId,
    PresentationRequiresProtocolV3,
    InvalidPresentation(PresentationControlError),
    SystemActionRequestMissingId,
    SystemActionRequiresProtocolV5,
    InvalidSystemAction(SystemActionControlError),
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
            Ok(PrivilegedControlCommand::ClipboardReadRequest(*request))
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
        control_envelope::Payload::PresentationStart(start) => {
            if guard.protocol_version().major == 0 && guard.protocol_version().minor < 3 {
                return Err(PrivilegedDispatchError::PresentationRequiresProtocolV3);
            }
            if envelope.request_id == 0 {
                return Err(PrivilegedDispatchError::PresentationRequestMissingId);
            }
            validate_presentation_start(start)
                .map_err(PrivilegedDispatchError::InvalidPresentation)?;
            guard.authorize(
                authorization,
                envelope,
                Permission::StartPresentation,
                now_unix_ms,
            )?;
            Ok(PrivilegedControlCommand::PresentationStart(*start))
        }
        control_envelope::Payload::PresentationStop(stop) => {
            if guard.protocol_version().major == 0 && guard.protocol_version().minor < 3 {
                return Err(PrivilegedDispatchError::PresentationRequiresProtocolV3);
            }
            if envelope.request_id == 0 {
                return Err(PrivilegedDispatchError::PresentationRequestMissingId);
            }
            validate_presentation_stop(stop)
                .map_err(PrivilegedDispatchError::InvalidPresentation)?;
            guard.authorize(
                authorization,
                envelope,
                Permission::StartPresentation,
                now_unix_ms,
            )?;
            Ok(PrivilegedControlCommand::PresentationStop(*stop))
        }
        control_envelope::Payload::SystemActionRequest(request) => {
            let version = guard.protocol_version();
            if version.major != SYSTEM_ACTION_MIN_VERSION.major
                || version.minor < SYSTEM_ACTION_MIN_VERSION.minor
            {
                return Err(PrivilegedDispatchError::SystemActionRequiresProtocolV5);
            }
            if envelope.request_id == 0 {
                return Err(PrivilegedDispatchError::SystemActionRequestMissingId);
            }

            let action = system_action(request.action)
                .map_err(PrivilegedDispatchError::InvalidSystemAction)?;
            let permission = match action {
                SystemAction::Lock => Permission::LockDevice,
                SystemAction::Restart => Permission::RestartDevice,
                SystemAction::Shutdown => Permission::ShutdownDevice,
                SystemAction::Unspecified => {
                    return Err(PrivilegedDispatchError::InvalidSystemAction(
                        SystemActionControlError::InvalidAction,
                    ));
                }
            };

            guard.authorize(authorization, envelope, permission, now_unix_ms)?;
            let authorized = AuthorizedSystemAction::from_validated(action)
                .map_err(PrivilegedDispatchError::InvalidSystemAction)?;
            Ok(PrivilegedControlCommand::SystemAction(authorized))
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
        ClipboardReadRequest, ClipboardWrite, Heartbeat, PresentationKeyGrant, PresentationStart,
        PresentationStop, ProtocolVersion as WireProtocolVersion, ReleaseAllInput,
        SystemActionRequest, input_event,
    };
    use classmesh_security::{
        CredentialFingerprint, CredentialRecord, Principal, PrincipalId, PrincipalKind,
    };

    use super::*;
    use crate::peer_identity::AuthenticatedPeerIdentity;

    const VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 3 };
    const SYSTEM_VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 5 };

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

    fn presentation_start_envelope(sequence: u64, request_id: u64) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: 77,
            sequence,
            protocol_version: Some(WireProtocolVersion {
                major: u32::from(VERSION.major),
                minor: u32::from(VERSION.minor),
            }),
            request_id,
            payload: Some(control_envelope::Payload::PresentationStart(
                PresentationStart {
                    presentation_id: 55,
                    stream_id: 7,
                },
            )),
        }
    }

    fn presentation_stop_envelope(sequence: u64, request_id: u64) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: 77,
            sequence,
            protocol_version: Some(WireProtocolVersion {
                major: u32::from(VERSION.major),
                minor: u32::from(VERSION.minor),
            }),
            request_id,
            payload: Some(control_envelope::Payload::PresentationStop(
                PresentationStop {
                    presentation_id: 55,
                },
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

    fn system_action_envelope(
        sequence: u64,
        request_id: u64,
        action: i32,
        version: ProtocolVersion,
    ) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: 77,
            sequence,
            protocol_version: Some(WireProtocolVersion {
                major: u32::from(version.major),
                minor: u32::from(version.minor),
            }),
            request_id,
            payload: Some(control_envelope::Payload::SystemActionRequest(
                SystemActionRequest { action },
            )),
        }
    }

    #[test]
    fn system_actions_require_v05_request_id_and_valid_action_before_sequence_consumption() {
        let authorization = store(BTreeSet::from([Permission::LockDevice]));

        let old_version = ProtocolVersion { major: 0, minor: 4 };
        let mut old_guard = AuthenticatedControlGuard::new(identity(), 77, old_version, 1);
        let old_envelope = system_action_envelope(2, 500, SystemAction::Lock as i32, old_version);
        assert_eq!(
            dispatch_privileged_command(&mut old_guard, &authorization, &old_envelope, 150),
            Err(PrivilegedDispatchError::SystemActionRequiresProtocolV5)
        );
        assert_eq!(old_guard.last_sequence(), 1);

        let mut missing_id_guard =
            AuthenticatedControlGuard::new(identity(), 77, SYSTEM_VERSION, 1);
        let missing_id = system_action_envelope(2, 0, SystemAction::Lock as i32, SYSTEM_VERSION);
        assert_eq!(
            dispatch_privileged_command(&mut missing_id_guard, &authorization, &missing_id, 150,),
            Err(PrivilegedDispatchError::SystemActionRequestMissingId)
        );
        assert_eq!(missing_id_guard.last_sequence(), 1);

        let mut malformed_guard = AuthenticatedControlGuard::new(identity(), 77, SYSTEM_VERSION, 1);
        let malformed = system_action_envelope(2, 501, i32::MAX, SYSTEM_VERSION);
        assert_eq!(
            dispatch_privileged_command(&mut malformed_guard, &authorization, &malformed, 150,),
            Err(PrivilegedDispatchError::InvalidSystemAction(
                SystemActionControlError::InvalidAction
            ))
        );
        assert_eq!(malformed_guard.last_sequence(), 1);
    }

    #[test]
    fn system_action_permissions_are_exact_and_denials_consume_sequence() {
        for (action, permission) in [
            (SystemAction::Lock, Permission::LockDevice),
            (SystemAction::Restart, Permission::RestartDevice),
            (SystemAction::Shutdown, Permission::ShutdownDevice),
        ] {
            let envelope = system_action_envelope(2, 600, action as i32, SYSTEM_VERSION);

            let allowed = store(BTreeSet::from([permission]));
            let mut allowed_guard =
                AuthenticatedControlGuard::new(identity(), 77, SYSTEM_VERSION, 1);
            let dispatched =
                dispatch_privileged_command(&mut allowed_guard, &allowed, &envelope, 150)
                    .expect("authorized action dispatches");
            let PrivilegedControlCommand::SystemAction(authorized) = dispatched else {
                panic!("expected authorized system action");
            };
            assert_eq!(authorized.action(), action);
            assert_eq!(allowed_guard.last_sequence(), 2);

            let denied = store(BTreeSet::new());
            let mut denied_guard =
                AuthenticatedControlGuard::new(identity(), 77, SYSTEM_VERSION, 1);
            assert_eq!(
                dispatch_privileged_command(&mut denied_guard, &denied, &envelope, 150),
                Err(PrivilegedDispatchError::Authorization(
                    CommandAuthorizationError::Unauthorized { permission }
                ))
            );
            assert_eq!(
                denied_guard.last_sequence(),
                2,
                "an otherwise valid denied system action must consume its sequence"
            );
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
    fn group_media_key_grant_is_not_mapped_to_sender_permission_yet() {
        let authorization = store(BTreeSet::from([Permission::StartPresentation]));
        let version = ProtocolVersion { major: 0, minor: 4 };
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, version, 1);
        let envelope = ControlEnvelope {
            control_session_id: 77,
            sequence: 2,
            protocol_version: Some(WireProtocolVersion { major: 0, minor: 4 }),
            request_id: 700,
            payload: Some(control_envelope::Payload::PresentationKeyGrant(
                PresentationKeyGrant {
                    presentation_id: 55,
                    stream_id: 7,
                    epoch: 1,
                    key_material: vec![1; 32],
                },
            )),
        };

        assert_eq!(
            dispatch_privileged_command(&mut guard, &authorization, &envelope, 150),
            Err(PrivilegedDispatchError::UnsupportedPayload)
        );
        assert_eq!(
            guard.last_sequence(),
            1,
            "wire key delivery must remain unavailable until recipient/session semantics are integrated"
        );
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
    fn presentation_lifecycle_requires_explicit_start_permission() {
        let allowed = store(BTreeSet::from([Permission::StartPresentation]));
        let mut start_guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);
        assert!(matches!(
            dispatch_privileged_command(
                &mut start_guard,
                &allowed,
                &presentation_start_envelope(2, 501),
                150,
            ),
            Ok(PrivilegedControlCommand::PresentationStart(_))
        ));

        let mut stop_guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);
        assert!(matches!(
            dispatch_privileged_command(
                &mut stop_guard,
                &allowed,
                &presentation_stop_envelope(2, 502),
                150,
            ),
            Ok(PrivilegedControlCommand::PresentationStop(_))
        ));

        let denied = store(BTreeSet::new());
        let mut denied_guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);
        assert_eq!(
            dispatch_privileged_command(
                &mut denied_guard,
                &denied,
                &presentation_start_envelope(2, 503),
                150,
            ),
            Err(PrivilegedDispatchError::Authorization(
                CommandAuthorizationError::Unauthorized {
                    permission: Permission::StartPresentation,
                }
            ))
        );
        assert_eq!(denied_guard.last_sequence(), 2);
    }

    #[test]
    fn presentation_lifecycle_is_not_accepted_on_protocol_v02() {
        let allowed = store(BTreeSet::from([Permission::StartPresentation]));
        let version = ProtocolVersion { major: 0, minor: 2 };
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, version, 1);
        let mut envelope = presentation_start_envelope(2, 500);
        envelope.protocol_version = Some(WireProtocolVersion { major: 0, minor: 2 });

        assert_eq!(
            dispatch_privileged_command(&mut guard, &allowed, &envelope, 150),
            Err(PrivilegedDispatchError::PresentationRequiresProtocolV3)
        );
        assert_eq!(guard.last_sequence(), 1);
    }

    #[test]
    fn malformed_presentation_fails_before_sequence_consumption() {
        let allowed = store(BTreeSet::from([Permission::StartPresentation]));
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);

        let mut missing_request = presentation_start_envelope(2, 0);
        assert_eq!(
            dispatch_privileged_command(&mut guard, &allowed, &missing_request, 150),
            Err(PrivilegedDispatchError::PresentationRequestMissingId)
        );
        assert_eq!(guard.last_sequence(), 1);

        missing_request.request_id = 504;
        let Some(control_envelope::Payload::PresentationStart(start)) =
            missing_request.payload.as_mut()
        else {
            panic!("expected presentation start");
        };
        start.stream_id = 0;
        assert_eq!(
            dispatch_privileged_command(&mut guard, &allowed, &missing_request, 150),
            Err(PrivilegedDispatchError::InvalidPresentation(
                PresentationControlError::InvalidStreamId
            ))
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
