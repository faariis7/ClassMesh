use classmesh_protocol::ProtocolVersion;
use classmesh_protocol::control_wire::{ControlEnvelope, control_envelope};
use classmesh_security::{AuthorizationStore, Permission};

use crate::peer_identity::AuthenticatedPeerIdentity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandAuthorizationError {
    MissingPayload,
    HandshakePayloadAfterEstablishment,
    MissingProtocolVersion,
    ProtocolVersionOutOfRange,
    WrongProtocolVersion {
        expected: ProtocolVersion,
        received: ProtocolVersion,
    },
    WrongSession {
        expected: u64,
        received: u64,
    },
    NonIncreasingSequence {
        previous: u64,
        received: u64,
    },
    Unauthorized {
        permission: Permission,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedControlGuard {
    peer: AuthenticatedPeerIdentity,
    control_session_id: u64,
    protocol_version: ProtocolVersion,
    last_sequence: u64,
}

impl AuthenticatedControlGuard {
    #[must_use]
    pub const fn new(
        peer: AuthenticatedPeerIdentity,
        control_session_id: u64,
        protocol_version: ProtocolVersion,
        last_sequence: u64,
    ) -> Self {
        Self {
            peer,
            control_session_id,
            protocol_version,
            last_sequence,
        }
    }

    #[must_use]
    pub const fn peer(self) -> AuthenticatedPeerIdentity {
        self.peer
    }

    #[must_use]
    pub const fn last_sequence(self) -> u64 {
        self.last_sequence
    }

    #[must_use]
    pub const fn protocol_version(self) -> ProtocolVersion {
        self.protocol_version
    }


    /// Validates and consumes one post-handshake envelope for this authenticated session.
    ///
    /// Sequence monotonicity is global to the peer's control stream, not per payload type.
    /// Structurally malformed envelopes fail before consuming the sequence.
    pub fn validate_envelope(
        &mut self,
        envelope: &ControlEnvelope,
    ) -> Result<(), CommandAuthorizationError> {
        let payload = envelope
            .payload
            .as_ref()
            .ok_or(CommandAuthorizationError::MissingPayload)?;
        if matches!(
            payload,
            control_envelope::Payload::Hello(_) | control_envelope::Payload::HelloAck(_)
        ) {
            return Err(CommandAuthorizationError::HandshakePayloadAfterEstablishment);
        }

        let wire_version = envelope
            .protocol_version
            .as_ref()
            .ok_or(CommandAuthorizationError::MissingProtocolVersion)?;
        let major = u16::try_from(wire_version.major)
            .map_err(|_| CommandAuthorizationError::ProtocolVersionOutOfRange)?;
        let minor = u16::try_from(wire_version.minor)
            .map_err(|_| CommandAuthorizationError::ProtocolVersionOutOfRange)?;
        let received_version = ProtocolVersion { major, minor };
        if received_version != self.protocol_version {
            return Err(CommandAuthorizationError::WrongProtocolVersion {
                expected: self.protocol_version,
                received: received_version,
            });
        }

        if envelope.control_session_id != self.control_session_id {
            return Err(CommandAuthorizationError::WrongSession {
                expected: self.control_session_id,
                received: envelope.control_session_id,
            });
        }
        if envelope.sequence == 0 || envelope.sequence <= self.last_sequence {
            return Err(CommandAuthorizationError::NonIncreasingSequence {
                previous: self.last_sequence,
                received: envelope.sequence,
            });
        }

        self.last_sequence = envelope.sequence;
        Ok(())
    }

    /// Validates the authenticated session envelope and current permission.
    ///
    /// A structurally valid in-session sequence is consumed even when authorization
    /// fails. This prevents a previously denied command from being replayed later if
    /// the principal is granted the permission after the original denial.
    pub fn authorize(
        &mut self,
        authorization: &AuthorizationStore,
        envelope: &ControlEnvelope,
        permission: Permission,
        now_unix_ms: u64,
    ) -> Result<(), CommandAuthorizationError> {
        self.validate_envelope(envelope)?;

        if !self.peer.authorize(authorization, permission, now_unix_ms) {
            return Err(CommandAuthorizationError::Unauthorized { permission });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use classmesh_security::{
        CredentialFingerprint, CredentialRecord, Principal, PrincipalId, PrincipalKind,
    };

    use super::*;

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

    const VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 2 };

    fn envelope(session: u64, sequence: u64) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: session,
            sequence,
            protocol_version: Some(classmesh_protocol::control_wire::ProtocolVersion {
                major: u32::from(VERSION.major),
                minor: u32::from(VERSION.minor),
            }),
            request_id: 0,
            payload: Some(control_envelope::Payload::InputEvent(
                classmesh_protocol::control_wire::InputEvent {
                    sequence,
                    timestamp_us: 0,
                    event: Some(
                        classmesh_protocol::control_wire::input_event::Event::ReleaseAll(
                            classmesh_protocol::control_wire::ReleaseAllInput {},
                        ),
                    ),
                },
            )),
        }
    }

    #[test]
    fn malformed_established_payload_does_not_consume_sequence() {
        let authorization = store(BTreeSet::from([Permission::ControlInput]));
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);

        let mut missing = envelope(77, 2);
        missing.payload = None;
        assert_eq!(
            guard.authorize(&authorization, &missing, Permission::ControlInput, 150),
            Err(CommandAuthorizationError::MissingPayload)
        );
        assert_eq!(guard.last_sequence(), 1);

        let hello = classmesh_protocol::control_wire::Hello {
            version: Some(classmesh_protocol::control_wire::ProtocolVersion {
                major: u32::from(VERSION.major),
                minor: u32::from(VERSION.minor),
            }),
            device_id: vec![7; 32],
            hostname: "student".to_owned(),
            capabilities: Vec::new(),
            app_version: "0.0.1".to_owned(),
            role: 2,
            credential_fingerprint_sha256: Vec::new(),
        };
        let mut handshake = envelope(77, 2);
        handshake.payload = Some(control_envelope::Payload::Hello(hello));
        assert_eq!(
            guard.authorize(&authorization, &handshake, Permission::ControlInput, 150,),
            Err(CommandAuthorizationError::HandshakePayloadAfterEstablishment)
        );
        assert_eq!(guard.last_sequence(), 1);
    }

    #[test]
    fn guard_requires_negotiated_protocol_version_without_consuming_sequence() {
        let authorization = store(BTreeSet::from([Permission::ControlInput]));
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);

        let mut missing = envelope(77, 2);
        missing.protocol_version = None;
        assert_eq!(
            guard.authorize(&authorization, &missing, Permission::ControlInput, 150),
            Err(CommandAuthorizationError::MissingProtocolVersion)
        );
        assert_eq!(guard.last_sequence(), 1);

        let mut wrong = envelope(77, 2);
        wrong.protocol_version =
            Some(classmesh_protocol::control_wire::ProtocolVersion { major: 0, minor: 1 });
        assert_eq!(
            guard.authorize(&authorization, &wrong, Permission::ControlInput, 150),
            Err(CommandAuthorizationError::WrongProtocolVersion {
                expected: VERSION,
                received: ProtocolVersion { major: 0, minor: 1 },
            })
        );
        assert_eq!(guard.last_sequence(), 1);

        guard
            .authorize(
                &authorization,
                &envelope(77, 2),
                Permission::ControlInput,
                150,
            )
            .expect("matching negotiated version should authorize");
        assert_eq!(guard.last_sequence(), 2);
    }

    #[test]
    fn guard_requires_exact_session_and_strictly_increasing_sequence() {
        let authorization = store(BTreeSet::from([Permission::ControlInput]));
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);

        assert_eq!(
            guard.authorize(
                &authorization,
                &envelope(78, 1),
                Permission::ControlInput,
                150,
            ),
            Err(CommandAuthorizationError::WrongSession {
                expected: 77,
                received: 78,
            })
        );
        assert_eq!(guard.last_sequence(), 1);

        guard
            .authorize(
                &authorization,
                &envelope(77, 2),
                Permission::ControlInput,
                150,
            )
            .expect("first post-handshake command should authorize");
        assert_eq!(
            guard.authorize(
                &authorization,
                &envelope(77, 2),
                Permission::ControlInput,
                150,
            ),
            Err(CommandAuthorizationError::NonIncreasingSequence {
                previous: 2,
                received: 2,
            })
        );
        assert_eq!(
            guard.authorize(
                &authorization,
                &envelope(77, 0),
                Permission::ControlInput,
                150,
            ),
            Err(CommandAuthorizationError::NonIncreasingSequence {
                previous: 2,
                received: 0,
            })
        );
    }

    #[test]
    fn non_privileged_envelopes_share_the_same_session_sequence() {
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);
        let mut heartbeat = envelope(77, 2);
        heartbeat.payload = Some(control_envelope::Payload::Heartbeat(
            classmesh_protocol::control_wire::Heartbeat {
                monotonic_time_us: 100,
                control_session_id: 77,
                media: 1,
            },
        ));

        guard
            .validate_envelope(&heartbeat)
            .expect("heartbeat should consume the global session sequence");
        assert_eq!(guard.last_sequence(), 2);

        let authorization = store(BTreeSet::from([Permission::ControlInput]));
        assert_eq!(
            guard.authorize(
                &authorization,
                &envelope(77, 2),
                Permission::ControlInput,
                150,
            ),
            Err(CommandAuthorizationError::NonIncreasingSequence {
                previous: 2,
                received: 2,
            })
        );
    }

    #[test]
    fn denied_sequence_cannot_be_replayed_after_permission_change() {
        let mut authorization = store(BTreeSet::new());
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);
        assert_eq!(
            guard.authorize(
                &authorization,
                &envelope(77, 2),
                Permission::ControlInput,
                150,
            ),
            Err(CommandAuthorizationError::Unauthorized {
                permission: Permission::ControlInput,
            })
        );
        assert_eq!(guard.last_sequence(), 2);

        let peer = identity();
        let mut credentials = BTreeMap::new();
        credentials.insert(
            peer.credential_fingerprint,
            CredentialRecord::active(peer.credential_fingerprint, 100),
        );
        authorization
            .upsert(Principal {
                id: peer.principal_id,
                kind: PrincipalKind::Teacher,
                enabled: true,
                permissions: BTreeSet::from([Permission::ControlInput]),
                credentials,
            })
            .expect("permission update should register");

        assert_eq!(
            guard.authorize(
                &authorization,
                &envelope(77, 2),
                Permission::ControlInput,
                151,
            ),
            Err(CommandAuthorizationError::NonIncreasingSequence {
                previous: 2,
                received: 2,
            })
        );
        guard
            .authorize(
                &authorization,
                &envelope(77, 3),
                Permission::ControlInput,
                151,
            )
            .expect("new sequence should use current permission");
    }

    #[test]
    fn credential_revocation_blocks_next_privileged_command() {
        let mut authorization = store(BTreeSet::from([Permission::ControlInput]));
        let mut guard = AuthenticatedControlGuard::new(identity(), 77, VERSION, 1);
        guard
            .authorize(
                &authorization,
                &envelope(77, 2),
                Permission::ControlInput,
                150,
            )
            .expect("credential should initially authorize");

        let peer = identity();
        let mut credentials = BTreeMap::new();
        let mut credential = CredentialRecord::active(peer.credential_fingerprint, 100);
        credential.revoke(160);
        credentials.insert(peer.credential_fingerprint, credential);
        authorization
            .upsert(Principal {
                id: peer.principal_id,
                kind: PrincipalKind::Teacher,
                enabled: true,
                permissions: BTreeSet::from([Permission::ControlInput]),
                credentials,
            })
            .expect("revocation update should register");

        assert_eq!(
            guard.authorize(
                &authorization,
                &envelope(77, 3),
                Permission::ControlInput,
                160,
            ),
            Err(CommandAuthorizationError::Unauthorized {
                permission: Permission::ControlInput,
            })
        );
    }
}
