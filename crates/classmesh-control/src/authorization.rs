use classmesh_protocol::control_wire::ControlEnvelope;
use classmesh_security::{AuthorizationStore, Permission};

use crate::peer_identity::AuthenticatedPeerIdentity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandAuthorizationError {
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
    last_sequence: u64,
}

impl AuthenticatedControlGuard {
    #[must_use]
    pub const fn new(peer: AuthenticatedPeerIdentity, control_session_id: u64) -> Self {
        Self {
            peer,
            control_session_id,
            last_sequence: 0,
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

    fn envelope(session: u64, sequence: u64) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: session,
            sequence,
            protocol_version: None,
            request_id: 0,
            payload: None,
        }
    }

    #[test]
    fn guard_requires_exact_session_and_strictly_increasing_sequence() {
        let authorization = store(BTreeSet::from([Permission::ControlInput]));
        let mut guard = AuthenticatedControlGuard::new(identity(), 77);

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
        assert_eq!(guard.last_sequence(), 0);

        guard
            .authorize(
                &authorization,
                &envelope(77, 1),
                Permission::ControlInput,
                150,
            )
            .expect("first command should authorize");
        assert_eq!(
            guard.authorize(
                &authorization,
                &envelope(77, 1),
                Permission::ControlInput,
                150,
            ),
            Err(CommandAuthorizationError::NonIncreasingSequence {
                previous: 1,
                received: 1,
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
                previous: 1,
                received: 0,
            })
        );
    }

    #[test]
    fn denied_sequence_cannot_be_replayed_after_permission_change() {
        let mut authorization = store(BTreeSet::new());
        let mut guard = AuthenticatedControlGuard::new(identity(), 77);
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
        let mut guard = AuthenticatedControlGuard::new(identity(), 77);
        guard
            .authorize(
                &authorization,
                &envelope(77, 1),
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
                &envelope(77, 2),
                Permission::ControlInput,
                160,
            ),
            Err(CommandAuthorizationError::Unauthorized {
                permission: Permission::ControlInput,
            })
        );
    }
}
