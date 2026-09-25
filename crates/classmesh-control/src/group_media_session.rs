use std::fmt;

use classmesh_protocol::control_wire::{
    ControlEnvelope, PresentationKeyAck, PresentationKeyGrant,
    ProtocolVersion as WireProtocolVersion, control_envelope,
};
use classmesh_protocol::group_media_control::{
    GroupMediaControlError, group_media_control_available, validate_key_ack, validate_key_grant,
};
use classmesh_protocol::{ControlRole, ProtocolVersion};
use classmesh_security::group_media::GroupMediaEpoch;
use classmesh_security::group_media_coordinator::{
    GroupMediaCoordinator, GroupMediaCoordinatorError,
};
use classmesh_security::{AuthorizationStore, Permission, PrincipalId};
use zeroize::Zeroize;

use crate::authorization::{AuthenticatedControlGuard, CommandAuthorizationError};
use crate::handshake::{EstablishedAuthenticatedPeer, EstablishedControlSession};

#[derive(Debug)]
pub enum GroupMediaSessionError {
    InvalidSessionId,
    SessionMismatch { negotiated: u64, authenticated: u64 },
    IdentityMismatch,
    ReceiverRoleRequired,
    ContractUnavailable,
    ZeroRequestId,
    ZeroSequence,
    InvalidGrant(GroupMediaControlError),
    Coordinator(GroupMediaCoordinatorError),
}

impl fmt::Display for GroupMediaSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSessionId => formatter.write_str("group-media control session id is zero"),
            Self::SessionMismatch {
                negotiated,
                authenticated,
            } => write!(
                formatter,
                "group-media session mismatch: negotiated={negotiated}, authenticated={authenticated}"
            ),
            Self::IdentityMismatch => {
                formatter.write_str("group-media authenticated receiver identity mismatch")
            }
            Self::ReceiverRoleRequired => {
                formatter.write_str("group-media receiver must negotiate StudentDevice role")
            }
            Self::ContractUnavailable => {
                formatter.write_str("group-media v0.4 capability contract is unavailable")
            }
            Self::ZeroRequestId => {
                formatter.write_str("group-media key grant request_id must be non-zero")
            }
            Self::ZeroSequence => {
                formatter.write_str("group-media key grant sequence must be non-zero")
            }
            Self::InvalidGrant(error) => write!(formatter, "invalid group-media key grant: {error:?}"),
            Self::Coordinator(error) => write!(formatter, "group-media coordinator: {error}"),
        }
    }
}

impl std::error::Error for GroupMediaSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Coordinator(error) => Some(error),
            _ => None,
        }
    }
}

impl From<GroupMediaCoordinatorError> for GroupMediaSessionError {
    fn from(value: GroupMediaCoordinatorError) -> Self {
        Self::Coordinator(value)
    }
}

/// Exact authenticated receiver/session binding for Phase 7E key delivery.
///
/// This type can only be created from the server-side enrolled handshake result,
/// where mTLS identity has already been resolved to the stable peer PrincipalId.
/// It intentionally requires StudentDevice role and the negotiated v0.4
/// TeacherPresentation + SframeGroupMedia contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundGroupMediaReceiverSession {
    principal: PrincipalId,
    control_session_id: u64,
    protocol_version: ProtocolVersion,
}

impl BoundGroupMediaReceiverSession {
    pub fn bind(
        session: &EstablishedControlSession,
        peer: EstablishedAuthenticatedPeer,
    ) -> Result<Self, GroupMediaSessionError> {
        if session.control_session_id == 0 || peer.control_session_id == 0 {
            return Err(GroupMediaSessionError::InvalidSessionId);
        }
        if session.control_session_id != peer.control_session_id {
            return Err(GroupMediaSessionError::SessionMismatch {
                negotiated: session.control_session_id,
                authenticated: peer.control_session_id,
            });
        }

        let principal = peer.identity.principal_id();
        if session.negotiated.principal_id != principal {
            return Err(GroupMediaSessionError::IdentityMismatch);
        }
        if session.negotiated.role != ControlRole::StudentDevice {
            return Err(GroupMediaSessionError::ReceiverRoleRequired);
        }
        if !group_media_control_available(
            session.negotiated.version,
            &session.negotiated.capabilities,
        ) {
            return Err(GroupMediaSessionError::ContractUnavailable);
        }

        Ok(Self {
            principal,
            control_session_id: session.control_session_id,
            protocol_version: session.negotiated.version,
        })
    }

    #[must_use]
    pub const fn principal(self) -> PrincipalId {
        self.principal
    }

    #[must_use]
    pub const fn control_session_id(self) -> u64 {
        self.control_session_id
    }

    pub fn issue_key_grant(
        self,
        coordinator: &mut GroupMediaCoordinator,
        authorization: &AuthorizationStore,
        presentation_id: u64,
        stream_id: u64,
        request_id: u64,
        sequence: u64,
    ) -> Result<(SensitivePresentationKeyEnvelope, PendingPresentationKeyAck), GroupMediaSessionError>
    {
        if request_id == 0 {
            return Err(GroupMediaSessionError::ZeroRequestId);
        }
        if sequence == 0 {
            return Err(GroupMediaSessionError::ZeroSequence);
        }

        let grant = coordinator.issue_key(authorization, self.principal)?;
        let epoch = grant.epoch();

        let mut key_bytes = grant.copy_key_material_for_delivery();
        let mut wire_grant = PresentationKeyGrant {
            presentation_id,
            stream_id,
            epoch: epoch.get(),
            key_material: key_bytes.to_vec(),
        };
        key_bytes.zeroize();

        if let Err(error) = validate_key_grant(&wire_grant) {
            wire_grant.key_material.zeroize();
            return Err(GroupMediaSessionError::InvalidGrant(error));
        }

        let sensitive = SensitivePresentationKeyEnvelope::new(ControlEnvelope {
            control_session_id: self.control_session_id,
            sequence,
            protocol_version: Some(version_to_wire(self.protocol_version)),
            request_id,
            payload: Some(control_envelope::Payload::PresentationKeyGrant(wire_grant)),
        });

        let pending = PendingPresentationKeyAck {
            principal: self.principal,
            control_session_id: self.control_session_id,
            request_id,
            presentation_id,
            stream_id,
            epoch,
            acknowledged: false,
        };

        Ok((sensitive, pending))
    }
}

pub struct SensitivePresentationKeyEnvelope {
    envelope: ControlEnvelope,
}

impl SensitivePresentationKeyEnvelope {
    fn new(envelope: ControlEnvelope) -> Self {
        Self { envelope }
    }

    #[must_use]
    pub const fn envelope(&self) -> &ControlEnvelope {
        &self.envelope
    }

    fn zeroize_key_material(&mut self) {
        if let Some(control_envelope::Payload::PresentationKeyGrant(grant)) =
            self.envelope.payload.as_mut()
        {
            grant.key_material.zeroize();
        }
    }
}

impl fmt::Debug for SensitivePresentationKeyEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (presentation_id, stream_id, epoch) = match self.envelope.payload.as_ref() {
            Some(control_envelope::Payload::PresentationKeyGrant(grant)) => {
                (grant.presentation_id, grant.stream_id, grant.epoch)
            }
            _ => (0, 0, 0),
        };

        formatter
            .debug_struct("SensitivePresentationKeyEnvelope")
            .field("control_session_id", &self.envelope.control_session_id)
            .field("sequence", &self.envelope.sequence)
            .field("request_id", &self.envelope.request_id)
            .field("presentation_id", &presentation_id)
            .field("stream_id", &stream_id)
            .field("epoch", &epoch)
            .finish_non_exhaustive()
    }
}

impl Drop for SensitivePresentationKeyEnvelope {
    fn drop(&mut self) {
        self.zeroize_key_material();
    }
}

#[derive(Debug)]
pub enum PresentationKeyAckError {
    AlreadyAcknowledged,
    UnexpectedPayload,
    InvalidAck(GroupMediaControlError),
    PeerMismatch,
    SessionMismatch { expected: u64, received: u64 },
    Authorization(CommandAuthorizationError),
    RequestMismatch { expected: u64, received: u64 },
    PresentationMismatch { expected: u64, received: u64 },
    StreamMismatch { expected: u64, received: u64 },
    EpochMismatch { expected: u32, received: u32 },
    Coordinator(GroupMediaCoordinatorError),
}

impl fmt::Display for PresentationKeyAckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyAcknowledged => formatter.write_str("presentation key already acknowledged"),
            Self::UnexpectedPayload => formatter.write_str("expected PresentationKeyAck payload"),
            Self::InvalidAck(error) => write!(formatter, "invalid PresentationKeyAck: {error:?}"),
            Self::PeerMismatch => formatter.write_str("presentation key ACK peer mismatch"),
            Self::SessionMismatch { expected, received } => write!(
                formatter,
                "presentation key ACK session mismatch: expected={expected}, received={received}"
            ),
            Self::Authorization(error) => {
                write!(formatter, "presentation key ACK authorization: {error:?}")
            }
            Self::RequestMismatch { expected, received } => write!(
                formatter,
                "presentation key ACK request mismatch: expected={expected}, received={received}"
            ),
            Self::PresentationMismatch { expected, received } => write!(
                formatter,
                "presentation key ACK presentation mismatch: expected={expected}, received={received}"
            ),
            Self::StreamMismatch { expected, received } => write!(
                formatter,
                "presentation key ACK stream mismatch: expected={expected}, received={received}"
            ),
            Self::EpochMismatch { expected, received } => write!(
                formatter,
                "presentation key ACK epoch mismatch: expected={expected}, received={received}"
            ),
            Self::Coordinator(error) => write!(formatter, "presentation key ACK coordinator: {error}"),
        }
    }
}

impl std::error::Error for PresentationKeyAckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Coordinator(error) => Some(error),
            _ => None,
        }
    }
}

/// One bounded, one-shot key acknowledgement correlation record.
///
/// Callers own at most the pending records for their bounded receiver set.
/// No request history or unbounded queue is retained here.
#[derive(Debug)]
pub struct PendingPresentationKeyAck {
    principal: PrincipalId,
    control_session_id: u64,
    request_id: u64,
    presentation_id: u64,
    stream_id: u64,
    epoch: GroupMediaEpoch,
    acknowledged: bool,
}

impl PendingPresentationKeyAck {
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }

    #[must_use]
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    #[must_use]
    pub const fn epoch(&self) -> GroupMediaEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn is_acknowledged(&self) -> bool {
        self.acknowledged
    }

    pub fn accept(
        &mut self,
        guard: &mut AuthenticatedControlGuard,
        authorization: &AuthorizationStore,
        coordinator: &mut GroupMediaCoordinator,
        envelope: &ControlEnvelope,
        now_unix_ms: u64,
    ) -> Result<(), PresentationKeyAckError> {
        if self.acknowledged {
            return Err(PresentationKeyAckError::AlreadyAcknowledged);
        }

        let Some(control_envelope::Payload::PresentationKeyAck(ack)) = envelope.payload.as_ref()
        else {
            return Err(PresentationKeyAckError::UnexpectedPayload);
        };
        validate_key_ack(ack).map_err(PresentationKeyAckError::InvalidAck)?;

        if guard.peer().principal_id() != self.principal {
            return Err(PresentationKeyAckError::PeerMismatch);
        }
        if envelope.control_session_id != self.control_session_id {
            return Err(PresentationKeyAckError::SessionMismatch {
                expected: self.control_session_id,
                received: envelope.control_session_id,
            });
        }

        guard
            .authorize(
                authorization,
                envelope,
                Permission::ReceivePresentation,
                now_unix_ms,
            )
            .map_err(PresentationKeyAckError::Authorization)?;

        if envelope.request_id != self.request_id {
            return Err(PresentationKeyAckError::RequestMismatch {
                expected: self.request_id,
                received: envelope.request_id,
            });
        }
        if ack.presentation_id != self.presentation_id {
            return Err(PresentationKeyAckError::PresentationMismatch {
                expected: self.presentation_id,
                received: ack.presentation_id,
            });
        }
        if ack.stream_id != self.stream_id {
            return Err(PresentationKeyAckError::StreamMismatch {
                expected: self.stream_id,
                received: ack.stream_id,
            });
        }
        if ack.epoch != self.epoch.get() {
            return Err(PresentationKeyAckError::EpochMismatch {
                expected: self.epoch.get(),
                received: ack.epoch,
            });
        }

        coordinator
            .mark_installed(authorization, self.principal, self.epoch)
            .map_err(PresentationKeyAckError::Coordinator)?;
        self.acknowledged = true;
        Ok(())
    }
}

fn version_to_wire(version: ProtocolVersion) -> WireProtocolVersion {
    WireProtocolVersion {
        major: u32::from(version.major),
        minor: u32::from(version.minor),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use classmesh_protocol::Capability;
    use classmesh_security::group_media_coordinator::GroupMediaReceiverInstallState;
    use classmesh_security::{
        CredentialFingerprint, CredentialRecord, Principal, PrincipalKind,
    };

    use crate::peer_identity::AuthenticatedPeerIdentity;

    use super::*;

    const VERSION: ProtocolVersion = ProtocolVersion { major: 0, minor: 4 };

    fn principal(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    fn fingerprint(value: u8) -> CredentialFingerprint {
        CredentialFingerprint([value; 32])
    }

    fn authorization(receiver: PrincipalId, credential: CredentialFingerprint) -> AuthorizationStore {
        let mut credentials = BTreeMap::new();
        credentials.insert(credential, CredentialRecord::active(credential, 1));
        let mut store = AuthorizationStore::default();
        store
            .upsert(Principal {
                id: receiver,
                kind: PrincipalKind::StudentDevice,
                enabled: true,
                permissions: BTreeSet::from([Permission::ReceivePresentation]),
                credentials,
            })
            .expect("receiver principal");
        store
    }

    fn peer(receiver: PrincipalId, credential: CredentialFingerprint, session_id: u64) -> EstablishedAuthenticatedPeer {
        EstablishedAuthenticatedPeer {
            identity: AuthenticatedPeerIdentity {
                principal_id: receiver,
                credential_fingerprint: credential,
            },
            control_session_id: session_id,
        }
    }

    fn session(receiver: PrincipalId, session_id: u64) -> EstablishedControlSession {
        EstablishedControlSession {
            control_session_id: session_id,
            negotiated: crate::NegotiatedHello {
                principal_id: receiver,
                role: ControlRole::StudentDevice,
                version: VERSION,
                capabilities: BTreeSet::from([
                    Capability::TeacherPresentation,
                    Capability::SframeGroupMedia,
                ]),
            },
        }
    }

    fn setup() -> (
        PrincipalId,
        CredentialFingerprint,
        AuthorizationStore,
        GroupMediaCoordinator,
        BoundGroupMediaReceiverSession,
        AuthenticatedPeerIdentity,
    ) {
        let receiver = principal(7);
        let credential = fingerprint(9);
        let authorization = authorization(receiver, credential);
        let mut coordinator = GroupMediaCoordinator::default();
        coordinator
            .register_receiver(&authorization, receiver)
            .expect("receiver registration");
        coordinator.begin_epoch().expect("epoch");
        let established_peer = peer(receiver, credential, 77);
        let bound = BoundGroupMediaReceiverSession::bind(&session(receiver, 77), established_peer)
            .expect("bound receiver session");
        (
            receiver,
            credential,
            authorization,
            coordinator,
            bound,
            established_peer.identity,
        )
    }

    fn ack_envelope(
        session_id: u64,
        sequence: u64,
        request_id: u64,
        presentation_id: u64,
        stream_id: u64,
        epoch: u32,
    ) -> ControlEnvelope {
        ControlEnvelope {
            control_session_id: session_id,
            sequence,
            protocol_version: Some(version_to_wire(VERSION)),
            request_id,
            payload: Some(control_envelope::Payload::PresentationKeyAck(
                PresentationKeyAck {
                    presentation_id,
                    stream_id,
                    epoch,
                },
            )),
        }
    }

    #[test]
    fn binding_requires_exact_authenticated_student_session_and_v04_capabilities() {
        let receiver = principal(1);
        let credential = fingerprint(2);
        let exact_peer = peer(receiver, credential, 77);

        let mut wrong_session = session(receiver, 78);
        assert!(matches!(
            BoundGroupMediaReceiverSession::bind(&wrong_session, exact_peer),
            Err(GroupMediaSessionError::SessionMismatch { .. })
        ));

        wrong_session.control_session_id = 77;
        wrong_session.negotiated.principal_id = principal(3);
        assert!(matches!(
            BoundGroupMediaReceiverSession::bind(&wrong_session, exact_peer),
            Err(GroupMediaSessionError::IdentityMismatch)
        ));

        let mut wrong_role = session(receiver, 77);
        wrong_role.negotiated.role = ControlRole::Teacher;
        assert!(matches!(
            BoundGroupMediaReceiverSession::bind(&wrong_role, exact_peer),
            Err(GroupMediaSessionError::ReceiverRoleRequired)
        ));

        let mut missing_capability = session(receiver, 77);
        missing_capability
            .negotiated
            .capabilities
            .remove(&Capability::SframeGroupMedia);
        assert!(matches!(
            BoundGroupMediaReceiverSession::bind(&missing_capability, exact_peer),
            Err(GroupMediaSessionError::ContractUnavailable)
        ));
    }

    #[test]
    fn grant_is_exact_session_bound_sensitive_and_request_correlated() {
        let (_, _, authorization, mut coordinator, bound, _) = setup();
        let (sensitive, pending) = bound
            .issue_key_grant(&mut coordinator, &authorization, 55, 7, 44, 2)
            .expect("key grant");

        let envelope = sensitive.envelope();
        assert_eq!(envelope.control_session_id, 77);
        assert_eq!(envelope.request_id, 44);
        assert_eq!(envelope.sequence, 2);
        let Some(control_envelope::Payload::PresentationKeyGrant(grant)) =
            envelope.payload.as_ref()
        else {
            panic!("expected key grant");
        };
        assert_eq!(grant.presentation_id, 55);
        assert_eq!(grant.stream_id, 7);
        assert_eq!(grant.epoch, pending.epoch().get());
        assert_eq!(grant.key_material.len(), 32);
        assert!(!format!("{sensitive:?}").contains(&format!("{:?}", grant.key_material)));
    }

    #[test]
    fn zero_request_or_sequence_fails_before_key_issue() {
        let (receiver, _, authorization, mut coordinator, bound, _) = setup();

        assert!(matches!(
            bound.issue_key_grant(&mut coordinator, &authorization, 55, 7, 0, 2),
            Err(GroupMediaSessionError::ZeroRequestId)
        ));
        assert_eq!(
            coordinator.receiver_state(receiver),
            Some(GroupMediaReceiverInstallState::AwaitingKey)
        );

        assert!(matches!(
            bound.issue_key_grant(&mut coordinator, &authorization, 55, 7, 44, 0),
            Err(GroupMediaSessionError::ZeroSequence)
        ));
        assert_eq!(
            coordinator.receiver_state(receiver),
            Some(GroupMediaReceiverInstallState::AwaitingKey)
        );
    }

    #[test]
    fn exact_ack_rechecks_live_permission_and_marks_only_bound_receiver_installed() {
        let (receiver, _, authorization, mut coordinator, bound, identity) = setup();
        let (_sensitive, mut pending) = bound
            .issue_key_grant(&mut coordinator, &authorization, 55, 7, 44, 2)
            .expect("key grant");
        let mut guard = AuthenticatedControlGuard::new(identity, 77, VERSION, 1);
        let ack = ack_envelope(77, 2, 44, 55, 7, pending.epoch().get());

        pending
            .accept(&mut guard, &authorization, &mut coordinator, &ack, 10)
            .expect("exact ACK");
        assert!(pending.is_acknowledged());
        assert_eq!(
            coordinator.receiver_state(receiver),
            Some(GroupMediaReceiverInstallState::Installed(pending.epoch()))
        );
    }

    #[test]
    fn wrong_session_ack_is_rejected_before_sequence_consumption() {
        let (_, _, authorization, mut coordinator, bound, identity) = setup();
        let (_sensitive, mut pending) = bound
            .issue_key_grant(&mut coordinator, &authorization, 55, 7, 44, 2)
            .expect("key grant");
        let mut guard = AuthenticatedControlGuard::new(identity, 77, VERSION, 1);
        let ack = ack_envelope(78, 2, 44, 55, 7, pending.epoch().get());

        assert!(matches!(
            pending.accept(&mut guard, &authorization, &mut coordinator, &ack, 10),
            Err(PresentationKeyAckError::SessionMismatch {
                expected: 77,
                received: 78
            })
        ));
        assert_eq!(guard.last_sequence(), 1);
        assert!(!pending.is_acknowledged());
    }

    #[test]
    fn request_mismatch_consumes_sequence_but_does_not_install_key() {
        let (receiver, _, authorization, mut coordinator, bound, identity) = setup();
        let (_sensitive, mut pending) = bound
            .issue_key_grant(&mut coordinator, &authorization, 55, 7, 44, 2)
            .expect("key grant");
        let mut guard = AuthenticatedControlGuard::new(identity, 77, VERSION, 1);

        let wrong = ack_envelope(77, 2, 45, 55, 7, pending.epoch().get());
        assert!(matches!(
            pending.accept(&mut guard, &authorization, &mut coordinator, &wrong, 10),
            Err(PresentationKeyAckError::RequestMismatch {
                expected: 44,
                received: 45
            })
        ));
        assert_eq!(guard.last_sequence(), 2);
        assert!(!pending.is_acknowledged());
        assert_eq!(
            coordinator.receiver_state(receiver),
            Some(GroupMediaReceiverInstallState::KeyIssued(pending.epoch()))
        );

        let exact = ack_envelope(77, 3, 44, 55, 7, pending.epoch().get());
        pending
            .accept(&mut guard, &authorization, &mut coordinator, &exact, 10)
            .expect("next exact ACK");
        assert!(pending.is_acknowledged());
    }

    #[test]
    fn revoked_receiver_cannot_acknowledge_an_issued_key() {
        let (receiver, _, mut authorization, mut coordinator, bound, identity) = setup();
        let (_sensitive, mut pending) = bound
            .issue_key_grant(&mut coordinator, &authorization, 55, 7, 44, 2)
            .expect("key grant");
        assert!(authorization.disable(receiver));

        let mut guard = AuthenticatedControlGuard::new(identity, 77, VERSION, 1);
        let ack = ack_envelope(77, 2, 44, 55, 7, pending.epoch().get());
        assert!(matches!(
            pending.accept(&mut guard, &authorization, &mut coordinator, &ack, 10),
            Err(PresentationKeyAckError::Authorization(
                CommandAuthorizationError::Unauthorized {
                    permission: Permission::ReceivePresentation
                }
            ))
        ));
        assert!(!pending.is_acknowledged());
    }

    #[test]
    fn ack_from_another_authenticated_principal_is_rejected_before_sequence_consumption() {
        let (_, _, authorization, mut coordinator, bound, _) = setup();
        let (_sensitive, mut pending) = bound
            .issue_key_grant(&mut coordinator, &authorization, 55, 7, 44, 2)
            .expect("key grant");

        let other_identity = AuthenticatedPeerIdentity {
            principal_id: principal(99),
            credential_fingerprint: fingerprint(100),
        };
        let mut guard = AuthenticatedControlGuard::new(other_identity, 77, VERSION, 1);
        let ack = ack_envelope(77, 2, 44, 55, 7, pending.epoch().get());
        assert!(matches!(
            pending.accept(&mut guard, &authorization, &mut coordinator, &ack, 10),
            Err(PresentationKeyAckError::PeerMismatch)
        ));
        assert_eq!(guard.last_sequence(), 1);
    }
}
