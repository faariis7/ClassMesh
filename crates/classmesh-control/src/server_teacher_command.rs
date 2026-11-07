//! Enrolled Service-side Teacher QUIC command ingress. No SCM or Worker activation.
//! Only an enrolled mTLS connection and authenticated Hello may construct this receiver.
use classmesh_protocol::control_wire::{ControlEnvelope, control_envelope};
use classmesh_protocol::{ControlRole, ProtocolVersion};
use classmesh_security::PrincipalKind;
use quinn::Connection;

use crate::authorization::AuthenticatedControlGuard;
use crate::dispatch::{
    PrivilegedControlCommand, PrivilegedDispatchError, dispatch_privileged_command,
};
use crate::handshake::{EstablishedAuthenticatedPeer, EstablishedControlSession};
use crate::live_authorization::{LiveAuthorizationError, LiveAuthorizationStore};
use crate::peer_identity::{PeerIdentityError, authenticated_peer_identity};
use crate::quic::{ControlChannel, ControlTransportError};

#[derive(Debug)]
pub enum ServiceTeacherCommandError {
    WrongRole,
    WrongPrincipalKind,
    InvalidSession,
    PeerIdentity(PeerIdentityError),
    Authorization(LiveAuthorizationError),
    Transport(ControlTransportError),
    Dispatch(PrivilegedDispatchError),
    FileTransferDisabled,
}

/// Session-owned command receiver. A reconnect or new Hello must construct a
/// new receiver, never reset the replay sequence of an existing one.
pub struct ServiceTeacherCommandReceiver {
    connection: Connection,
    channel: ControlChannel,
    guard: AuthenticatedControlGuard,
}

impl ServiceTeacherCommandReceiver {
    /// `established` and `peer` MUST come from `server_hello_enrolled` on this
    /// very connection/channel, with enrolled mTLS client verification enabled.
    /// The constructor rechecks the live credential before any command is read.
    pub fn new(
        connection: Connection,
        channel: ControlChannel,
        established: &EstablishedControlSession,
        peer: EstablishedAuthenticatedPeer,
        authorization: &LiveAuthorizationStore,
        now_unix_ms: u64,
    ) -> Result<Self, ServiceTeacherCommandError> {
        if established.negotiated.role != ControlRole::Teacher {
            return Err(ServiceTeacherCommandError::WrongRole);
        }
        if established.control_session_id == 0
            || peer.control_session_id != established.control_session_id
            || peer.identity.principal_id() != established.negotiated.principal_id
        {
            return Err(ServiceTeacherCommandError::InvalidSession);
        }
        let snapshot = authorization
            .snapshot()
            .map_err(ServiceTeacherCommandError::Authorization)?;
        let current = authenticated_peer_identity(&connection, snapshot.store(), now_unix_ms)
            .map_err(ServiceTeacherCommandError::PeerIdentity)?;
        if current != peer.identity {
            return Err(ServiceTeacherCommandError::InvalidSession);
        }
        if snapshot
            .store()
            .principal(current.principal_id())
            .map(|p| p.kind)
            != Some(PrincipalKind::Teacher)
        {
            return Err(ServiceTeacherCommandError::WrongPrincipalKind);
        }
        let guard = AuthenticatedControlGuard::new(
            current,
            established.control_session_id,
            ProtocolVersion {
                major: established.negotiated.version.major,
                minor: established.negotiated.version.minor,
            },
            1,
        );
        Ok(Self {
            connection,
            channel,
            guard,
        })
    }

    /// Revalidate mTLS identity and current policy both before and after IO.
    /// The returned opaque command is permission-checked; no Worker command is
    /// executed by this library. Failures retire the caller's session.
    pub async fn receive_authorized(
        &mut self,
        authorization: &LiveAuthorizationStore,
        now_unix_ms: impl Fn() -> u64,
    ) -> Result<PrivilegedControlCommand, ServiceTeacherCommandError> {
        self.verify(authorization, now_unix_ms())?;
        let envelope = self
            .channel
            .receive()
            .await
            .map_err(ServiceTeacherCommandError::Transport)?;
        self.verify(authorization, now_unix_ms())?;
        // File transfer remains explicitly disabled for the MVP. Never grant
        // it merely because a Teacher credential has other control permissions.
        if is_file_transfer(&envelope) {
            self.guard.validate_envelope(&envelope).map_err(|e| {
                ServiceTeacherCommandError::Dispatch(PrivilegedDispatchError::Authorization(e))
            })?;
            return Err(ServiceTeacherCommandError::FileTransferDisabled);
        }
        let snapshot = authorization
            .snapshot()
            .map_err(ServiceTeacherCommandError::Authorization)?;
        dispatch_privileged_command(&mut self.guard, snapshot.store(), &envelope, now_unix_ms())
            .map_err(ServiceTeacherCommandError::Dispatch)
    }

    fn verify(
        &self,
        authorization: &LiveAuthorizationStore,
        now: u64,
    ) -> Result<(), ServiceTeacherCommandError> {
        let snapshot = authorization
            .snapshot()
            .map_err(ServiceTeacherCommandError::Authorization)?;
        let current = authenticated_peer_identity(&self.connection, snapshot.store(), now)
            .map_err(ServiceTeacherCommandError::PeerIdentity)?;
        if current != self.guard.peer() {
            return Err(ServiceTeacherCommandError::InvalidSession);
        }
        if snapshot
            .store()
            .principal(current.principal_id())
            .map(|p| p.kind)
            != Some(PrincipalKind::Teacher)
        {
            return Err(ServiceTeacherCommandError::WrongPrincipalKind);
        }
        Ok(())
    }
}

fn is_file_transfer(envelope: &ControlEnvelope) -> bool {
    matches!(
        envelope.payload,
        Some(
            control_envelope::Payload::FileTransferOffer(_)
                | control_envelope::Payload::FileTransferChunk(_)
                | control_envelope::Payload::FileTransferFinish(_)
                | control_envelope::Payload::FileTransferCancel(_)
                | control_envelope::Payload::FileTransferPullRequest(_)
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use classmesh_protocol::control_wire::{FileTransferCancel, Heartbeat};

    #[test]
    fn file_transfer_is_disabled_but_heartbeat_is_not_misclassified() {
        let mut envelope = ControlEnvelope {
            control_session_id: 9,
            sequence: 2,
            protocol_version: None,
            request_id: 1,
            payload: Some(control_envelope::Payload::FileTransferCancel(
                FileTransferCancel::default(),
            )),
        };
        assert!(is_file_transfer(&envelope));
        envelope.payload = Some(control_envelope::Payload::Heartbeat(Heartbeat::default()));
        assert!(!is_file_transfer(&envelope));
    }
}
