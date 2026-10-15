//! Inactive future-v12 control-side authoritative policy recheck.
//!
//! Issuance REQUIRES a token from the actual privileged dispatcher and the
//! typed enrolled peer/session; policy is read from the real AuthorizationStore
//! at every subsequent call. This does not make the running Service store
//! dynamically mutable, prove current network connection liveness, hold a
//! Windows Worker HANDLE, negotiate a new IPC version, or move clipboard data.
use classmesh_protocol::{Capability, ControlRole, ProtocolVersion};
use classmesh_protocol::control_wire::ControlEnvelope;
use classmesh_security::{AuthorizationStore, CredentialFingerprint, Permission, PrincipalId, PrincipalKind};

use crate::authorization::AuthenticatedControlGuard;
use crate::dispatch::AuthorizedClipboardRead;
use crate::handshake::{EstablishedAuthenticatedPeer, EstablishedControlSession};

const MAX_LEASE_MS: u64 = 2_500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardAuthorityError {
    InvalidRequest,
    SessionChanged,
    CapabilityGone,
    NotAuthorized,
    AuthorityUnavailable,
    ClockRegression,
    Expired,
    AlreadyUsed,
    PendingRequestChanged,
}

/// A one-shot, non-bearer control proof: no clipboard content, encryption keys,
/// transport access, or permission to bypass future v12 native peer checks.
#[derive(Debug)]
pub struct ClipboardAuthorityLease {
    principal: PrincipalId,
    credential: CredentialFingerprint,
    session: u64,
    sequence: u64,
    request: u64,
    version: ProtocolVersion,
    last_checked_ms: u64,
    deadline_ms: u64,
    pending: bool,
}

impl ClipboardAuthorityLease {
    /// Issue only AFTER the real Service enrolled Teacher control command
    /// passed dispatch_privileged_command and yielded AuthorizedClipboardRead.
    pub fn issue(
        token: AuthorizedClipboardRead,
        guard: &AuthenticatedControlGuard,
        envelope: &ControlEnvelope,
        session: &EstablishedControlSession,
        peer: EstablishedAuthenticatedPeer,
        store: &AuthorizationStore,
        now_unix_ms: u64,
    ) -> Result<Self, ClipboardAuthorityError> {
        // AuthorizedClipboardRead is intentionally non-Clone/non-Copy.
        // Consuming its only value exactly once preserves the dispatcher proof.
        let request_id = token.request_id();
        if request_id == 0
            || request_id != envelope.request_id
            || envelope.sequence == 0
            || session.control_session_id == 0
            || guard.last_sequence() != envelope.sequence
        {
            return Err(ClipboardAuthorityError::InvalidRequest);
        }
        let deadline_ms = now_unix_ms
            .checked_add(MAX_LEASE_MS)
            .ok_or(ClipboardAuthorityError::Expired)?;
        let mut lease = Self {
            principal: peer.identity.principal_id(),
            credential: peer.identity.credential_fingerprint(),
            session: session.control_session_id,
            sequence: envelope.sequence,
            request: request_id,
            version: session.negotiated.version,
            last_checked_ms: now_unix_ms,
            deadline_ms,
            pending: false,
        };
        lease.validate(store, session, peer, guard, now_unix_ms)?;
        lease.pending = true;
        Ok(lease)
    }

    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.pending
    }

    /// Caller MUST pass the latest authoritative policy/session, not a Worker
    /// echo or a cached policy. The current production Service captures
    /// Arc<AuthorizationStore> immutably, so *live policy publication* is a
    /// separate integration gate. This type deliberately cannot imply it.
    pub fn recheck(
        &mut self,
        store: Option<&AuthorizationStore>,
        session: Option<&EstablishedControlSession>,
        peer: Option<EstablishedAuthenticatedPeer>,
        guard: Option<&AuthenticatedControlGuard>,
        current_pending: Option<(u64, u64, u64)>,
        now_unix_ms: u64,
    ) -> Result<(), ClipboardAuthorityError> {
        if !self.pending {
            return Err(ClipboardAuthorityError::AlreadyUsed);
        }
        // On a caught callback panic, do not allow pending authorization to
        // be retained. Restore only after all typed sources check successfully.
        self.pending = false;
        let (Some(store), Some(session), Some(peer), Some(guard)) = (store, session, peer, guard)
        else {
            return Err(ClipboardAuthorityError::AuthorityUnavailable);
        };
        if current_pending != Some((self.session, self.sequence, self.request)) {
            return Err(ClipboardAuthorityError::PendingRequestChanged);
        }
        self.validate(store, session, peer, guard, now_unix_ms)?;
        self.last_checked_ms = now_unix_ms;
        self.pending = true;
        Ok(())
    }

    /// Only consumes this control-side lease. No Worker IPC or payload is sent.
    pub fn finish(
        &mut self,
        store: Option<&AuthorizationStore>,
        session: Option<&EstablishedControlSession>,
        peer: Option<EstablishedAuthenticatedPeer>,
        guard: Option<&AuthenticatedControlGuard>,
        current_pending: Option<(u64, u64, u64)>,
        now_unix_ms: u64,
    ) -> Result<(), ClipboardAuthorityError> {
        self.recheck(store, session, peer, guard, current_pending, now_unix_ms)?;
        self.pending = false;
        Ok(())
    }

    #[must_use]
    pub fn cancel(&mut self) -> bool {
        let was_pending = self.pending;
        self.pending = false;
        was_pending
    }

    fn validate(
        &self,
        store: &AuthorizationStore,
        session: &EstablishedControlSession,
        peer: EstablishedAuthenticatedPeer,
        guard: &AuthenticatedControlGuard,
        now_unix_ms: u64,
    ) -> Result<(), ClipboardAuthorityError> {
        if now_unix_ms < self.last_checked_ms {
            return Err(ClipboardAuthorityError::ClockRegression);
        }
        if now_unix_ms >= self.deadline_ms {
            return Err(ClipboardAuthorityError::Expired);
        }
        if session.control_session_id != self.session
            || peer.control_session_id != self.session
            || guard.control_session_id() != self.session
            || guard.peer() != peer.identity
            || peer.identity.principal_id() != self.principal
            || peer.identity.credential_fingerprint() != self.credential
            || guard.protocol_version() != self.version
            || session.negotiated.version != self.version
            || session.negotiated.principal_id != self.principal
            || guard.last_sequence() < self.sequence
        {
            return Err(ClipboardAuthorityError::SessionChanged);
        }
        if !session.negotiated.capabilities.contains(&Capability::ClipboardText) {
            return Err(ClipboardAuthorityError::CapabilityGone);
        }
        if session.negotiated.role != ControlRole::Teacher
            || !store.principal(self.principal).is_some_and(|p| p.kind == PrincipalKind::Teacher)
            || store.principal_for_credential(self.credential, now_unix_ms) != Some(self.principal)
            || !store.authorize_credential(
                self.credential,
                Permission::ReadClipboard,
                now_unix_ms,
            )
        {
            return Err(ClipboardAuthorityError::NotAuthorized);
        }
        Ok(())
    }
}
