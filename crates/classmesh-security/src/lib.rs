#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrincipalId(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    Teacher,
    StudentDevice,
    Administrator,
    Service,
    SessionWorker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    ViewMonitoring,
    ViewInteractive,
    ControlInput,
    StartPresentation,
    ReceivePresentation,
    SendFile,
    ReceiveFile,
    LockDevice,
    RestartDevice,
    ShutdownDevice,
    ManageEnrollment,
    ManagePolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub id: PrincipalId,
    pub kind: PrincipalKind,
    pub public_key_fingerprint: [u8; 32],
    pub enabled: bool,
    pub permissions: BTreeSet<Permission>,
}

impl Principal {
    #[must_use]
    pub fn allows(&self, permission: Permission) -> bool {
        self.enabled && self.permissions.contains(&permission)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentState {
    Unenrolled,
    PendingApproval,
    Enrolled,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRecord {
    pub principal: PrincipalId,
    pub state: EnrollmentState,
    pub enrolled_at_unix_ms: Option<u64>,
    pub revoked_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentError {
    AlreadyEnrolled,
    Revoked,
    NotPending,
}

impl EnrollmentRecord {
    #[must_use]
    pub const fn new(principal: PrincipalId) -> Self {
        Self {
            principal,
            state: EnrollmentState::Unenrolled,
            enrolled_at_unix_ms: None,
            revoked_at_unix_ms: None,
        }
    }

    pub fn request(&mut self) -> Result<(), EnrollmentError> {
        match self.state {
            EnrollmentState::Unenrolled => {
                self.state = EnrollmentState::PendingApproval;
                Ok(())
            }
            EnrollmentState::PendingApproval => Ok(()),
            EnrollmentState::Enrolled => Err(EnrollmentError::AlreadyEnrolled),
            EnrollmentState::Revoked => Err(EnrollmentError::Revoked),
        }
    }

    pub fn approve(&mut self, now_unix_ms: u64) -> Result<(), EnrollmentError> {
        if self.state != EnrollmentState::PendingApproval {
            return Err(EnrollmentError::NotPending);
        }
        self.state = EnrollmentState::Enrolled;
        self.enrolled_at_unix_ms = Some(now_unix_ms);
        self.revoked_at_unix_ms = None;
        Ok(())
    }

    pub fn revoke(&mut self, now_unix_ms: u64) {
        self.state = EnrollmentState::Revoked;
        self.revoked_at_unix_ms = Some(now_unix_ms);
    }
}

#[derive(Debug, Default)]
pub struct AuthorizationStore {
    principals: BTreeMap<PrincipalId, Principal>,
}

impl AuthorizationStore {
    pub fn upsert(&mut self, principal: Principal) {
        self.principals.insert(principal.id, principal);
    }

    #[must_use]
    pub fn authorize(&self, principal: PrincipalId, permission: Permission) -> bool {
        self.principals
            .get(&principal)
            .is_some_and(|record| record.allows(permission))
    }

    pub fn disable(&mut self, principal: PrincipalId) -> bool {
        let Some(record) = self.principals.get_mut(&principal) else {
            return false;
        };
        record.enabled = false;
        true
    }
}

/// Bounded replay window for monotonically assigned command sequence numbers.
///
/// This is not a cryptographic anti-replay mechanism by itself. It is application-level duplicate
/// suppression intended to sit inside an authenticated transport/session.
#[derive(Debug)]
pub struct ReplayWindow {
    capacity: usize,
    seen: BTreeSet<u64>,
    order: VecDeque<u64>,
}

impl ReplayWindow {
    /// # Panics
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "replay window must be non-zero");
        Self {
            capacity,
            seen: BTreeSet::new(),
            order: VecDeque::with_capacity(capacity),
        }
    }

    /// Returns true only the first time a sequence number is observed inside the bounded window.
    pub fn accept(&mut self, sequence: u64) -> bool {
        if self.seen.contains(&sequence) {
            return false;
        }
        while self.order.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.order.push_back(sequence);
        self.seen.insert(sequence);
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalPeerValidation {
    Accepted,
    WrongSession,
    WrongProcess,
    WrongPrincipal,
    ChallengeFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedWorkerPeer {
    pub session_id: u32,
    pub process_id: u32,
    pub principal: PrincipalId,
}

impl ExpectedWorkerPeer {
    #[must_use]
    pub fn validate_metadata(
        self,
        session_id: u32,
        process_id: u32,
        principal: PrincipalId,
    ) -> LocalPeerValidation {
        if session_id != self.session_id {
            return LocalPeerValidation::WrongSession;
        }
        if process_id != self.process_id {
            return LocalPeerValidation::WrongProcess;
        }
        if principal != self.principal {
            return LocalPeerValidation::WrongPrincipal;
        }
        LocalPeerValidation::Accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u8) -> PrincipalId {
        PrincipalId([value; 32])
    }

    #[test]
    fn enrollment_cannot_skip_approval() {
        let mut record = EnrollmentRecord::new(id(1));
        assert_eq!(record.approve(10), Err(EnrollmentError::NotPending));
        record.request().expect("request should succeed");
        record.approve(20).expect("approval should succeed");
        assert_eq!(record.state, EnrollmentState::Enrolled);
    }

    #[test]
    fn authorization_is_permission_and_enabled_state_specific() {
        let mut permissions = BTreeSet::new();
        permissions.insert(Permission::ViewMonitoring);
        let principal = Principal {
            id: id(2),
            kind: PrincipalKind::Teacher,
            public_key_fingerprint: [9; 32],
            enabled: true,
            permissions,
        };
        let mut store = AuthorizationStore::default();
        store.upsert(principal);
        assert!(store.authorize(id(2), Permission::ViewMonitoring));
        assert!(!store.authorize(id(2), Permission::ShutdownDevice));
        assert!(store.disable(id(2)));
        assert!(!store.authorize(id(2), Permission::ViewMonitoring));
    }

    #[test]
    fn replay_window_rejects_recent_duplicate_but_stays_bounded() {
        let mut window = ReplayWindow::new(2);
        assert!(window.accept(1));
        assert!(!window.accept(1));
        assert!(window.accept(2));
        assert!(window.accept(3));
        assert!(window.accept(1));
    }

    #[test]
    fn expected_worker_binds_local_ipc_to_session_and_process() {
        let expected = ExpectedWorkerPeer {
            session_id: 4,
            process_id: 100,
            principal: id(7),
        };
        assert_eq!(
            expected.validate_metadata(4, 100, id(7)),
            LocalPeerValidation::Accepted
        );
        assert_eq!(
            expected.validate_metadata(5, 100, id(7)),
            LocalPeerValidation::WrongSession
        );
    }
}
